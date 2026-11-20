#!/usr/bin/env python3
"""Managed-prefix dependency installation using a native surrogate, never Wine or vendor binaries."""

import base64
import copy
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
TRIAL = runpy.run_path(str(HERE / 'test_preparation_trial.py'))
PE = runpy.run_path(str(HERE / 'test_prepare_game.py'))['pe']
import preparation_dependency_install as dep
import preparation_dependency_state as state
import preparation_recheck as recheck
from preparation_common import Invalid
from preparation_execution import LaunchSession
from preparation_processes import ProcessStopCheck
from preparation_softdenchi_recipe import softdenchi_recipe, validate_recipe

MARKER = b'\nDROIDDECK_SYNTHETIC_INSTALLER\n'
# Native surrogate for the preparation Proton. It never runs Windows code: the
# "installer" is a synthetic PE whose trailing JSON tells this script what to write.
FAKE = b'''#!/usr/bin/python3
import base64, json, os, sys
from pathlib import Path
root = Path(os.environ['STEAM_COMPAT_DATA_PATH'])
if sys.argv[1:] == ['runinprefix', 'winver.exe']:
    raise SystemExit(0)
if len(sys.argv) >= 3 and sys.argv[1] == 'runinprefix' and sys.argv[2].startswith('/'):
    raw = Path(sys.argv[2]).read_bytes()
    spec = json.loads(raw.split(b'\\nDROIDDECK_SYNTHETIC_INSTALLER\\n', 1)[1])
    if sys.argv[3:] and spec.get('silent_noop'):
        raise SystemExit(0)
    drive = root / 'pfx/drive_c'
    for relative, data in spec['files'].items():
        path = drive / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(data))
    with open(root / 'pfx/system.reg', 'a') as registry:
        registry.write(spec['registry'])
    raise SystemExit(spec['exit'])
(root / 'pfx/drive_c/windows').mkdir(parents=True, exist_ok=True)
for name in ('system.reg', 'user.reg'):
    (root / 'pfx' / name).write_text('WINE REGISTRY Version 2\\n')
(root / 'version').write_text('synthetic-version-1\\n')
'''

GUID_A = '{11111111-2222-3333-4444-555555555555}'
GUID_B = '{66666666-7777-8888-9999-AAAAAAAAAAAA}'
X86 = PE()
X64 = PE(0x8664, 0x20B)
SERVICE = PE() + b'service'
TEXT = b'synthetic license text'


def registry_path(value):
    return value.replace('\\', '\\\\')


def wine_registry(*, version='5.0.9.0', pending=False, com=True, secret=True):
    product = softdenchi_recipe()['product']
    uninstall = registry_path('Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + product['product_code'])
    lines = ['', f'[{uninstall}] 1700000000', f'"DisplayVersion"="{version}"',
             f'[{registry_path(product["marker_key"])}] 1', '"sdrt"="5090"',
             '[System\\\\ControlSet001\\\\Services\\\\UCManSvc] 1',
             '"ImagePath"=str(2):"\\"C:\\\\Program Files (x86)\\\\SoftDenchi\\\\UCManSvc.exe\\""',
             '"Start"=dword:00000002', '"Type"=dword:00000110']
    if com:
        lines += [f'[Software\\\\Classes\\\\Wow6432Node\\\\CLSID\\\\{GUID_A}\\\\InprocServer32] 1',
                  '@="C:\\\\Program Files (x86)\\\\SoftDenchi\\\\SatX4.ocx"', '"ThreadingModel"="Apartment"',
                  f'[Software\\\\Classes\\\\CLSID\\\\{GUID_A}\\\\InprocServer32] 1',
                  '@=hex(2):43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,20,00,46,00,69,00,6c,00,\\',
                  '  65,00,73,00,5c,00,53,00,6f,00,66,00,74,00,44,00,65,00,6e,00,63,00,68,00,69,00,5c,00,53,00,\\',
                  '  61,00,74,00,58,00,34,00,2e,00,6f,00,63,00,78,00,00,00',
                  f'[Software\\\\Classes\\\\Wow6432Node\\\\CLSID\\\\{GUID_B}\\\\LocalServer32] 1',
                  '@="C:\\\\Program Files (x86)\\\\SoftDenchi\\\\UCManSvc.exe"']
    if pending:
        lines += ['[System\\\\ControlSet001\\\\Control\\\\Session Manager] 1',
                  '"PendingFileRenameOperations"=str(7):"\\\\??\\\\C:\\\\x\\0\\0"']
    if secret:
        lines += ['[Software\\\\DUMMY_SECRET_STORE] 1', '"Password"="DUMMY_SECRET_VALUE"']
    return '\n'.join(lines) + '\n'


FILES = {'Program Files (x86)/SoftDenchi/SatX4.ocx': X86, 'Program Files/SoftDenchi/SatX4.ocx': X64,
         'Program Files (x86)/SoftDenchi/UCManSvc.exe': SERVICE, 'Program Files (x86)/SoftDenchi/License.txt': TEXT}


def installer(files=None, registry=None, exit_code=0, silent_noop=False):
    files = FILES if files is None else files
    body = {'files': {k: base64.b64encode(v).decode() for k, v in files.items()},
            'registry': wine_registry() if registry is None else registry, 'exit': exit_code}
    if silent_noop:
        # A bootstrap that ignores the silent arguments: it installs nothing when given any.
        body['silent_noop'] = True
    return PE() + MARKER + json.dumps(body).encode()


def recipe_for(data):
    recipe = softdenchi_recipe()
    recipe['bootstrap'].update(filename='sdrt-fixture.exe', size=len(data), sha256=hashlib.sha256(data).hexdigest())
    recipe['files'] = [[path, len(raw), hashlib.sha256(raw).hexdigest(), None if path.endswith('.txt') else
                        ('x86_64' if raw == X64 else 'x86')] for path, raw in FILES.items()]
    recipe['classes'] = [[GUID_A, 'InprocServer32', 'x86', 'Program Files (x86)/SoftDenchi/SatX4.ocx'],
                         [GUID_A, 'InprocServer32', 'x64', 'Program Files/SoftDenchi/SatX4.ocx'],
                         [GUID_B, 'LocalServer32', 'x86', 'Program Files (x86)/SoftDenchi/UCManSvc.exe']]
    return validate_recipe(recipe)


def spec_for(data, **changes):
    spec = {'asset_id': 'softdenchi-fixture', 'revision': 1, 'version': '5.0.9.0', 'purpose': 'synthetic-test',
            'filename': 'sdrt-fixture.exe', 'format': 'pe', 'pe_machine': 'x86', 'expected_size': len(data),
            'expected_sha256': hashlib.sha256(data).hexdigest(), 'hash_kind': 'external-reference',
            'hash_reference': 'synthetic fixture', 'source_kind': 'official', 'source_reference': 'synthetic fixture',
            'acquired_on': '2026-11-19', 'provenance_status': 'operator-reviewed', 'terms_status': 'personal-use-reviewed'}
    spec.update(changes)
    return spec


class StateTests(unittest.TestCase):
    """Offline parser and file checks; platform independent."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.compat = Path(temporary.name).resolve() / 'compatdata'
        (self.compat / 'pfx/drive_c/windows').mkdir(parents=True)
        self.registry = self.compat / 'pfx/system.reg'
        self.registry.write_text('WINE REGISTRY Version 2\n')
        self.recipe = recipe_for(installer())

    def install(self, files=FILES, registry=None):
        for relative, raw in files.items():
            path = self.compat / 'pfx/drive_c' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        with open(self.registry, 'a') as stream:
            stream.write(wine_registry() if registry is None else registry)

    def test_fresh_prefix_is_absent_and_secrets_are_not_retained(self):
        self.registry.write_text('WINE REGISTRY Version 2\n[Software\\\\DUMMY_SECRET_STORE] 1\n"Password"="DUMMY_SECRET_VALUE"\n')
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['state'], 'absent')
        self.assertFalse(result['wine_started'])
        self.assertNotIn('DUMMY_SECRET', json.dumps(result))

    def test_complete_fixture_is_present_verified_including_continued_hex_value(self):
        self.install()
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['state'], 'present-verified', result)
        self.assertEqual(set(result['groups'].values()), {'passed'})
        self.assertIs(result['pending_file_rename_operations'], False)
        self.assertNotIn('DUMMY_SECRET', json.dumps(result))

    def test_case_insensitive_paths_are_resolved_without_following_links(self):
        files = {k.replace('SoftDenchi', 'softdenchi'): v for k, v in FILES.items()}
        self.install(files)
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'present-verified')

    def test_pending_rename_is_not_verified(self):
        self.install(registry=wine_registry(pending=True))
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['state'], 'present-unverified')
        self.assertIs(result['pending_file_rename_operations'], True)

    def test_partial_and_wrong_content_are_not_verified(self):
        self.install({'Program Files (x86)/SoftDenchi/SatX4.ocx': X86}, registry='')
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'partial')
        self.install({**FILES, 'Program Files/SoftDenchi/SatX4.ocx': X64 + b'changed'})
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['state'], 'partial')
        self.assertEqual(result['items']['installed-files-hashes-pe-versions']['Program Files/SoftDenchi/SatX4.ocx']['reason'],
                         'size-differs')

    def test_other_product_version_is_incompatible(self):
        self.install(registry=wine_registry(version='5.0.8.0'))
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'incompatible')

    def test_symlink_hardlink_and_directory_link_are_rejected(self):
        self.install()
        outside = self.compat.parent / 'DUMMY_OUTSIDE'
        outside.write_bytes(X86)
        target = self.compat / 'pfx/drive_c/Program Files (x86)/SoftDenchi/SatX4.ocx'
        target.unlink()
        target.symlink_to(outside)
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['items']['installed-files-hashes-pe-versions'][
            'Program Files (x86)/SoftDenchi/SatX4.ocx']['reason'], 'symlink-not-followed')
        target.unlink()
        os.link(outside, target)
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['items']['installed-files-hashes-pe-versions'][
            'Program Files (x86)/SoftDenchi/SatX4.ocx']['reason'], 'multiple-links')
        directory = self.compat / 'pfx/drive_c/Program Files'
        (self.compat / 'moved').mkdir()
        os.rename(directory, self.compat / 'moved/Program Files')
        directory.symlink_to(self.compat / 'moved/Program Files')
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'uninspected')

    def test_malformed_or_duplicate_registry_is_uninspected_not_absent(self):
        duplicate = '[Software\\\\Wow6432Node\\\\Paltiosoft\\\\UCharge] 1\n"sdrt"="5090"\n' * 2
        for text in ('[Software\\\\Microsoft] 1\n"unterminated name=1\n', '[Software\\\\Microsoft] 1\ngarbage\n',
                     '[Software\\\\Wow6432Node\\\\Paltiosoft\\\\UCharge] 1\n"sdrt"="unterminated\n', duplicate):
            self.registry.write_text('WINE REGISTRY Version 2\n' + text)
            result = state.inspect_dependency_state(self.compat, self.recipe)
            self.assertEqual(result['state'], 'uninspected', text)
        self.registry.write_text('NOT A REGISTRY\n')
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'uninspected')

    def test_other_product_traces_are_never_absent(self):
        product = softdenchi_recipe()['product']
        packed_product, packed_upgrade = state.packed_guid(product['product_code']), state.packed_guid(product['upgrade_code'])
        only32 = registry_path('Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + product['product_code'])
        self.registry.write_text(f'WINE REGISTRY Version 2\n[{only32}] 1\n"DisplayVersion"="5.0.9.0"\n')
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['state'], 'partial')
        self.assertEqual(result['product_traces']['uninstall-32bit-view']['result'], 'present')
        upgrade = registry_path('Software\\Classes\\Installer\\UpgradeCodes\\' + packed_upgrade)
        self.registry.write_text(f'WINE REGISTRY Version 2\n[{upgrade}] 1\n"{"0" * 32}"=""\n')
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'incompatible')
        self.registry.write_text('WINE REGISTRY Version 2\n')
        self.install(registry=wine_registry() + f'[{upgrade}] 1\n"{packed_product}"=""\n')
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertEqual(result['state'], 'present-verified')
        self.assertEqual(result['product_traces']['upgrade-code-classes']['related_products'], 0)

    def test_unexpected_pending_rename_type_is_unknown_not_clear(self):
        self.install(registry=wine_registry() + '[System\\\\ControlSet001\\\\Control\\\\Session Manager] 1\n'
                     '"PendingFileRenameOperations"=dword:00000001\n')
        result = state.inspect_dependency_state(self.compat, self.recipe)
        self.assertIsNone(result['pending_file_rename_operations'])
        self.assertEqual(result['state'], 'present-unverified')
        self.assertIn('value-type-differs', result['pending_file_rename_detail'])

    def test_invalid_utf8_registry_is_uninspected(self):
        self.registry.write_bytes(b'WINE REGISTRY Version 2\n[Software\\\\Wow6432Node\\\\Palti\xffosoft] 1\n')
        self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'uninspected')

    def test_retry_policy_follows_only_cancelled_pre_installer_or_interrupted_records(self):
        def record(status, phase):
            return {'status': status, 'phase': phase}
        self.assertEqual(dep.retry_blockers(None, 0), [])
        for allowed in (record('cancelled-absent', 'post-inspected'), record('stopped-before-installer', 'gui-check-stopped'),
                        record('failed', 'gui-check-exited'), record('needs-user', 'installer-spawned'),
                        record('running', 'installer-exited')):
            self.assertEqual(dep.retry_blockers(allowed, 0), [], allowed)
        for blocked in (record('failed', 'post-inspected'), record('failed', 'installer-spawned'),
                        record('present-verified', 'post-inspected'), record('partial', 'post-inspected')):
            self.assertTrue(dep.retry_blockers(blocked, 0), blocked)
        self.assertEqual(dep.retry_blockers(None, 1), ['invalid-installation-record-present'])

    def test_registry_line_limit_is_enforced(self):
        with patch.object(state, 'MAX_LOGICAL_LINE', 64):
            self.registry.write_text('WINE REGISTRY Version 2\n[Software\\\\X] 1\n"a"="' + 'x' * 100 + '"\n')
            self.assertEqual(state.inspect_dependency_state(self.compat, self.recipe)['state'], 'uninspected')

    def test_trusted_recipe_is_static_and_consistent(self):
        recipe = validate_recipe(softdenchi_recipe())
        self.assertEqual(len(recipe['files']), 43)
        self.assertEqual(len(recipe['classes']), 15)
        self.assertEqual(recipe['bootstrap']['filename'], 'sdrt5090_x64.exe')
        recipe['files'].append(list(recipe['files'][0]))
        with self.assertRaises(Invalid):
            validate_recipe(recipe)


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux filesystem/native fixture; not device Wine')
class InstallTests(TRIAL['TrialTests']):
    def customize_trial_source(self, archive, root):
        with tarfile.open(archive, 'r:gz') as package:
            items = [(copy.copy(m), package.extractfile(m).read() if m.isfile() else None) for m in package]
        with tarfile.open(archive, 'w:gz') as package:
            for member, raw in items:
                if member.name == root + '/proton':
                    raw = FAKE
                    member.size = len(raw)
                    member.mode = 0o755
                package.addfile(member, io.BytesIO(raw) if raw is not None else None)
            for name in ('files/share', 'files/share/default_pfx_arm64', 'files/share/fex-emu'):
                if any(m.name == root + '/' + name for m, _ in items):
                    continue
                member = tarfile.TarInfo(root + '/' + name)
                member.type, member.mode = tarfile.DIRTYPE, 0o755
                package.addfile(member)
            member = tarfile.TarInfo(root + '/files/share/default_pfx_arm64/fixture.dat')
            member.size, member.mode = 1, 0o644
            package.addfile(member, io.BytesIO(b'x'))

    def setUp(self):
        super().setUp()
        patch.object(dep, 'RESERVE', 1024 * 1024).start()
        patch.object(dep, 'STOP_GRACE', 1).start()
        self.trial_record, self.trial_digest, _ = self.recheck_origin()
        plan = self.recheck_plan(self.trial_record, self.trial_digest)
        with self.f.store() as store, patch.object(recheck, 'plan_launch', side_effect=self.launch_fixture):
            session = recheck.RecheckSession(plan, store, lambda: self.recheck_plan(self.trial_record, self.trial_digest),
                                             plan.digest, ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            self.assertEqual(session.wait(10)['status'], 'probe-exited-unverified')
            self.recheck_id = session.record['recheck_id']
        self.use_installer(installer())

    def use_installer(self, data, **changes):
        self.data = data
        self.recipe = recipe_for(data)
        path = self.f.fixture.source.root / 'sdrt-fixture.exe'
        if path.exists():
            path.unlink()
        path.write_bytes(data)
        self.config['dependency_installation'] = {'handler': 'softdenchi-interactive', 'recipe_revision': 1,
                                                  'asset': spec_for(data, **changes)}

    def install_plan(self):
        source, _, games = TRIAL['BASE']['selection'].registration_catalog(self.environment)
        return dep.plan_dependency_install(record=self.trial_record, record_sha256=self.trial_digest, config=self.config,
            directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source, games=games,
            steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
            runtime_root=self.f.root, recipe=self.recipe)

    def install_session(self, store, plan=None, confirmation=None):
        plan = self.install_plan() if plan is None else plan
        return dep.DependencyInstallSession(plan, store, self.install_plan, plan.digest if confirmation is None else confirmation,
                                            ProcessStopCheck(plan.recheck.compatdata, self.f.proc))

    def run_flow(self, display=True, popen=None):
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep.subprocess, 'Popen', wraps=subprocess.Popen) as spawned:
            session = self.install_session(store).start_gui_check()
            self.assertEqual(session.wait_gui_check(10)['phase'], 'gui-check-stopped')
            if session.confirm_display(display)['phase'] != 'gui-check-stopped':
                return session.record, spawned
            session.start_installer()
            result = session.wait_installer(10)
            self.assertEqual(store.read_record('trials', self.trial_record['trial_id'] + '.json')[1], self.trial_digest)
            return result, spawned

    def test_plan_is_read_only_and_binds_only_the_recipe_bootstrap(self):
        before = self.protected()
        with patch('subprocess.Popen', side_effect=AssertionError('plan never executes')):
            plan = self.install_plan()
        summary = plan.summary()
        self.assertEqual(summary['blockers'], [])
        self.assertEqual(summary['pre_state'], 'absent')
        self.assertFalse(summary['execution_authorized'])
        self.assertEqual(summary['steps'][1]['arguments'], [])
        self.assertEqual(before, self.protected())
        self.assertFalse((self.f.store_root / dep.RECORDS).exists())

    def test_other_x86_pe_with_self_consistent_manifest_is_refused(self):
        recipe = self.recipe
        self.use_installer(installer(exit_code=0) + b'other')
        self.recipe = recipe
        plan = self.install_plan()
        self.assertIn('asset-not-recipe-bootstrap', plan.blockers)
        with self.f.store() as store, patch('subprocess.Popen', side_effect=AssertionError('blocked')), self.assertRaises(Invalid):
            self.install_session(store, plan).start_gui_check()

    def test_unreviewed_terms_block_before_any_write(self):
        self.use_installer(installer(), terms_status='unconfirmed')
        plan = self.install_plan()
        self.assertIn('asset:terms-unconfirmed', plan.blockers)

    def test_confirmed_flow_installs_once_with_original_name_and_verifies_offline(self):
        before = self.protected()
        result, spawned = self.run_flow()
        self.assertEqual(result['status'], 'present-verified', result)
        self.assertEqual(result['gui_check']['display_confirmed'], True)
        self.assertTrue(result['installer']['staged_unchanged'])
        allocation = result['prefix_allocation']
        self.assertGreaterEqual(allocation['growth_bytes'], 0)
        self.assertGreater(allocation['after']['regular_files'], allocation['before']['regular_files'])
        self.assertFalse(result['preparation_complete'])
        commands = [call.args[0][1:] for call in spawned.call_args_list]
        self.assertEqual(commands[0], ('runinprefix', 'winver.exe'))
        self.assertEqual(commands[1][0], 'runinprefix')
        self.assertEqual(Path(commands[1][1]).name, 'sdrt-fixture.exe')
        # Menu 8 passes no arguments to the installer (the surrogate accepts silent ones for menu 12).
        self.assertEqual(len(commands[1]), 2)
        self.assertEqual(len(commands), 2)
        self.assertEqual(before, self.protected())
        self.assertNotIn('DUMMY_SECRET', json.dumps(result))
        with self.f.store() as store:
            listed = store.inventory()['dependency_installs']
            self.assertEqual(store.read_record('rechecks', self.recheck_id + '.json')[0]['status'], 'probe-exited-unverified')
        self.assertEqual([item['status'] for item in listed], ['present-verified'])
        self.assertTrue(listed[0]['reinspection_required'])

    def test_unconfirmed_display_never_starts_installer(self):
        record, spawned = self.run_flow(display=False)
        self.assertEqual(record['status'], 'stopped-before-installer')
        self.assertEqual(len(spawned.call_args_list), 1)
        self.assertFalse((self.home / '.local/share/droiddeck-preparation-work/43/inputs').exists())

    def test_cancelled_installer_without_changes_is_cancelled_absent_and_retry_shows_history(self):
        self.use_installer(installer(files={}, registry='', exit_code=1602 % 256))
        result, _ = self.run_flow()
        self.assertEqual(result['status'], 'cancelled-absent')
        self.assertEqual(result['installer']['unix_exit_status'], 1602 % 256)
        plan = self.install_plan()
        self.assertEqual(plan.blockers, ())
        self.assertEqual(plan.summary()['previous_installation']['status'], 'cancelled-absent')

    def test_partial_or_zero_exit_with_failed_checks_is_preserved_and_blocks_reinstall(self):
        self.use_installer(installer(files={'Program Files (x86)/SoftDenchi/SatX4.ocx': X86}, registry=''))
        result, _ = self.run_flow()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['installer']['unix_exit_status'], 0)
        installed = self.home / 'unused'
        self.assertFalse(installed.exists())
        plan = self.install_plan()
        self.assertIn('dependency-state-partial-preserve-and-inspect', plan.blockers)
        self.assertTrue((plan.recheck.compatdata / 'pfx/drive_c/Program Files (x86)/SoftDenchi/SatX4.ocx').exists())

    def test_pending_rename_is_installed_unverified(self):
        self.use_installer(installer(registry=wine_registry(pending=True)))
        result, _ = self.run_flow()
        self.assertEqual(result['status'], 'installed-unverified')

    def test_timeout_and_lingering_processes_never_kill(self):
        fake = unittest.mock.Mock()
        fake.poll.return_value = None
        busy = {'clear_in_view': False, 'active_count': 1, 'unknown_count': 0, 'device_namespace_verified': False}
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep.subprocess, 'Popen', return_value=fake):
            session = self.install_session(store).start_gui_check()
            self.assertEqual(session.wait_gui_check(1)['status'], 'needs-user')
            fake.poll.return_value = 0
            with patch.object(ProcessStopCheck, 'check', return_value=busy):
                result = session.wait_gui_check(1)
            self.assertEqual(result['status'], 'needs-user')
            self.assertEqual(result['gui_check']['status'], 'exited-processes-remain')
            fake.kill.assert_not_called()
            fake.terminate.assert_not_called()
        self.assertNotIn('DUMMY_PRIVATE', json.dumps(result))

    def test_settings_change_during_installer_is_failed_without_repair(self):
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
            session = self.install_session(store).start_gui_check()
            session.wait_gui_check(10)
            session.confirm_display(True)
            session.start_installer()
            session.process.wait(timeout=10)
            self.games_config.write_text('{"DUMMY_EXTERNAL_CHANGE": true}')
            result = session.wait_installer(1)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['settings_identity_unchanged'])
        self.assertIn('DUMMY_EXTERNAL_CHANGE', self.games_config.read_text())

    def test_failed_installer_record_and_invalid_records_block_a_new_attempt(self):
        self.use_installer(installer(files={}, registry=''))
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
            session = self.install_session(store).start_gui_check()
            session.wait_gui_check(10)
            session.confirm_display(True)
            session.start_installer()
            session.process.wait(timeout=10)
            self.games_config.write_text('{"DUMMY_EXTERNAL_CHANGE": true}')
            self.assertEqual(session.wait_installer(1)['status'], 'failed')
        self.games_config.write_bytes((self.f.fixture.game.settings / 'games.json').read_bytes())
        plan = self.install_plan()
        self.assertEqual(plan.pre_state['state'], 'absent')
        self.assertIn('previous-installation-failed-review-required', plan.blockers)
        records = self.f.store_root / dep.RECORDS
        for item in records.glob('depinstall-*.json'):
            item.unlink()
        descriptor = os.open(records / 'depinstall-broken.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(descriptor, b'{"DUMMY": true}')
        os.close(descriptor)
        self.assertIn('invalid-installation-record-present', self.install_plan().blockers)

    def test_staged_copy_changed_after_staging_is_refused(self):
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
            session = self.install_session(store).start_gui_check()
            session.wait_gui_check(10)
            session.confirm_display(True)
            store.cache_asset(session.plan.spec, session.plan.asset_root)
            staged = session._stage()
            staged.write_bytes(staged.read_bytes() + b'x')
            with self.assertRaises(Invalid):
                session._check_staged(staged)

    def test_wrong_confirmation_and_busy_view_never_spawn(self):
        with self.f.store() as store, patch('subprocess.Popen', side_effect=AssertionError('no child')):
            with self.assertRaises(Invalid):
                self.install_session(store, confirmation='0' * 64).start_gui_check()
            with patch.object(ProcessStopCheck, 'check', return_value={'clear_in_view': False}), self.assertRaises(Invalid):
                self.install_session(store).start_gui_check()

    def test_scoped_launch_plan_cannot_use_ordinary_readiness(self):
        captured = []

        def capture(**kwargs):
            captured.append(self.launch_fixture(**kwargs))
            return captured[-1]
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=capture):
            session = self.install_session(store).start_gui_check()
            session.wait_gui_check(10)
            with self.assertRaises(Invalid):
                LaunchSession(captured[0], store, lambda: {'target': True, 'payload': True, 'runtime': True, 'stopped': True},
                              ProcessStopCheck(session.plan.recheck.compatdata, self.f.proc)).start()

    SERVICES = 'C:\\windows\\system32\\services.exe'
    SERVICE = 'C:\\Program Files (x86)\\SoftDenchi\\UCManSvc.exe'
    PROXY = 'C:\\Program Files (x86)\\SoftDenchi\\SdProxy.exe'

    def fake_process(self, pid, image, parent, started, exe='loader', environ=None):
        folder = self.f.proc / str(pid)
        folder.mkdir()
        tail = ['S', str(parent)] + ['0'] * 17 + [str(started)] + ['0'] * 5
        (folder / 'stat').write_text(f'{pid} (fake) ' + ' '.join(tail))
        compat = self.f.steam / 'steamapps/compatdata/43'
        if environ is None:
            environ = (b'STEAM_COMPAT_DATA_PATH=' + str(compat).encode() + b'\0WINEPREFIX=' + str(compat / 'pfx').encode() +
                       b'\0DUMMY_SECRET=1\0')
        (folder / 'environ').write_bytes(environ)
        (folder / 'cmdline').write_bytes(image.encode() + b'\0--DUMMY_ARGUMENT\0')
        if exe is not None:
            target = self.home / ('fake-' + exe)
            if not target.exists():
                target.write_bytes(b'synthetic loader, never executed')
            (folder / 'exe').symlink_to(target)
        return pid, started

    def lingering_tree(self, proxy_parent=None, services_started=10):
        self.fake_process(900001, '/opt/fixture/files/bin/wineserver', 1, 5)
        self.fake_process(900002, self.SERVICES, 1, services_started)
        self.fake_process(900003, 'C:\\windows\\system32\\explorer.exe', 900002, 12)
        self.fake_process(900004, self.SERVICE, 900002, 20)
        first = self.fake_process(900005, self.PROXY, proxy_parent or 900004, 30)
        second = self.fake_process(900006, self.PROXY, 900005, 40)
        return [first, second]

    def clear_fake(self):
        for folder in self.f.proc.iterdir():
            if folder.name.startswith('9000'):
                for item in folder.iterdir():
                    item.unlink()
                folder.rmdir()

    def installed_with_lingering(self, store, **tree):
        session = self.install_session(store).start_gui_check()
        session.wait_gui_check(10)
        session.confirm_display(True)
        session.start_installer()
        session.process.wait(timeout=10)
        targets = self.lingering_tree(**tree)
        result = session.wait_installer(1)
        self.assertEqual(result['installer']['status'], 'exited-processes-remain')
        return session, targets

    def test_lingering_proxies_are_recorded_then_stopped_only_by_sigterm_after_confirmation(self):
        sent = []

        def sender(key):
            sent.append(key)
            self.clear_fake()
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'PROXY_STOP_WAIT', 2):
            session, targets = self.installed_with_lingering(store)
            observed = session.record['lingering']['observed']
            self.assertEqual(observed['roles'], {'wineserver': 1, 'wine-infrastructure': 2, 'softdenchi-service': 1,
                                                 'softdenchi-proxy': 2})
            _summary, planned, reason = session.preview_proxy_stop()
            self.assertEqual((sorted(planned), reason), (sorted(targets), None))
            self.assertEqual(sent, [])
            result = session.stop_lingering_proxies(sender)
        self.assertEqual(sent, [targets[0]])  # The child had exited with its parent: recorded as gone, not signalled.
        stop = result['lingering']['stop']
        self.assertEqual((stop['result'], stop['planned'], stop['sent'], stop['forced_kill']), ('sigterm-sent', 2, 1, False))
        self.assertEqual([item['result'] for item in stop['signals']], ['sigterm-sent', 'gone-before-signal'])
        self.assertEqual(result['status'], 'present-verified')
        self.assertEqual(result['phase'], 'post-inspected')
        text = json.dumps(result)
        self.assertNotIn('DUMMY_SECRET', text)
        self.assertNotIn('DUMMY_ARGUMENT', text)
        self.assertNotIn('Program Files', json.dumps(observed))

    def test_unexplained_process_or_origin_refuses_the_stop(self):
        cases = ({'extra': True}, {'proxy_parent': 900003}, {'services_started': 25})
        reasons = ('unclassified process in prefix view', 'proxy origin not confirmed', 'service origin not confirmed')
        for case, reason in zip(cases, reasons):
            with self.subTest(case=case):
                self.clear_fake()
                sent = []
                with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
                    session = self.install_session(store)
                    tree = {key: value for key, value in case.items() if key != 'extra'}
                    self.lingering_tree(**tree)
                    if case.get('extra'):
                        self.fake_process(900007, 'C:\\users\\DUMMY_PRIVATE\\tool.exe', 900002, 50)
                    _, planned, found = session.preview_proxy_stop()
                    self.assertIsNone(planned)
                    self.assertEqual(found, reason)
                    self.assertEqual(sent, [])
        self.clear_fake()

    def remove_fake(self, pid):
        folder = self.f.proc / str(pid)
        for item in folder.iterdir():
            item.unlink()
        folder.rmdir()

    def installer_with_attributed_proxies(self, store):
        """The installer's launcher starts the SdProxy tree while it runs, then exits (device 0.26.2)."""
        session = self.install_session(store).start_gui_check()
        session.wait_gui_check(10)
        session.confirm_display(True)
        session.start_installer()
        session.process.wait(timeout=10)
        root = session.process.pid
        # The launcher itself carries no prefix variables, so it is outside the prefix view.
        self.fake_process(root, '/opt/fixture/DUMMY_LAUNCHER', 1, 3, environ=b'DUMMY=1\0')
        self.lingering_tree(proxy_parent=root)
        result = session.wait_installer(1)
        self.assertEqual(result['installer']['status'], 'exited-processes-remain')
        # The starter is gone: the first SdProxy is re-parented outside the view.
        self.remove_fake(root)
        self.clear_fake()
        targets = self.lingering_tree(proxy_parent=900404)
        return session, targets

    def test_installer_run_proxy_attributed_while_the_installer_ran_is_stopped(self):
        sent = []

        def sender(key):
            sent.append(key)
            self.clear_fake()
        self.clear_fake()
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'process_start_time', return_value=3), patch.object(dep, 'PROXY_STOP_WAIT', 2):
            session, targets = self.installer_with_attributed_proxies(store)
            self.assertEqual(session.record['installer']['spawned_started'], 3)
            self.assertEqual(session.record['installer']['installer_proxies'], [list(key) for key in targets])
            summary, planned, reason = session.preview_proxy_stop()
            self.assertEqual((planned, reason), (targets, None))
            self.assertEqual(summary['stop_origins'], {'installer-run': 2})
            output = io.StringIO()
            self.assertFalse(dep._confirm_proxy_stop(2, io.StringIO('q\n'), output, summary['stop_origins']))
            self.assertIn('今回のインストーラーの実行中にその子孫と確認したもの 2件', output.getvalue())
            result = session.stop_lingering_proxies(sender)
        self.assertEqual(sent, [targets[0]])
        self.assertEqual(result['lingering']['stop']['origins'], {'installer-run': 2})
        self.assertEqual(result['lingering']['stop']['result'], 'sigterm-sent')
        self.assertEqual(result['status'], 'present-verified')
        dep.validate_install_record(result)
        self.clear_fake()

    def _dying_first_proxy(self, targets, sent, vanish_after=None):
        """Sender for the device 0.26.3 case: the signaled SdProxy is briefly unreadable while it exits."""
        reads = {'after': None}
        real_inventory = dep.inventory_processes

        def sender(key):
            sent.append(key)
            if key == targets[0]:
                (self.f.proc / str(key[0]) / 'cmdline').write_bytes(b'')
                reads['after'] = 0
            else:
                self.clear_fake()

        def inventory(*args, **kwargs):
            if reads['after'] is not None:
                reads['after'] += 1
                if vanish_after is not None and reads['after'] > vanish_after and (self.f.proc / str(targets[0][0])).exists():
                    self.remove_fake(targets[0][0])
            return real_inventory(*args, **kwargs)
        return sender, inventory

    def test_signaled_proxy_briefly_unreadable_while_exiting_does_not_abort_the_next_send(self):
        sent = []
        self.clear_fake()
        real_signal = dep.signal_proxies
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'process_start_time', return_value=3), patch.object(dep, 'PROXY_STOP_WAIT', 2), \
                patch.object(dep, 'SIGNAL_SETTLE_INTERVAL', 0):
            session, targets = self.installer_with_attributed_proxies(store)
            sender, inventory = self._dying_first_proxy(targets, sent, vanish_after=2)
            output = io.StringIO()
            with patch.object(dep, 'inventory_processes', side_effect=inventory), \
                    patch.object(dep, 'signal_proxies', lambda *args: real_signal(*args[:3], sender, *args[4:])):
                dep._offer_session_proxy_stop(session, io.StringIO('1\n'), output, str)
            result = dict(session.record)
        self.assertEqual(sent, targets)
        self.assertEqual([item['result'] for item in result['lingering']['stop']['signals']], ['sigterm-sent'] * 2)
        second = result['lingering']['stop']['signals'][1]
        self.assertGreater(second['reads'], 1)
        self.assertEqual(second['unreadable_seen'], [targets[0][0]])
        self.assertEqual(result['lingering']['stop']['result'], 'sigterm-sent')
        self.assertNotIn('unreadable_pids', result['lingering']['stop'])
        self.assertEqual(result['status'], 'present-verified')
        self.assertIn('停止後の状態: present-verified', output.getvalue())
        self.assertNotIn('導入後の検査は済んでいません', output.getvalue())
        dep.validate_install_record(result)
        self.clear_fake()

    def test_view_still_unreadable_after_the_settle_wait_aborts_and_names_the_pid(self):
        sent = []
        self.clear_fake()
        real_signal = dep.signal_proxies
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'process_start_time', return_value=3), \
                patch.object(dep, 'SIGNAL_SETTLE_WAIT', 0.2), patch.object(dep, 'SIGNAL_SETTLE_INTERVAL', 0.01):
            session, targets = self.installer_with_attributed_proxies(store)
            sender, inventory = self._dying_first_proxy(targets, sent)
            output = io.StringIO()
            with patch.object(dep, 'inventory_processes', side_effect=inventory), \
                    patch.object(dep, 'signal_proxies', lambda *args: real_signal(*args[:3], sender, *args[4:])):
                dep._offer_session_proxy_stop(session, io.StringIO('1\n'), output, str)
            result = dict(session.record)
        self.assertEqual(sent, [targets[0]])
        stop = result['lingering']['stop']
        self.assertEqual((stop['result'], stop['reason']), ('aborted', 'unreadable process in prefix view'))
        self.assertEqual(stop['unreadable_pids'], [targets[0][0]])
        self.assertEqual(stop['revalidation']['result'], 'timeout')
        self.assertGreater(stop['revalidation']['reads'], 1)
        self.assertEqual(stop['revalidation']['new_pids'], [])
        self.assertEqual(result['lingering']['before_stop']['unreadable_pids'], [])
        self.assertEqual(result['status'], 'needs-user')
        self.assertIsNone(result['post_state'])
        text = output.getvalue()
        self.assertIn('停止を中止しました（unreadable process in prefix view）。送信済み 1件。', text)
        self.assertIn('導入後の検査は済んでいません。DroidDeckを完全に終了して起動し直してから、メニュー9', text)
        dep.validate_install_record(result)
        self.clear_fake()

    def test_anything_new_after_a_send_aborts_without_reading_again(self):
        plan = self.install_plan().recheck
        real_inventory = dep.inventory_processes
        for case in ('foreign-process', 'new-unreadable-pid'):
            with self.subTest(case=case):
                self.clear_fake()
                targets = self.lingering_tree()
                reads = []

                def sender(key, case=case, targets=targets, reads=reads):
                    if key != targets[0]:
                        self.fail('a view with something new must not allow the next send')
                    reads.append(0)
                    if case == 'foreign-process':
                        self.fake_process(900007, 'C:\\users\\DUMMY_PRIVATE\\tool.exe', 900002, 50)
                    else:
                        self.fake_process(900008, self.PROXY, 900002, 50)
                        (self.f.proc / '900008' / 'cmdline').write_bytes(b'')

                def inventory(*args, reads=reads, **kwargs):
                    if reads:
                        reads[0] += 1
                    return real_inventory(*args, **kwargs)
                log, detail = [], {}
                with patch.object(dep, 'inventory_processes', side_effect=inventory), \
                        patch.object(dep, 'SIGNAL_SETTLE_WAIT', 30), patch.object(dep, 'SIGNAL_SETTLE_INTERVAL', 0), \
                        self.assertRaises(Invalid):
                    dep.signal_proxies(plan.compatdata, targets, self.f.proc, sender, log, dep.NO_SCOPE, detail)
                self.assertEqual(reads, [1])
                self.assertEqual([item['result'] for item in log], ['sigterm-sent'])
                self.assertEqual(detail.get('unreadable_pids'), [900008] if case == 'new-unreadable-pid' else None)
                self.assertEqual(detail['revalidation']['result'], 'not-shrinking')
                self.assertEqual(detail['revalidation']['new_pids'], [900008 if case == 'new-unreadable-pid' else 900007])
        # The first target already gone at its send: the view is still read before the next send.
        self.clear_fake()
        targets = self.lingering_tree()

        def gone_first(key, targets=targets):
            if key != targets[0]:
                self.fail('a view with something new must not allow the next send')
            self.fake_process(900007, 'C:\\users\\DUMMY_PRIVATE\\tool.exe', 900002, 50)
            raise ProcessLookupError
        log, detail = [], {}
        with self.assertRaisesRegex(Invalid, 'unclassified process'):
            dep.signal_proxies(plan.compatdata, targets, self.f.proc, gone_first, log, dep.NO_SCOPE, detail)
        self.assertEqual([item['result'] for item in log], ['gone-before-signal'])
        self.assertEqual(detail['revalidation']['result'], 'not-shrinking')
        self.clear_fake()

    def test_menu8_names_the_missing_inspection_only_when_it_did_not_run(self):
        class Session:
            def __init__(self, record):
                self.record = record

            def preview_proxy_stop(self):
                return {'processes': [], 'unreadable_count': 0, 'stop_origins': {'installer-run': 1}}, [(1, 2)], None

            def stop_lingering_proxies(self):
                return self.record
        sent = {'stop': {'result': 'sigterm-sent', 'signals': [{'result': 'sigterm-sent'}]}}
        for status, post_state, missing in (('partial', 'partial', False), ('present-verified', 'present-verified', False),
                                            ('needs-user', None, True), ('needs-user', 'uninspected', True)):
            with self.subTest(post_state=post_state):
                output = io.StringIO()
                dep._offer_session_proxy_stop(Session({'status': status, 'post_state': post_state, 'lingering': sent}),
                                              io.StringIO('1\n'), output, str)
                self.assertIn('停止後の状態: ' + status, output.getvalue())
                self.assertEqual('導入後の検査は済んでいません' in output.getvalue(), missing)

    def test_parentless_proxy_not_attributed_to_this_installer_is_refused(self):
        self.clear_fake()
        # Without the installer start time nothing is attributed.
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'process_start_time', side_effect=OSError('no start time')):
            session, _ = self.installed_with_lingering(store, proxy_parent=900404)
            self.assertNotIn('spawned_started', session.record['installer'])
            self.assertNotIn('installer_proxies', session.record['installer'])
            result = session.stop_lingering_proxies(lambda key: self.fail('refused stop must not signal'))
        self.assertEqual(result['lingering']['stop'], {'result': 'refused', 'reason': 'proxy origin not confirmed'})
        compat = self.install_plan().recheck.compatdata
        attributed = dep.StopScope(installer_proxies=frozenset({(900005, 30), (900006, 40)}))
        cases = ((attributed, 900404, 31, 'proxy origin not confirmed'),     # a later SdProxy from another launch
                 (attributed, None, None, 'service origin not confirmed'),     # a second services.exe
                 (dep.StopScope(installer_proxies=frozenset({(900005, 29)})), None, None, 'proxy origin not confirmed'))
        for scope, other_parent, other_started, reason in cases:
            with self.subTest(reason=reason, scope=scope):
                self.clear_fake()
                self.lingering_tree(proxy_parent=900404)
                if other_started is not None:
                    self.fake_process(900011, self.PROXY, other_parent, other_started)
                elif reason == 'service origin not confirmed':
                    self.fake_process(900010, self.SERVICES, 1, 11)
                first, second = (dep.inventory_processes(compat, self.f.proc) for _ in range(2))
                self.assertEqual(dep.process_start_time(900005, self.f.proc), 30)
                with self.assertRaisesRegex(Invalid, reason):
                    dep.proxy_stop_targets(first, second, scope)
        # Menu 9 has no installer run to attribute the origin: the same tree is refused.
        self.clear_fake()
        plan = self.install_plan().recheck
        self.lingering_tree(proxy_parent=900404)
        with self.f.store() as store:
            entry = dep.offer_reinspection_proxy_stop(plan, store, ProcessStopCheck(plan.compatdata, self.f.proc),
                                                      io.StringIO(), io.StringIO(), str,
                                                      sender=lambda key: self.fail('menu 9 must refuse'))
        self.assertEqual(entry['stop'], {'result': 'refused', 'reason': 'proxy origin not confirmed'})
        self.clear_fake()

    def test_ancestry_attribution_requires_matching_start_times(self):
        parents = {10: (1, 3), 20: (10, 5), 30: (20, 7), 40: (99, 8)}
        self.assertTrue(dep.descends_from(parents, (30, 7), (10, 3)))
        self.assertFalse(dep.descends_from(parents, (30, 7), (10, 4)))      # root PID reused
        self.assertFalse(dep.descends_from(parents, (30, 6), (10, 3)))      # target PID reused
        self.assertFalse(dep.descends_from(parents, (40, 8), (10, 3)))      # parent outside the map
        self.assertFalse(dep.descends_from({20: (10, 5), 10: (20, 6)}, (20, 5), (1, 1)))  # parent newer than child
        self.assertFalse(dep.descends_from({20: (20, 5)}, (20, 5), (1, 1)))

    def test_installer_attribution_is_validated_in_the_record(self):
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'process_start_time', return_value=3):
            session, _ = self.installer_with_attributed_proxies(store)
            record = dict(session.record)
        self.clear_fake()
        installer = record['installer']
        without_start = {k: v for k, v in installer.items() if k != 'spawned_started'}
        cases = (({**installer, 'spawned_started': -1}, 'invalid installer start time'),
                 ({**installer, 'spawned_started': '3'}, 'invalid installer start time'),
                 (without_start, 'invalid installer SdProxy attribution'),
                 ({**installer, 'installer_proxies': []}, 'invalid installer SdProxy attribution'),
                 ({**installer, 'installer_proxies': [[900005, 30], [900005, 30]]}, 'invalid installer SdProxy attribution'),
                 ({**installer, 'installer_proxies': [[900005, -1]]}, 'invalid installer SdProxy attribution'))
        for broken, reason in cases:
            with self.subTest(broken=broken), self.assertRaisesRegex(Invalid, reason):
                dep.validate_install_record({**record, 'installer': broken})
        with self.assertRaisesRegex(Invalid, 'invalid installer start time'):
            dep.validate_install_record({**record, 'gui_check': {**record['gui_check'], 'spawned_started': 3}})

    def test_installer_wait_keeps_observing_without_prompting_at_first(self):
        steps = []

        def wait(timeout):
            steps.append(timeout)
            done = sum(steps) >= 700
            state = {'status': 'exited' if done else 'waiting'}
            return {'status': 'running' if done else 'needs-user', 'installer': state, 'gui_check': state}
        output = io.StringIO()
        outcome = dep._wait_loop(wait, io.StringIO('1\n1\n1\n1\n'), output, 'installer', 600)
        self.assertEqual(outcome['status'], 'running')
        self.assertEqual(steps, [120, 120, 120, 120, 120, 30, 30, 30, 30])
        self.assertEqual(output.getvalue().count('未完了です'), 4)  # first asked after the quiet 600 s
        steps.clear()
        output = io.StringIO()
        dep._wait_loop(wait, io.StringIO('q\n'), output, 'gui_check')
        self.assertEqual(steps, [30])
        self.assertEqual(output.getvalue().count('未完了です'), 1)

    def tool_xalia(self):
        tool = dep._tool_directory(self.install_plan().recheck)
        return 'Z:' + str(tool / 'files/share/xalia/xalia.exe').replace('/', '\\')

    def test_wine_and_proton_helpers_seen_on_the_device_are_explained(self):
        # 0.26.2 device run: lsass.exe, tabtip.exe and Proton's xalia.exe stayed beside the SdProxy tree.
        self.clear_fake()
        targets = self.lingering_tree()
        self.fake_process(900007, 'C:\\windows\\system32\\lsass.exe', 900002, 13)
        self.fake_process(900008, 'C:\\windows\\system32\\tabtip.exe', 900003, 14)
        self.fake_process(900009, self.tool_xalia(), 900003, 15)
        with self.f.store() as store:
            summary, planned, reason = self.install_session(store).preview_proxy_stop()
        self.assertEqual((sorted(planned), reason), (sorted(targets), None))
        self.assertEqual(summary['roles'], {'wineserver': 1, 'wine-infrastructure': 4, 'proton-xalia': 1,
                                            'softdenchi-service': 1, 'softdenchi-proxy': 2})
        self.assertEqual(summary['stop_origins'], {'ucmansvc': 2})
        self.assertEqual({item['name']: item['place'] for item in summary['processes']}['xalia.exe'], 'proton-share-xalia')
        self.assertNotIn(str(self.f.steam), json.dumps(summary))
        self.clear_fake()

    def test_helper_names_outside_their_expected_place_stay_unexplained(self):
        xalia = self.tool_xalia()
        cases = (('C:\\users\\DUMMY_PRIVATE\\lsass.exe', 900002), ('C:\\DUMMY_PRIVATE\\tabtip.exe', 900003),
                 (xalia, 900002), (xalia, 900404), (xalia.replace('Z:', '', 1).replace('\\', '/'), 900003),
                 ('C:\\unrelated\\files\\share\\xalia\\xalia.exe', 900003), ('C:\\DUMMY_PRIVATE\\xalia.exe', 900003))
        for image, parent in cases:
            with self.subTest(image=image, parent=parent):
                self.clear_fake()
                self.lingering_tree()
                self.fake_process(900007, image, parent, 50)
                with self.f.store() as store:
                    _, planned, reason = self.install_session(store).preview_proxy_stop()
                self.assertIsNone(planned)
                self.assertEqual(reason, 'unclassified process in prefix view')
        self.clear_fake()

    def test_conflicting_prefix_environment_or_executable_identity_refuses_the_stop(self):
        compat = self.f.steam / 'steamapps/compatdata/43'
        cases = ({'environ': b'STEAM_COMPAT_DATA_PATH=' + str(compat).encode() + b'\0WINEPREFIX=/DUMMY_OTHER/pfx\0'},
                 {'exe': 'other-loader'}, {'exe': None})
        reasons = ('conflicting prefix environment', 'executable identity not confirmed', 'executable identity not confirmed')
        for case, reason in zip(cases, reasons):
            with self.subTest(case=case):
                self.clear_fake()
                self.lingering_tree()
                (self.f.proc / '900006').rename(self.f.proc / '900099')
                for item in (self.f.proc / '900099').iterdir():
                    item.unlink()
                (self.f.proc / '900099').rmdir()
                self.fake_process(900006, self.PROXY, 900005, 40, **case)
                with self.f.store() as store:
                    _, planned, found = self.install_session(store).preview_proxy_stop()
                self.assertIsNone(planned)
                self.assertEqual(found, reason)
        self.clear_fake()

    def test_stop_is_revalidated_after_confirmation_and_partial_sends_are_kept(self):
        plan = self.install_plan().recheck
        stop = ProcessStopCheck(plan.compatdata, self.f.proc)
        self.lingering_tree()

        def confirm_then_change(count, stream, output):
            self.fake_process(900007, 'C:\\users\\DUMMY_PRIVATE\\tool.exe', 900002, 50)
            return True
        with self.f.store() as store, patch.object(dep, '_confirm_proxy_stop', side_effect=confirm_then_change):
            entry = dep.offer_reinspection_proxy_stop(plan, store, stop, io.StringIO(), io.StringIO(), str,
                                                      sender=lambda key: self.fail('revalidation must refuse'))
        self.assertEqual(entry['stop']['result'], 'aborted')
        self.assertEqual(entry['stop']['reason'], 'unclassified process in prefix view')
        self.assertEqual(entry['stop']['signals'], [])
        self.clear_fake()
        targets = self.lingering_tree()

        def fail_second(key):
            if key == targets[1]:
                raise PermissionError('DUMMY_PRIVATE')
        log = []
        with self.assertRaises(PermissionError):
            dep.signal_proxies(plan.compatdata, targets, self.f.proc, fail_second, log)
        self.assertEqual(log, [{'pid': targets[0][0], 'started': targets[0][1], 'result': 'sigterm-sent'}])
        output = io.StringIO()
        with self.f.store() as store, patch.object(dep, '_confirm_proxy_stop', return_value=True):
            entry = dep.offer_reinspection_proxy_stop(plan, store, stop, io.StringIO(), output, str, sender=fail_second)
        self.assertEqual(entry['stop']['result'], 'aborted')
        self.assertEqual([item['result'] for item in entry['stop']['signals']], ['sigterm-sent'])
        self.assertIn('送信済み 1件', output.getvalue())
        self.assertNotIn('DUMMY_PRIVATE', json.dumps(entry))
        self.clear_fake()

    def test_later_target_identity_change_aborts_and_keeps_the_first_send(self):
        plan = self.install_plan().recheck
        for change in ('other-loader', None):
            with self.subTest(change=change):
                self.clear_fake()
                targets = self.lingering_tree()

                def swap_child(key, change=change, targets=targets):
                    if key != targets[0]:
                        self.fail('changed target must not be signalled')
                    exe = self.f.proc / str(targets[1][0]) / 'exe'
                    exe.unlink()
                    if change is not None:
                        other = self.home / ('fake-' + change)
                        if not other.exists():
                            other.write_bytes(b'different synthetic loader')
                        exe.symlink_to(other)
                log, detail = [], {}
                with patch.object(dep, 'SIGNAL_SETTLE_WAIT', 30), patch.object(dep, 'SIGNAL_SETTLE_INTERVAL', 0), \
                        self.assertRaisesRegex(Invalid, 'target changed before signal'):
                    dep.signal_proxies(plan.compatdata, targets, self.f.proc, swap_child, log, dep.NO_SCOPE, detail)
                self.assertEqual([item['result'] for item in log], ['sigterm-sent'])
                # A changed confirmed process is not "shrinking": no waiting for the deadline.
                self.assertEqual((detail['revalidation']['result'], detail['revalidation']['reads']), ('not-shrinking', 1))
        self.clear_fake()

    def test_new_or_changed_known_process_after_a_send_aborts_even_if_the_view_passes(self):
        plan = self.install_plan().recheck
        for case in ('new explorer', 'service loader changed'):
            with self.subTest(case=case):
                self.clear_fake()
                targets = self.lingering_tree()

                def sender(key, case=case, targets=targets):
                    if key != targets[0]:
                        self.fail('second send after a new or changed process')
                    if case == 'new explorer':
                        self.fake_process(900008, 'C:\\windows\\system32\\explorer.exe', 900002, 60)
                    else:
                        exe = self.f.proc / '900004' / 'exe'
                        exe.unlink()
                        other = self.home / 'fake-other-loader'
                        if not other.exists():
                            other.write_bytes(b'different synthetic loader')
                        exe.symlink_to(other)
                log, detail = [], {}
                with patch.object(dep, 'SIGNAL_SETTLE_WAIT', 30), patch.object(dep, 'SIGNAL_SETTLE_INTERVAL', 0), \
                        self.assertRaisesRegex(Invalid, 'new or changed process'):
                    dep.signal_proxies(plan.compatdata, targets, self.f.proc, sender, log, dep.NO_SCOPE, detail)
                self.assertEqual([item['result'] for item in log], ['sigterm-sent'])
                self.assertEqual((detail['revalidation']['result'], detail['revalidation']['reads']), ('not-shrinking', 1))
                self.assertEqual(detail['revalidation']['new_pids'], [900008 if case == 'new explorer' else 900004])
        self.clear_fake()

    def test_more_unreadable_pids_than_reported_abort_at_once(self):
        plan = self.install_plan().recheck
        targets = self.lingering_tree()

        def flood(key):
            for pid in range(900100, 900117):
                self.fake_process(pid, self.PROXY, 900002, 60)
                (self.f.proc / str(pid) / 'cmdline').write_bytes(b'')
        log, detail = [], {}
        with patch.object(dep, 'SIGNAL_SETTLE_WAIT', 30), patch.object(dep, 'SIGNAL_SETTLE_INTERVAL', 0), \
                self.assertRaisesRegex(Invalid, 'unreadable process'):
            dep.signal_proxies(plan.compatdata, targets, self.f.proc,
                               lambda key: flood(key) if key == targets[0] else self.fail('second send'), log, dep.NO_SCOPE, detail)
        self.assertEqual((detail['revalidation']['result'], detail['revalidation']['reads']), ('not-shrinking', 1))
        self.assertEqual(detail['revalidation']['unreadable_count'], 17)
        self.assertEqual(len(detail['unreadable_pids']), 16)
        self.clear_fake()

    @unittest.skipUnless(callable(getattr(os, 'pidfd_open', None)), 'pidfd required')
    def test_await_exit_returns_when_the_pinned_child_exits(self):
        import time
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.2)'])
        descriptor = os.pidfd_open(child.pid, 0)
        try:
            began = time.monotonic()
            dep._await_exit(descriptor, 5)
            self.assertLess(time.monotonic() - began, 3)
        finally:
            os.close(descriptor)
            child.wait()
        dep._await_exit(-1, 0.01)  # an unusable descriptor never raises

    def test_menu9_keeps_the_signal_history_when_a_later_step_fails(self):
        plan = self.install_plan().recheck
        stop = ProcessStopCheck(plan.compatdata, self.f.proc)
        targets = self.lingering_tree()
        busy = {'clear_in_view': False, 'active_count': 6, 'unknown_count': 0}
        with self.f.store() as store, patch.object(dep, '_confirm_proxy_stop', return_value=True), \
                patch.object(ProcessStopCheck, 'check', side_effect=[busy, OSError('DUMMY_PRIVATE')]):
            entry = dep.offer_reinspection_proxy_stop(plan, store, stop, io.StringIO(), io.StringIO(), str,
                                                      sender=lambda key: None)
        self.assertEqual(entry['stop']['result'], 'sigterm-sent')
        self.assertEqual(entry['stop']['observation_error']['error_class'], 'OSError')
        self.assertEqual(dep.signals_sent(entry), 2)
        self.assertNotIn('DUMMY_PRIVATE', json.dumps(entry))
        self.clear_fake()
        self.lingering_tree()
        sent = []

        def sender(key):
            sent.append(key)
            self.clear_fake()
        real_signal = dep.signal_proxies
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch.object(dep, 'ProcessStopCheck', lambda compatdata: ProcessStopCheck(compatdata, self.f.proc)), \
                patch.object(dep, 'signal_proxies', lambda *args: real_signal(*args[:3], sender, *args[4:])), \
                patch.object(dep, 'PROXY_STOP_WAIT', 2), \
                patch.object(dep, 'inspect_managed_dependency', side_effect=Invalid('DUMMY_LATER_FAILURE')):
            status, report, output = self.menu('9\n1\n1\n')
        self.assertEqual(status, 2)
        self.assertEqual(report['lingering']['stop']['result'], 'stopped')
        self.assertEqual(dep.signals_sent(report['lingering']), 1)
        self.assertEqual(report['writes'][0], {'scope': 'sigterm-to-confirmed-sdproxy', 'count': 1})
        self.assertIn('SIGTERMは1件送信済み', output)
        self.assertNotIn('変更はしていません。\n', output.replace('それ以外の変更はしていません。', ''))
        self.assertEqual(sent, [targets[0]])
        self.clear_fake()

    def test_target_change_before_signal_and_remaining_processes_are_not_success(self):
        targets = self.lingering_tree()
        compat = self.f.steam / 'steamapps/compatdata/43'
        with self.assertRaises(Invalid):
            dep.signal_proxies(compat, [(targets[0][0], 999)], self.f.proc, sender=lambda key: self.fail('signalled'))
        self.clear_fake()
        with self.f.store() as store, patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'PROXY_STOP_WAIT', 1):
            session, _ = self.installed_with_lingering(store)
            result = session.stop_lingering_proxies(lambda key: None)
        self.assertEqual(result['lingering']['stop']['result'], 'sigterm-sent-processes-remain')
        self.assertEqual(result['status'], 'needs-user')
        self.assertIsNone(result['post_state'])
        self.clear_fake()

    def test_reinspection_offers_the_stop_and_declining_sends_nothing(self):
        plan = self.install_plan().recheck
        stop = ProcessStopCheck(plan.compatdata, self.f.proc)
        self.lingering_tree()
        with self.f.store() as store:
            entry = dep.offer_reinspection_proxy_stop(plan, store, stop, io.StringIO('q\n'), io.StringIO(), str,
                                                      sender=lambda key: self.fail('declined'))
            self.assertEqual(entry['stop'], {'result': 'declined'})
            output = io.StringIO()
            with patch.object(dep, 'PROXY_STOP_WAIT', 2):
                entry = dep.offer_reinspection_proxy_stop(plan, store, stop, io.StringIO('1\n'), output, str,
                                                          sender=lambda key: self.clear_fake())
            self.assertEqual(entry['stop']['result'], 'stopped')
            self.assertIn('SIGKILL', output.getvalue())
            self.assertEqual(dep.inspect_managed_dependency(plan, store, stop, self.recipe)['state'], 'absent')

    def test_mfc_and_unknown_handlers_are_rejected(self):
        self.config['dependency_installation']['handler'] = 'mfc-local'
        with self.assertRaises(Invalid):
            self.install_plan()

    def test_menu_install_then_reinspection_without_wine(self):
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
            status, report, output = self.menu('8\n1\n1\n1\n1\n')
        self.assertEqual(status, 2)
        self.assertEqual(report['installation']['status'], 'present-verified', output)
        self.assertIn('winver', output)
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch('subprocess.Popen', side_effect=AssertionError('reinspection never starts Wine')):
            status, report, _ = self.menu('9\n1\n')
        self.assertEqual(report['inspection']['state'], 'present-verified')
        self.assertEqual(len(report['installation_history']), 1)
        self.assertFalse(report['wine_started'])

    def test_plan_failure_names_the_check_and_keeps_independent_diagnostics(self):
        appconfig = next((self.f.steam / 'compatibilitytools.d').glob('*/files/share/fex-emu/AppConfig'))
        (appconfig / 'override.json').write_text('{"DUMMY_SECRET": true}')
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch('subprocess.Popen', side_effect=AssertionError('planning failure never starts Wine')):
            status, report, output = self.menu('8\n1\n')
        self.assertEqual(status, 2)
        self.assertEqual(report['stage'], 'dependency-plan')
        self.assertEqual(report['check'], 'recheck-fex-tool-tree')
        self.assertEqual(report['reason'], 'FEX AppConfig is not empty; configuration not permitted')
        self.assertIn('検査停止: recheck-fex-tool-tree', output)
        checks = report['diagnostics']['checks']
        self.assertEqual(checks['managed-recheck-plan']['check'], 'recheck-fex-tool-tree')
        self.assertEqual(checks['dependency-state']['state'], 'absent')
        self.assertIs(checks['asset-file']['recipe_bootstrap'], True)
        self.assertEqual(checks['recheck-records']['records'][0]['status'], 'probe-exited-unverified')
        self.assertTrue(checks['recheck-records']['records'][0]['prefix_version_matches_live'])
        self.assertEqual(checks['registration']['registered'], True)
        self.assertFalse(report['diagnostics']['wine_started'])
        self.assertNotIn('DUMMY_SECRET', json.dumps(report))
        self.assertFalse((self.f.store_root / dep.RECORDS).exists())

    def test_environment_presence_change_is_named_without_values(self):
        reference = self.config['runtime_reference']['environment_presence']
        name = next((key for key in ('DISPLAY', 'XDG_RUNTIME_DIR', 'PULSE_SERVER', 'WAYLAND_DISPLAY')
                     if reference.get(key) and self.environment.get(key)), None)
        if name is None:
            self.skipTest('fixture reference has no present display/runtime variable')
        value = self.environment.pop(name)
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe):
            _, report, _ = self.menu('8\n1\n')
        self.assertEqual(report['check'], 'recheck-runtime-environment')
        differing = report['diagnostics']['checks']['environment-presence']['differing']
        self.assertEqual(differing[name], {'reference': True, 'current': False})
        self.assertNotIn(value, json.dumps(report))

    def test_hard_linked_asset_is_named_with_metadata(self):
        asset = self.f.fixture.source.root / 'sdrt-fixture.exe'
        os.link(asset, self.home / 'second-link.exe')
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe):
            _, report, _ = self.menu('8\n1\n')
        self.assertEqual(report['check'], 'asset-inspection')
        self.assertEqual(report['reason'], 'single-link regular file required')
        file = report['diagnostics']['checks']['asset-file']
        self.assertEqual(file['metadata']['path']['link_count'], 2)
        self.assertEqual(file['inspection']['reason'], 'single-link regular file required')

    def test_menu_cancel_before_gui_check_writes_nothing(self):
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch('subprocess.Popen', side_effect=AssertionError('cancel never executes')):
            status, report, _ = self.menu('8\n1\nq\n')
        self.assertEqual((status, report), (0, None))
        self.assertFalse((self.f.store_root / dep.RECORDS).exists())


for _name in dir(TRIAL['TrialTests']):
    if _name.startswith('test_'):
        setattr(InstallTests, _name, None)


if __name__ == '__main__':
    unittest.main()
