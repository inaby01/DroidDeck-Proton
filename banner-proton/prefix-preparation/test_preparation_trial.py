#!/usr/bin/env python3
"""Dedicated initialization scope using a harmless native fixture, never Wine."""

import copy
import io
import json
import runpy
import subprocess
import sys
import tarfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / 'test_preparation_static_placement.py'))
import preparation_execution as execution
import preparation_recheck as recheck
import preparation_trial as trial
import preparation_trial_audit as audit
from preparation_common import Invalid
from preparation_execution import LaunchSession
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore

FAKE = b'''#!/usr/bin/python3
import os
from pathlib import Path
root = Path(os.environ['STEAM_COMPAT_DATA_PATH'])
(root / 'pfx/drive_c/windows').mkdir(parents=True, exist_ok=True)
for name in ('system.reg', 'user.reg'):
    (root / 'pfx' / name).write_text('WINE REGISTRY Version 2\\n')
(root / 'version').write_text('synthetic-version-1\\n')
'''


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux filesystem/native fixture; not device Wine')
class TrialTests(BASE['StaticFixture']):
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
        self.apply()
        (self.f.steam / "steamapps/compatdata").mkdir(parents=True, exist_ok=True)
        # Fixtures are snapshots, never permitted as live roots in production.
        self.addCleanup(patch.stopall)
        self.live_requirement = trial._live_runtime
        patch.object(trial, '_live_runtime', return_value=None).start()
        patch.object(trial, 'RESERVE', 1024 * 1024).start()

    def trial_plan(self):
        return trial.plan_trial(self.plan(), self.home)

    def launch_fixture(self, **kwargs):
        # A native surrogate has no DroidDeck hooks or real Wine dependencies.
        kwargs['runtime_plan'] = None
        kwargs['runtime_environment'] = {}
        return execution.plan_launch(**kwargs)

    def session(self, plan, store, **kwargs):
        return trial.TrialSession(plan, store, kwargs.get('refresh', self.trial_plan),
            kwargs.get('confirmation', plan.digest), kwargs.get('stop', ProcessStopCheck(plan.compatdata, self.f.proc)))

    def record(self):
        files = list((self.f.store_root / 'trials').glob('trial-*.json'))
        return json.loads(files[-1].read_bytes())

    def test_plan_is_read_only_and_never_asserts_runtime_readiness(self):
        before = self.protected()
        with patch('subprocess.Popen', side_effect=AssertionError('no child')):
            plan = self.trial_plan()
        self.assertEqual(before, self.protected())
        self.assertFalse(plan.compatdata.exists())
        self.assertFalse(plan.work.parent.exists())
        self.assertFalse(plan.summary()['execution_authorized'])
        self.assertFalse(plan.summary()['runtime_execution_verified'])

    def test_live_root_is_required_without_fixture_double(self):
        with patch.object(trial, '_live_runtime', self.live_requirement), self.assertRaisesRegex(Invalid, 'live current-root'):
            self.trial_plan()

    def test_requires_reviewed_installed_tool_and_absent_prefix(self):
        plan = self.trial_plan()
        plan.compatdata.mkdir()
        with self.assertRaises(Invalid):
            self.trial_plan()
        self.assertTrue(plan.compatdata.exists())

    def test_existing_private_trial_root_is_preserved(self):
        plan = self.trial_plan()
        plan.work.parent.mkdir(parents=True)
        marker = plan.work.parent / 'DUMMY_PRIVATE'
        marker.write_text('preserve')
        with self.assertRaises(Invalid):
            self.trial_plan()
        self.assertEqual(marker.read_text(), 'preserve')

    def test_trial_capacity_reserve_is_required(self):
        with patch.object(trial, 'RESERVE', 2**63), self.assertRaises(Invalid):
            self.trial_plan()

    def test_exact_confirmation_and_locks_are_required(self):
        plan = self.trial_plan()
        with self.f.store() as store, self.assertRaises(Invalid):
            self.session(plan, store, confirmation='0' * 64).start()
        self.assertFalse(plan.compatdata.exists())
        self.assertFalse(plan.work.exists())

    def test_active_and_unknown_view_refuse_before_creating_paths(self):
        for observation in ({'clear_in_view': False, 'active_count': 1}, {'clear_in_view': False, 'unknown_count': 1}):
            plan = self.trial_plan()
            with self.f.store() as store, patch.object(ProcessStopCheck, 'check', return_value=observation), self.assertRaises(Invalid):
                self.session(plan, store).start()
            self.assertFalse(plan.work.exists())
            self.assertFalse(plan.compatdata.exists())

    def test_changed_inputs_refuse_before_mutation(self):
        plan = self.trial_plan()
        with self.f.store() as store, self.assertRaises(Invalid):
            self.session(plan, store, refresh=lambda: replace(plan, digest='0' * 64)).start()
        self.assertFalse(plan.compatdata.exists())

    def test_native_fixture_initializes_and_preserves_all_protected_inputs(self):
        plan = self.trial_plan()
        before = self.protected()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            record = session.wait(10)
        self.assertEqual(record['status'], 'initialized-unverified')
        self.assertTrue(record['settings_identity_unchanged'])
        self.assertFalse(record['runtime_execution_verified'])
        self.assertFalse(record['preparation_complete'])
        self.assertEqual(before, self.protected())
        self.assertEqual(plan.work.stat().st_mode & 0o777, 0o700)
        self.assertTrue((plan.compatdata / 'pfx/user.reg').exists())
        self.assertNotIn('PROOT_FP_KEY', json.dumps(record))
        with PrivateStore(self.f.store_root) as store:
            found = store.inventory()['trials']
        self.assertEqual(found[0]['status'], 'initialized-unverified')
        self.assertTrue(found[0]['reinspection_required'])


    def test_without_target_lock_refuses_before_writes(self):
        plan = self.trial_plan()
        with PrivateStore(self.f.store_root) as store, self.assertRaises(Invalid):
            self.session(plan, store).start()
        self.assertFalse(plan.work.exists())
        self.assertFalse(plan.compatdata.exists())

    def test_cancelled_trial_menu_does_not_launch_or_create(self):
        self.config['initialization_trial'] = True
        before = self.protected()
        with patch('subprocess.Popen', side_effect=AssertionError('no child')):
            status, report, output = self.menu('5\n1\nq\n')
        self.assertEqual(status, 0)
        self.assertIsNone(report)
        self.assertIn('新規prefix', output)
        self.assertEqual(before, self.protected())
        self.assertFalse((self.home / '.local/share/droiddeck-preparation-work').exists())

    def test_confirmed_trial_menu_saves_result_and_preserves_settings(self):
        self.config['initialization_trial'] = True
        before = self.protected()
        with patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            _, report, _ = self.menu('5\n1\n1\n')
        self.assertEqual(report['trial']['status'], 'initialized-unverified')
        self.assertTrue(report['prefix_created'])
        self.assertFalse(report['binding_written'])
        self.assertFalse(report['preparation_complete'])
        self.assertEqual(before, self.protected())

    def test_lingering_services_get_bounded_grace_without_forced_termination(self):
        plan = self.trial_plan()
        clear = {'clear_in_view': True, 'device_namespace_verified': False}
        busy = {**clear, 'clear_in_view': False, 'active_count': 1}
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            with patch.object(ProcessStopCheck, 'check', side_effect=[busy, clear]):
                result = session.wait(1)
        self.assertEqual(result['status'], 'initialized-unverified')
        self.assertFalse(result['device_namespace_verified'])

    def test_settings_change_is_detected_and_never_repaired(self):
        plan = self.trial_plan()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            session.process.wait(timeout=10)
            self.games_config.write_text('{"DUMMY_EXTERNAL_CHANGE": true}')
            result = session.wait(1)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['settings_identity_unchanged'])
        self.assertIn('DUMMY_EXTERNAL_CHANGE', self.games_config.read_text())
        self.assertTrue(plan.compatdata.exists())

    def test_replaced_tool_after_spawn_is_reported_failed_without_cleanup(self):
        plan = self.trial_plan()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            session.process.wait(timeout=10)
            (session.launch.spec['tool'] / 'version').write_bytes(b'changed-after-launch')
            self.assertEqual(session.wait(1)['status'], 'failed')
        self.assertTrue(plan.compatdata.exists())
        self.assertTrue(plan.work.exists())

    def test_post_audit_reports_tree_changes_and_prefix_together_without_execution(self):
        self.config['initialization_trial'] = True
        plan = self.trial_plan()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            session.process.wait(timeout=10)
            cache = session.launch.spec['tool'] / '__pycache__'
            cache.mkdir()
            (cache / 'DUMMY_PRIVATE').write_bytes(b'DUMMY_SECRET')
            original = session.wait(1)
        self.assertEqual(original['status'], 'failed')
        # Refused under the runtime contract's cache rule; the unknown file name is not disclosed.
        self.assertEqual(original['error']['tree_diagnostic']['check'], 'python-cache')
        self.assertEqual(original['error']['tree_diagnostic']['relative_path'], '__pycache__')
        record_file = self.f.store_root / 'trials' / (original['trial_id'] + '.json')
        before = record_file.read_bytes()
        with patch('subprocess.Popen', side_effect=AssertionError('audit never executes')):
            _, report, _ = self.menu('6\n1\n')
        self.assertEqual(report['origin_status'], 'failed')
        self.assertTrue(report['trial_record_unchanged'])
        self.assertFalse(report['status_promoted'])
        self.assertEqual(report['checks']['prefix-structure']['status'], 'accepted')
        self.assertEqual(report['checks']['strict-tool-identity']['status'], 'rejected')
        self.assertEqual(report['checks']['tool-differences']['difference_count'], 1)
        self.assertEqual(before, record_file.read_bytes())
        self.assertNotIn('DUMMY_SECRET', json.dumps(report))
        self.assertTrue(cache.exists())

    def test_post_audit_keeps_independent_checks_when_source_archive_is_missing(self):
        self.config['initialization_trial'] = True
        plan = self.trial_plan()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            session.wait(10)
        archive = self.f.fixture.source.archive
        archive.rename(archive.with_suffix('.preserved'))
        with patch('subprocess.Popen', side_effect=AssertionError('no retry')):
            _, report, _ = self.menu('6\n1\n')
        self.assertEqual(report['checks']['source-archive']['status'], 'rejected')
        self.assertEqual(report['checks']['prefix-structure']['status'], 'accepted')
        self.assertEqual(report['checks']['process-observation']['status'], 'accepted')
        self.assertTrue(report['dependent_checks_not_run'])
        self.assertFalse(report['status_promoted'])

    def test_prefix_measurement_does_not_follow_drive_links_or_read_values(self):
        root = self.home / 'measure-fixture'
        root.mkdir()
        external = self.home / 'DUMMY_PRIVATE_AUTH'
        external.write_bytes(b'DUMMY_SECRET')
        (root / 'drive-link').symlink_to(external)
        with patch('builtins.open', side_effect=AssertionError('metadata only')):
            result = audit.measure_prefix(root)
        self.assertEqual(result['symlinks_not_followed'], 1)
        self.assertEqual(result['logical_file_bytes'], 0)
        self.assertFalse(result['contents_read'])
        self.assertNotIn('DUMMY', json.dumps(result))

    def recheck_origin(self):
        self.config['initialization_trial'] = True
        plan = self.trial_plan()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = self.session(plan, store).start()
            session.wait(10)
            record, digest = store.read_record('trials', session.record['trial_id'] + '.json')
        directory = session.launch.spec['tool'] / 'files/share/fex-emu/AppConfig'
        directory.mkdir(mode=0o700)
        self.addCleanup(patch.stopall)
        self.recheck_live_requirement = recheck._require_live
        patch.object(recheck, '_require_live', return_value=None).start()
        return record, digest, directory

    def recheck_plan(self, record, digest):
        source, _, games = BASE['selection'].registration_catalog(self.environment)
        return recheck.plan_recheck(record=record, record_sha256=digest, config=self.config,
            directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'],
            source=source, games=games, steam=self.f.steam, settings=self.f.settings, home=self.home,
            environment=self.environment, runtime_root=self.f.root)

    def test_recheck_native_command_retains_old_history_and_existing_prefix(self):
        record, digest, directory = self.recheck_origin()
        plan = self.recheck_plan(record, digest)
        sentinel = plan.compatdata / 'DUMMY_PRESERVE'
        sentinel.write_text('preserve')
        protected = self.protected()
        with self.f.store() as store, patch.object(recheck, 'plan_launch', side_effect=self.launch_fixture):
            session = recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest),
                plan.digest, ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            result = session.wait(10)
            self.assertEqual(store.read_record('trials', record['trial_id'] + '.json')[1], digest)
            self.assertTrue(store.inventory()['rechecks'][0]['reinspection_required'])
        self.assertEqual(result['status'], 'probe-exited-unverified')
        self.assertFalse(result['old_trial_record_updated'])
        self.assertFalse(result['preparation_complete'])
        self.assertEqual(sentinel.read_text(), 'preserve')
        self.assertEqual(protected, self.protected())
        self.assertTrue(directory.exists())

    def test_recheck_refuses_config_in_runtime_directory_and_changed_origin(self):
        record, digest, directory = self.recheck_origin()
        file = directory / 'override.json'
        file.write_text('{"DUMMY_SECRET": true}')
        with self.assertRaises(Invalid):
            self.recheck_plan(record, digest)
        file.unlink()
        with self.assertRaises(Invalid):
            self.recheck_plan(record, '0' * 64)

    def test_existing_probe_inspection_does_not_enable_normal_new_prefix_verification(self):
        record, digest, _directory = self.recheck_origin()
        plan = self.recheck_plan(record, digest)
        with self.assertRaises(Invalid):
            BASE['probe'].verify_probe_registration(plan.target.exe, plan.record['app_id'], plan.target.source,
                                                   plan.target.steam, plan.probe_store)

    def test_recheck_launch_plan_cannot_use_ordinary_ready_flags(self):
        record, digest, _directory = self.recheck_origin()
        plan = self.recheck_plan(record, digest)
        captured = []
        def capture(**kwargs):
            value = self.launch_fixture(**kwargs)
            captured.append(value)
            return value
        with self.f.store() as store, patch.object(recheck, 'plan_launch', side_effect=capture):
            session = recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest),
                plan.digest, ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            session.wait(10)
            with self.assertRaises(Invalid):
                LaunchSession(captured[0], store, lambda: {'target': True, 'payload': True, 'runtime': True, 'stopped': True},
                              ProcessStopCheck(plan.compatdata, self.f.proc)).start()
        self.assertEqual(captured[0].argv[1], 'runinprefix')

    def test_recheck_menu_cancel_and_confirm_are_scoped_separately(self):
        self.recheck_origin()
        with patch('subprocess.Popen', side_effect=AssertionError('cancel never executes')):
            status, report, _ = self.menu('7\n1\nq\n')
        self.assertEqual(status, 0)
        self.assertIsNone(report)
        with patch.object(recheck, 'plan_launch', side_effect=self.launch_fixture):
            _, report, _ = self.menu('7\n1\n1\n')
        self.assertEqual(report['recheck']['status'], 'probe-exited-unverified')
        self.assertTrue(report['old_trial_record_unchanged'])
        self.assertFalse(report['prefix_reinitialized'])

    def test_recheck_active_view_and_wrong_confirmation_never_launch(self):
        record, digest, _ = self.recheck_origin()
        plan = self.recheck_plan(record, digest)
        with self.f.store() as store, patch('subprocess.Popen', side_effect=AssertionError('no child')):
            with self.assertRaises(Invalid):
                recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest), '0' * 64,
                    ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            with patch.object(ProcessStopCheck, 'check', return_value={'clear_in_view': False, 'unknown_count': 1}), self.assertRaises(Invalid):
                recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest), plan.digest,
                    ProcessStopCheck(plan.compatdata, self.f.proc)).start()
        self.assertFalse((self.f.store_root / 'rechecks').exists())

    def test_recheck_timeout_can_resume_wait_without_forced_termination(self):
        record, digest, _ = self.recheck_origin()
        plan = self.recheck_plan(record, digest)
        fake = unittest.mock.Mock()
        fake.wait.side_effect = [subprocess.TimeoutExpired('DUMMY_PRIVATE', 1), 0]
        with self.f.store() as store, patch.object(recheck, 'plan_launch', side_effect=self.launch_fixture), patch.object(recheck.subprocess, 'Popen', return_value=fake):
            session = recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest), plan.digest,
                ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            self.assertEqual(session.wait(1)['status'], 'needs-user')
            result = session.wait(1)
            self.assertEqual(result['status'], 'probe-exited-unverified')
            fake.kill.assert_not_called()
            fake.terminate.assert_not_called()
            self.assertNotIn('DUMMY_PRIVATE', json.dumps(result))

    def test_recheck_detects_settings_change_without_repair(self):
        record, digest, _ = self.recheck_origin()
        plan = self.recheck_plan(record, digest)
        with self.f.store() as store, patch.object(recheck, 'plan_launch', side_effect=self.launch_fixture):
            session = recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest), plan.digest,
                ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            session.process.wait(timeout=10)
            self.games_config.write_text('{"DUMMY_EXTERNAL_CHANGE": true}')
            result = session.wait(1)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['settings_identity_unchanged'])
        self.assertIn('DUMMY_EXTERNAL_CHANGE', self.games_config.read_text())

    def test_failed_tree_mismatch_origin_retains_immutable_history(self):
        record, digest, _ = self.recheck_origin()
        record.update(status='failed', tool_version='0.19.0', error={'check': 'trial-post-checks', 'error_class': 'TreeMismatch', 'errno': None})
        with self.f.store() as store:
            digest = store.write_record('trials', record['trial_id'] + '.json', record, expected_hash=digest)
        plan = self.recheck_plan(record, digest)
        with self.f.store() as store, patch.object(recheck, 'plan_launch', side_effect=self.launch_fixture):
            session = recheck.RecheckSession(plan, store, lambda: self.recheck_plan(record, digest), plan.digest,
                ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            self.assertEqual(session.wait(10)['status'], 'probe-exited-unverified')
            old, current = store.read_record('trials', record['trial_id'] + '.json')
        self.assertEqual(current, digest)
        self.assertEqual(old['status'], 'failed')

    def test_recheck_requires_live_runtime_and_private_prefix_ancestors(self):
        record, digest, _ = self.recheck_origin()
        with patch.object(recheck, '_require_live', self.recheck_live_requirement), self.assertRaisesRegex(Invalid, 'live runtime'):
            self.recheck_plan(record, digest)
        plan = self.recheck_plan(record, digest)
        plan.compatdata.parent.chmod(0o777)
        self.addCleanup(plan.compatdata.parent.chmod, 0o700)
        with self.assertRaises(Invalid):
            self.recheck_plan(record, digest)

    def test_failure_before_spawn_is_journaled_and_preserved(self):
        plan = self.trial_plan()
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=Invalid('DUMMY_SECRET')), self.assertRaises(Invalid):
            self.session(plan, store).start()
        self.assertTrue(plan.work.exists())
        self.assertFalse(plan.compatdata.exists())
        record = self.record()
        self.assertEqual(record['status'], 'failed')
        self.assertNotIn('DUMMY_SECRET', json.dumps(record))

    def test_timeout_never_kills_child_and_can_be_waited_again(self):
        plan = self.trial_plan()
        fake = unittest.mock.Mock()
        fake.wait.side_effect = [subprocess.TimeoutExpired('private-command', 1), 7]
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture), patch.object(trial.subprocess, 'Popen', return_value=fake):
            session = self.session(plan, store).start()
            self.assertEqual(session.wait(1)['status'], 'needs-user')
            self.assertEqual(session.wait(1)['status'], 'failed')
            fake.kill.assert_not_called()
            fake.terminate.assert_not_called()
        self.assertTrue(plan.compatdata.exists())
        self.assertNotIn('private-command', json.dumps(self.record()))

    def test_zero_exit_without_prefix_structure_is_not_success(self):
        plan = self.trial_plan()
        fake = unittest.mock.Mock()
        fake.wait.return_value = 0
        with self.f.store() as store, patch.object(trial, 'plan_launch', side_effect=self.launch_fixture), patch.object(trial.subprocess, 'Popen', return_value=fake):
            session = self.session(plan, store).start()
            self.assertEqual(session.wait(1)['status'], 'failed')
        self.assertTrue(plan.compatdata.exists())

    def test_prefix_appearing_after_preview_is_not_overwritten(self):
        plan = self.trial_plan()
        plan.compatdata.mkdir()
        marker = plan.compatdata / 'DUMMY_EXISTING_DATA'
        marker.write_text('preserve')
        with self.f.store() as store, self.assertRaises(Invalid):
            self.session(plan, store).start()
        self.assertEqual(marker.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
