#!/usr/bin/env python3
"""Reviewed new-slot placement, confirmed by an ordinary registered game that is only read."""

import copy
import hashlib
import io
import json
import runpy
import sys
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / 'test_preparation_tool_writer.py'))
FOLDER = runpy.run_path(str(HERE / 'test_preparation_folder_reads.py'))
import preparation_batch as batch
import preparation_selection as selection
import preparation_static_placement as placement
import preparation_tool_writer as writer
from preparation_common import Invalid
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore


class StaticFixture(unittest.TestCase):
    writable_xalia = False
    def setUp(self):
        self.f = FIX['ToolWriterTests']()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        f = self.f
        self.home = f.root / 'private-home'
        self.home.mkdir(mode=0o700)
        selection._private_report_directory(self.home, [])
        f.store_root = self.home / '.local/state/droiddeck-prefix-preparation/tool-store'
        source = f.fixture.source
        with tarfile.open(source.archive, 'r:gz') as original:
            entries = [(copy.copy(m), original.extractfile(m).read() if m.isfile() else None) for m in original]
        root = FIX['FIXTURE']['CUSTOM']['ROOT']
        data = FIX['FIXTURE']['GAME']['pe']()
        with tarfile.open(source.archive, 'w:gz') as package:
            for member, raw in entries:
                package.addfile(member, io.BytesIO(raw) if raw is not None else None)
            for name in ('files', 'files/lib', 'files/lib/wine', 'files/lib/wine/i386-windows'):
                member = tarfile.TarInfo(root + '/' + name)
                member.type, member.mode = tarfile.DIRTYPE, 0o755
                package.addfile(member)
            # The fixture Wine's x86 cmd.exe (used as the x86 layout reference by the game-prefix tests).
            member = tarfile.TarInfo(root + '/files/lib/wine/i386-windows/cmd.exe')
            member.size, member.mode = len(data), 0o444
            package.addfile(member, io.BytesIO(data))
            if self.writable_xalia:
                for name in ('files/share', 'files/share/xalia'):
                    member = tarfile.TarInfo(root + '/' + name)
                    member.type, member.mode = tarfile.DIRTYPE, 0o755
                    package.addfile(member)
                for name in ('Fixture.dll', 'xalia.exe'):
                    member = tarfile.TarInfo(root + '/files/share/xalia/' + name)
                    raw = b'SYNTHETIC_XALIA_NOT_EXECUTED'
                    member.size, member.mode = len(raw), 0o666
                    package.addfile(member, io.BytesIO(raw))
        if hasattr(self, "customize_trial_source"):
            self.customize_trial_source(source.archive, root)
        source.sha = hashlib.sha512(source.archive.read_bytes()).hexdigest()
        f.fixture.options['sha512'] = source.sha
        f.fixture.options['tool_slot'] = 'preparation'
        # The ordinary registered game 42 confirms the placement (only read); later tests prepare it.
        self.exe = f.exe
        (f.steam / 'config').mkdir()
        self.steam_config = f.steam / 'config/config.vdf'
        self.steam_config.write_bytes(f.fixture.game.config.read_bytes())
        self.games_config = f.settings / 'games.json'
        self.games_config.write_bytes((f.fixture.game.settings / 'games.json').read_bytes())
        self.review = {'schema_version': 1, 'basis': 'github-artifact-zip-and-inner-sha512', 'archive_sha512': source.sha,
                       'source_commit': 'a' * 40, 'run_id': '123', 'artifact_id': '456',
                       'artifact_zip_sha256': 'b' * 64, 'build_info_sha256': 'c' * 64}
        if self.writable_xalia:
            self.review['private_xalia_files'] = ['files/share/xalia/Fixture.dll', 'files/share/xalia/xalia.exe']
        self.config = {'schema_version': 1, 'payload': {'archive': source.archive.name, 'sha512': source.sha,
            'root': root, 'mode': 'cleanup', 'tool_slot': 'preparation'}, 'runtime_reference': f.fixture.reference,
            'probe_material': True, 'placement_review': self.review}
        self.environment = {**f.environment, 'BL_ADDED_GAMES': str(f.added)}

    def plan(self):
        return placement.plan_confirmed_placement(self.f.fixture.plan(archive_from_folder=True), self.review,
                                                  self.f.store_root, self.f.settings)

    def apply(self, plan=None, refresh=None):
        plan = self.plan() if plan is None else plan
        with self.f.store() as store:
            return placement.apply_static_placement(plan, self.plan if refresh is None else refresh, store, plan.digest)

    def protected(self):
        paths = [self.exe, self.f.added, self.steam_config, self.games_config]
        return {str(p): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in paths}

    def menu(self, text):
        """prepare.sh for an operational bundle; for any other fixture bundle, the earlier menu numbers
        that still exist (see detail_menu)."""
        if not selection.operational_layout(self.config):
            return self.detail_menu(text)
        output = io.StringIO()
        status, name = batch.interactive_workflow(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
            input_stream=io.StringIO(text), output_stream=output, environment=self.environment, steam=self.f.steam,
            settings=self.f.settings, home=self.home, runtime_root=self.f.root)
        report = json.loads((self.f.fixture.source.root / name).read_bytes()) if name else None
        return status, report, output.getvalue()

    def script(self, entry, text):
        """One of the 1.0.0 scripts (prepare, status, diagnose, recovery)."""
        output = io.StringIO()
        status, name = batch.interactive_workflow(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
            input_stream=io.StringIO(text), output_stream=output, environment=self.environment, steam=self.f.steam,
            settings=self.f.settings, home=self.home, runtime_root=self.f.root, entry=entry)
        report = json.loads((self.f.fixture.source.root / name).read_bytes()) if name else None
        return status, report, output.getvalue()

    def options(self, output, text):
        return {'input_stream': io.StringIO(text), 'output_stream': output, 'environment': self.environment,
                'steam': self.f.steam, 'settings': self.f.settings, 'home': self.home, 'runtime_root': self.f.root}

    def direct(self, function, text):
        output = io.StringIO()
        status, name = function(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
                                **self.options(output, text))
        report = json.loads((self.f.fixture.source.root / name).read_bytes()) if name else None
        return status, report, output.getvalue()

    def entry_menu(self, text):
        """0.31.0's individual operations, mapped to the 1.0.0 scripts: 1 is recovery.sh 1, 2 status.sh,
        5 and 6 recovery.sh 2 and 3, 4 the earlier menu numbers that still exist (3 was removed in 1.0.1)."""
        first, _, rest = text.partition('\n')
        if first == '1':
            return self.script('recovery', '1\n' + rest)
        if first == '2':
            return self.script('status', rest)
        if first in ('5', '6'):
            return self.script('recovery', {'5': '2', '6': '3'}[first] + '\n' + rest)
        if first == '4':
            return self.detail_menu(rest)
        return self.script('recovery', text)

    def detail_menu(self, text):
        """The earlier screen's numbers (removed in 1.0.1) for the functions that remain, called directly
        as that screen did: 8 and 9 (recovery.sh 5 and 6), 10 (4) and 12 (1). q cancels."""
        import preparation_dependency_install as dependency
        import preparation_game_prefix as game_prefix
        import preparation_one_pass as one_pass
        first, _, rest = text.partition('\n')
        function = {'8': dependency.interactive_dependency_install, '9': dependency.interactive_dependency_reinspect,
                    '10': game_prefix.interactive_game_prefix, '12': one_pass.interactive_one_pass}.get(first.strip())
        if function is None:
            self.assertIn(first.strip(), ('q', ''), 'menu ' + first + ' was removed in 1.0.1')
            return 0, None, ''
        return self.direct(function, rest)


class StaticPlanTests(StaticFixture):
    def test_plan_is_read_only_and_does_not_claim_execution_readiness(self):
        before = self.f.fixture.snapshot()
        with patch('subprocess.Popen', side_effect=AssertionError('no executable')):
            plan = self.plan()
        self.assertEqual(before, self.f.fixture.snapshot())
        self.assertEqual(plan.summary()['writes'], [])
        for key in ('execution_authorized', 'prefix_initialization_authorized', 'binding_authorized'):
            self.assertFalse(plan.summary()[key])
        self.assertEqual(plan.summary()['scope'], 'static-preparation-slot-only')

    def test_unknown_or_mismatched_build_review_refused(self):
        for key, value in [('schema_version', True), ('basis', 'operator-flag'), ('archive_sha512', '0' * 128),
                           ('source_commit', '../source'), ('run_id', 'run; execute')]:
            original = self.review[key]
            self.review[key] = value
            with self.subTest(key=key), self.assertRaises(Invalid):
                self.plan()
            self.review[key] = original

    def test_legacy_slot_is_not_eligible_for_static_bypass(self):
        self.f.fixture.options['tool_slot'] = 'legacy'
        with self.assertRaises(Invalid):
            self.plan()

    def test_snapshot_cannot_write_outside_snapshot(self):
        outside = self.f.fixture.source.root / 'outside-management'
        with self.assertRaises(Invalid):
            placement.plan_confirmed_placement(self.f.fixture.plan(archive_from_folder=True), self.review, outside, self.f.settings)

    def test_review_must_match_emitted_bundle_payload(self):
        altered = copy.deepcopy(self.config)
        altered['placement_review']['archive_sha512'] = '0' * 128
        with self.assertRaises(Invalid):
            selection.validate_selection_config(altered)

@unittest.skipUnless(sys.platform == 'linux', 'native static placement requires Linux renameat2')
class StaticNativeTests(StaticFixture):
    def test_static_copy_never_calls_proc_scan_launch_or_full_readiness_callback(self):
        before = self.protected()
        with patch('subprocess.Popen', side_effect=AssertionError('no executable')), \
             patch.object(ProcessStopCheck, 'check', side_effect=AssertionError('no fabricated proc scope')):
            result = self.apply()
        self.assertEqual(result['mode'], 'static-preparation-tool-installed')
        self.assertFalse(result['wine_executed'])
        self.assertFalse(result['prefix_created'])
        self.assertFalse(result['binding_written'])
        self.assertFalse(result['execution_authorized'])
        self.assertEqual(before, self.protected())
        self.assertFalse(self.f.compatdata.exists())
        self.assertEqual(result['installation']['status'], 'installed-tree-verified')

    def test_original_full_writer_still_rejects_missing_stopped_readiness(self):
        self.f.checks['stopped'] = False
        with self.f.store() as store, self.assertRaises(Invalid):
            self.f.apply(store)
        self.assertFalse(self.f.destination().exists())
        self.assertFalse((self.f.store_root / 'installations').exists())

    def test_matching_confirmation_and_locks_are_required(self):
        plan = self.plan()
        with PrivateStore(self.f.store_root, create=True) as store:
            with self.assertRaises(Invalid):
                placement.apply_static_placement(plan, self.plan, store, plan.digest)
            with store.locked(self.f.lock_key), self.assertRaises(Invalid):
                placement.apply_static_placement(plan, self.plan, store, '0' * 64)
        self.assertFalse(self.f.destination().exists())

    def test_mutable_report_action_cannot_fake_reuse_or_skip_placement(self):
        plan = self.plan()
        plan.installation.report['action'] = 'reuse-verified-tree'
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertFalse(self.f.destination().exists())

    def test_review_change_after_preview_refuses_before_tree_writes(self):
        plan = self.plan()
        self.review['source_commit'] = 'd' * 40
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertFalse(self.f.destination().exists())

    def test_source_change_after_staging_preserves_stage_without_publish(self):
        actual = writer._stream_tree
        def changed(*args):
            result = actual(*args)
            self.exe.write_bytes(self.exe.read_bytes() + b'changed')
            return result
        with patch.object(writer, '_stream_tree', side_effect=changed), self.assertRaises(Invalid):
            self.apply()
        self.assertFalse(self.f.destination().exists())
        self.assertEqual(len(list((self.f.steam / 'compatibilitytools.d').glob('.prefix-preparation-staging-*'))), 1)

    def test_publication_race_never_replaces_existing_directory(self):
        destination = self.f.destination()
        actual = writer._publish
        def collide(*args):
            destination.mkdir()
            (destination / 'keep').write_text('RACE_SENTINEL')
            return actual(*args)
        with patch.object(writer, '_publish', side_effect=collide), self.assertRaises(FileExistsError):
            self.apply()
        self.assertEqual((destination / 'keep').read_text(), 'RACE_SENTINEL')
        self.assertEqual(list(destination.iterdir()), [destination / 'keep'])

    def test_changed_existing_new_slot_is_not_repaired_or_replaced(self):
        self.apply()
        target = self.f.destination()
        (target / 'proton').write_bytes(b'changed')
        before = (target / 'proton').read_bytes()
        with self.assertRaises(Invalid):
            self.plan()
        self.assertEqual((target / 'proton').read_bytes(), before)

    def test_legacy_tool_is_preserved_even_when_it_differs(self):
        tools = self.f.steam / 'compatibilitytools.d'
        tools.mkdir()
        legacy = tools / self.f.plan().customization.directory.replace('SoftDenchi-Prep-Proton', 'SoftDenchi-Proton')
        legacy.mkdir(mode=0o700)
        file = legacy / 'proton'
        file.write_bytes(b'PRIVATE_LEGACY_SENTINEL')
        before = file.read_bytes(), file.stat().st_mtime_ns
        self.apply()
        self.assertEqual(before, (file.read_bytes(), file.stat().st_mtime_ns))
        self.assertTrue(self.f.destination().is_dir())

    def test_matching_existing_tree_is_read_only_observation(self):
        self.apply()
        plan = self.plan()
        before = self.f.fixture.snapshot()
        result = self.apply(plan)
        self.assertEqual(result['mode'], 'static-matching-tool-observed')
        self.assertEqual(result['writes'], [])
        self.assertEqual(before, self.f.fixture.snapshot())

    def test_capacity_is_not_double_counted_after_tree_has_been_staged(self):
        plan = self.plan()
        calls = 0
        def refresh():
            nonlocal calls
            calls += 1
            current = self.plan()
            if calls >= 3:
                current.installation.report['capacity'].update(available_bytes=1, estimate_fits=False)
            return current
        result = self.apply(plan, refresh)
        self.assertEqual(result['mode'], 'static-preparation-tool-installed')
        self.assertGreaterEqual(calls, 3)

    def test_low_initial_capacity_is_refused(self):
        plan = self.plan()
        def refresh():
            current = self.plan()
            current.installation.report['capacity'].update(available_bytes=1, estimate_fits=False)
            return current
        with self.assertRaises(Invalid):
            self.apply(plan, refresh)
        self.assertFalse(self.f.destination().exists())

class PrivateModePlanTests(StaticFixture):
    writable_xalia = True

    def test_missing_or_extra_reviewed_file_refuses(self):
        approved = self.review.pop('private_xalia_files')
        with self.assertRaises(Invalid):
            self.plan()
        self.review['private_xalia_files'] = approved + ['files/share/xalia/unexpected.dll']
        with self.assertRaises(Invalid):
            self.plan()
        self.assertFalse(self.f.destination().exists())

    def test_nonprivate_tool_parent_refuses_without_chmod(self):
        tools = self.f.steam / 'compatibilitytools.d'
        tools.mkdir()
        tools.chmod(0o755)
        before = self.f.fixture.snapshot()
        with self.assertRaises(Invalid):
            self.plan()
        self.assertEqual(tools.stat().st_mode & 0o777, 0o755)
        self.assertEqual(before, self.f.fixture.snapshot())

    def test_review_cannot_name_arbitrary_writable_payload_paths(self):
        self.review['private_xalia_files'] = ['files/bin-arm64/wine']
        with self.assertRaises(Invalid):
            self.plan()


@unittest.skipUnless(sys.platform == 'linux', 'native static placement requires Linux renameat2')
class PrivateModeNativeTests(StaticFixture):
    writable_xalia = True

    def test_exact_reviewed_modes_preserved_only_under_private_parent(self):
        before = self.protected()
        result = self.apply()
        self.assertEqual(result['mode'], 'static-preparation-tool-installed')
        destination = self.f.destination()
        for name in self.review['private_xalia_files']:
            path = destination / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o666)
            self.assertEqual(path.read_bytes(), b'SYNTHETIC_XALIA_NOT_EXECUTED')
        self.assertEqual(destination.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(before, self.protected())
        self.assertFalse(result['execution_authorized'])

    def test_private_parent_change_after_streaming_stops_publication(self):
        actual = writer._stream_tree
        def expose(*args):
            result = actual(*args)
            (self.f.steam / 'compatibilitytools.d').chmod(0o755)
            return result
        with patch.object(writer, '_stream_tree', side_effect=expose), self.assertRaises(Invalid):
            self.apply()
        self.assertFalse(self.f.destination().exists())
        self.assertEqual(len(list((self.f.steam / 'compatibilitytools.d').glob('.prefix-preparation-staging-*'))), 1)

    def test_full_writer_does_not_gain_private_permission_exception(self):
        with self.f.store() as store, self.assertRaises(Invalid) as caught:
            self.f.apply(store)
        self.assertEqual(str(caught.exception), 'unsupported payload permissions')
        self.assertFalse(self.f.destination().exists())


class ConfirmedFixture(StaticFixture):
    """Placement confirmed by an ordinary registered game (42), which is only read."""

    def confirmed_plan(self, key='42', exe_root=None):
        installation = self.f.fixture.plan(registration_id=key, exe_root=exe_root or self.f.exe_root, archive_from_folder=True)
        return placement.plan_confirmed_placement(installation, self.review, self.f.store_root, self.f.settings)

    def confirmed_apply(self, plan):
        compatdata = self.f.steam / 'steamapps/compatdata/42'
        with PrivateStore(self.f.store_root, create=True) as store, store.locked(hashlib.sha256(str(compatdata).encode()).hexdigest()):
            return placement.apply_static_placement(plan, self.confirmed_plan, store, plan.digest)

    def game_files(self):
        paths = [self.f.exe, self.f.added, self.steam_config, self.games_config]
        prefix = self.f.steam / 'steamapps/compatdata/42'
        paths += sorted(prefix.rglob('*')) if prefix.exists() else []
        return {str(p): (p.read_bytes() if p.is_file() else None, p.stat().st_mtime_ns, p.stat().st_ino) for p in paths}


class ConfirmedPlanTests(ConfirmedFixture):
    def test_ordinary_registration_plans_read_only_under_its_own_key(self):
        before = self.f.fixture.snapshot()
        with patch('subprocess.Popen', side_effect=AssertionError('no executable')):
            plan = self.confirmed_plan()
        self.assertEqual(before, self.f.fixture.snapshot())
        summary = plan.summary()
        self.assertNotIn('probe_registration', summary)
        self.assertEqual(summary['confirmation_registration']['kind'], 'confirmation-registration')
        self.assertEqual(summary['confirmation_registration']['app_id'], '42')
        self.assertEqual(summary['writes'], [])
        self.assertTrue(plan.installation.archive_from_folder)
        for key in ('execution_authorized', 'prefix_initialization_authorized', 'binding_authorized'):
            self.assertFalse(summary[key])

    def test_existing_prefix_is_allowed_and_only_read(self):
        prefix = self.f.steam / 'steamapps/compatdata/42/pfx'
        prefix.mkdir(parents=True)
        (prefix / 'user.reg').write_text('fixture')
        before = self.f.fixture.snapshot()
        self.assertEqual(self.confirmed_plan().summary()['confirmation_registration']['app_id'], '42')
        self.assertEqual(before, self.f.fixture.snapshot())

    def test_two_registrations_of_one_executable_are_ambiguous(self):
        games = json.loads(self.f.added.read_bytes())
        games.append({'appid': 44, 'exe': str(self.f.exe), 'name': 'Duplicate'})
        self.f.added.write_text(json.dumps(games))
        with self.assertRaisesRegex(Invalid, 'ambiguous confirmation registration'):
            self.confirmed_plan()

    def test_game_folder_inside_the_settings_is_refused_by_the_plan_too(self):
        inside = self.f.settings / 'games'
        inside.mkdir()
        exe = inside / 'Inside.exe'
        exe.write_bytes(self.f.exe.read_bytes() + b'inside')
        games = json.loads(self.f.added.read_bytes())
        games.append({'appid': 45, 'exe': str(exe), 'name': 'Inside'})
        self.f.added.write_text(json.dumps(games))
        with self.assertRaisesRegex(Invalid, 'game folder overlaps tool folders'):
            self.confirmed_plan('45', inside)

    def test_candidates_exclude_unsafe_prefixes_with_reasons(self):
        base = self.f.steam / 'steamapps/compatdata'
        base.mkdir(parents=True)
        other = self.f.root / 'other-games'
        other.mkdir()
        games = {
            '42': {'exe': str(self.f.exe)},
            '50': {'exe': str(other / 'a.exe')},
            str(2**32 - 5): {'exe': str(other / 'b.exe')},
            '60': {'exe': str(self.f.steam / 'game.exe')},
            '61': {'exe': str(self.f.root / 'c.exe')},
            '62': {'exe': str(self.f.settings / 'inside' / 'e.exe')},
            '70': {'exe': str(other / 'd.exe')},
            '71': {'exe': str(other / 'd.exe')},
        }
        (other / 'd.exe').write_bytes(b'x')
        (base / '50').symlink_to(other)
        (base / str(2**32 - 5)).mkdir()
        (base / '-5').mkdir()
        management = self.home / '.local/state/droiddeck-prefix-preparation/tool-store'
        selectable, excluded = placement._confirmation_candidates(games, self.f.steam, self.f.settings, management)
        self.assertEqual(selectable, ['42'])
        self.assertEqual(dict(excluded), {'50': 'prefix is a symbolic link', str(2**32 - 5): 'two prefix aliases exist',
                                          '60': 'game folder overlaps tool folders', '61': 'game folder overlaps tool folders',
                                          '62': 'game folder overlaps tool folders',
                                          '70': 'ambiguous confirmation registration', '71': 'ambiguous confirmation registration'})

def report_name(output):
    return output.rsplit('結果を保存しました: ', 1)[1].strip()


@unittest.skipUnless(sys.platform == 'linux', 'native static placement requires Linux renameat2')
class ConfirmedNativeTests(ConfirmedFixture):
    def test_change_of_the_confirmation_game_after_preview_publishes_nothing(self):
        plan = self.confirmed_plan()
        with self.f.exe.open('ab') as out:
            out.write(b'changed')
        with self.assertRaises(Invalid):
            self.confirmed_apply(plan)
        self.assertFalse(self.f.destination().exists())

    def test_confirmed_placement_records_the_confirmation_registration(self):
        result = self.confirmed_apply(self.confirmed_plan())
        self.assertEqual(result['mode'], 'static-preparation-tool-installed')
        self.assertEqual(result['confirmation_registration']['kind'], 'confirmation-registration')


if __name__ == '__main__':
    unittest.main()
