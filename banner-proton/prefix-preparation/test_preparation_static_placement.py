#!/usr/bin/env python3
"""Reviewed new-slot placement; full legacy readiness remains mandatory elsewhere."""

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
import preparation_probe as probe
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
        self.probe_store = self.home / '.local/state/droiddeck-prefix-preparation/probe-store'
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
            member = tarfile.TarInfo(root + '/' + probe.MEMBER)
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
        source.sha = hashlib.sha512(source.archive.read_bytes()).hexdigest()
        f.fixture.options['sha512'] = source.sha
        f.fixture.options['tool_slot'] = 'preparation'
        base = f.root / 'shared-probe'
        base.mkdir()
        material = probe.plan_probe_material(source.archive, source.sha, root, f.added, f.steam, base)
        with PrivateStore(self.probe_store, create=True) as store, store.locked(hashlib.sha256(material.record['destination'].encode()).hexdigest()):
            probe.create_probe_material(material, lambda: probe.plan_probe_material(source.archive, source.sha, root,
                f.added, f.steam, base, probe_id=material.record['probe_id']), store)
        self.exe = Path(material.record['destination']) / probe.EXE
        games = json.loads(f.added.read_bytes())
        games.append({'appid': 43, 'exe': str(self.exe), 'name': 'New registration probe'})
        f.added.write_text(json.dumps(games))
        f.fixture.options.update(registration_id='43', exe_root=self.exe.parent)
        f.compatdata = f.steam / 'steamapps/compatdata/43'
        f.lock_key = hashlib.sha256(str(f.compatdata).encode()).hexdigest()
        f.stop_check = ProcessStopCheck(f.compatdata, f.proc)
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
        return placement.plan_static_placement(self.f.plan(), self.review, self.f.store_root, self.probe_store, self.f.settings)

    def apply(self, plan=None, refresh=None):
        plan = self.plan() if plan is None else plan
        with self.f.store() as store:
            return placement.apply_static_placement(plan, self.plan if refresh is None else refresh, store, plan.digest)

    def protected(self):
        paths = [self.exe, self.exe.parent / probe.MARKER, self.f.added, self.steam_config, self.games_config]
        return {str(p): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in paths}

    def menu(self, text):
        output = io.StringIO()
        status, name = probe.interactive_workflow(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
            input_stream=io.StringIO(text), output_stream=output, environment=self.environment, steam=self.f.steam,
            settings=self.f.settings, home=self.home, runtime_root=self.f.root)
        report = json.loads((self.f.fixture.source.root / name).read_bytes()) if name else None
        return status, report, output.getvalue()


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

    def test_unready_receipt_is_not_eligible(self):
        with PrivateStore(self.probe_store) as store:
            directory = next((self.probe_store / 'probe-runs').glob('*.json'))
            record, digest = store.read_record('probe-runs', directory.name)
            key = hashlib.sha256(record['destination'].encode()).hexdigest()
            with store.locked(key):
                record['status'] = 'probe-failed'
                store.write_record('probe-runs', directory.name, record, digest)
        with self.assertRaises(Invalid):
            self.plan()

    def test_probe_source_archive_must_match_reviewed_placement_source(self):
        with PrivateStore(self.probe_store) as store:
            path = next((self.probe_store / 'probe-runs').glob('*.json'))
            record, digest = store.read_record('probe-runs', path.name)
            key = hashlib.sha256(record['destination'].encode()).hexdigest()
            with store.locked(key):
                record['archive_sha512'] = '0' * 128
                store.write_record('probe-runs', path.name, record, digest)
        (self.exe.parent / probe.MARKER).write_text(json.dumps(probe._marker(record)))
        with self.assertRaises(Invalid):
            self.plan()

    def test_existing_prefix_refused_before_any_tool_write(self):
        self.f.compatdata.mkdir(parents=True)
        with self.assertRaises(Invalid):
            self.plan()
        self.assertFalse(self.f.destination().exists())

    def test_snapshot_cannot_write_outside_snapshot(self):
        outside = self.f.fixture.source.root / 'outside-management'
        with self.assertRaises(Invalid):
            placement.plan_static_placement(self.f.plan(), self.review, outside, self.probe_store, self.f.settings)

    def test_review_must_match_emitted_bundle_payload(self):
        altered = copy.deepcopy(self.config)
        altered['placement_review']['archive_sha512'] = '0' * 128
        with self.assertRaises(Invalid):
            selection.validate_selection_config(altered)

    def test_cancel_selection_and_preview_write_nothing(self):
        before = self.f.fixture.snapshot()
        for answer in ('4\nq\n', '4\n1\nq\n', '4\n1\n', '4\n1\nyes\n'):
            status, report, _ = self.menu(answer)
            self.assertEqual((status, report), (0, None))
        self.assertEqual(before, self.f.fixture.snapshot())


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

    def test_menu_installs_then_generates_same_target_followup_plan(self):
        before = self.protected()
        status, report, output = self.menu('4\n1\n1\n')
        self.assertEqual(status, 2)
        self.assertEqual(report['mode'], 'static-preparation-tool-installed', report)
        self.assertNotIn('error', report)
        followup = report['followup_plan']
        self.assertEqual(followup['installation_plan']['action'], 'reuse-verified-tree')
        self.assertTrue(followup['probe_registration']['prefix_absent'])
        self.assertIn('execution-not-exposed', followup['blockers'])
        self.assertNotIn('payload-provenance-unreviewed', followup['blockers'])
        self.assertIn('runtime-equivalence-unverified', followup['blockers'])
        self.assertFalse(report['preparation_complete'])
        self.assertEqual(before, self.protected())
        self.assertIn('まだ起動しません', output)
        _, again, _ = self.menu('4\n1\n')
        self.assertEqual(again['mode'], 'static-matching-tool-observed')
        self.assertEqual(len(again['writes']), 1)


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

    def test_nonprivate_parent_error_is_saved_with_specific_reason(self):
        tools = self.f.steam / 'compatibilitytools.d'
        tools.mkdir()
        tools.chmod(0o755)
        _, report, output = self.menu('4\n1\n')
        self.assertEqual(report['mode'], 'static-placement-stopped')
        self.assertEqual(report['error']['reason'], 'tool-parent-not-owned-private-0700')
        self.assertFalse(report['published_tree_or_staging_may_exist'])
        self.assertEqual(len(report['writes']), 1)
        self.assertIn('tool-parent-not-owned-private-0700', output)
        self.assertEqual(tools.stat().st_mode & 0o777, 0o755)

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


if __name__ == '__main__':
    unittest.main()
