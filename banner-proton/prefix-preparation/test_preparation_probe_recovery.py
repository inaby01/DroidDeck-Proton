#!/usr/bin/env python3
"""Explicit receipt recovery from synthetic material; no Wine or real device."""

import copy
import hashlib
import io
import json
import runpy
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / 'test_preparation_probe.py'))
import preparation_probe as probe
import preparation_probe_recovery as recovery
import preparation_selection as selection
from preparation_common import Invalid
from preparation_store import PrivateStore


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = FIX['ProbeTests']()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.created, self.exe = self.f.incomplete()
        self.store_root = self.f.store_root
        self.key = hashlib.sha256(self.created.record['destination'].encode()).hexdigest()
        self.filename = self.created.record['probe_id'] + '.json'

    def plan(self):
        return recovery.plan_probe_recovery(self.f.f.archive, self.f.f.sha, FIX['FIX']['ROOT'], self.exe,
            '12345', self.f.f.added, self.f.f.steam, self.store_root)

    def apply(self, plan=None):
        plan = self.plan() if plan is None else plan
        with PrivateStore(self.store_root) as store, store.locked(self.key):
            return recovery.apply_probe_recovery(plan, self.plan, store)

    def receipt(self):
        with PrivateStore(self.store_root) as store:
            return store.read_record('probe-runs', self.filename)

    def test_plan_is_read_only_and_has_no_raw_receipt_or_execution(self):
        before = self.f.f.snapshot()
        with patch.object(PrivateStore, 'write_record', side_effect=AssertionError('no writes')), \
             patch('subprocess.Popen', side_effect=AssertionError('no process')):
            plan = self.plan()
        self.assertEqual(before, self.f.f.snapshot())
        self.assertEqual(plan.summary()['writes'], [])
        self.assertTrue(plan.summary()['full_archive_verified'])
        self.assertNotIn('baseline_ids', json.dumps(plan.summary()))
        self.assertEqual(plan.summary()['previous_state'], 'probe-failed')

    def test_recovery_preserves_original_and_changes_only_private_records(self):
        original, digest = self.receipt()
        directory = Path(original['destination'])
        contents = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in directory.iterdir()}
        old_games = self.f.f.added.read_bytes()
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            result = self.apply()
        current, _ = self.receipt()
        self.assertEqual(current['status'], 'probe-ready')
        evidence = current['revalidation']
        self.assertEqual(evidence['previous_state'], 'probe-failed')
        self.assertEqual(evidence['previous_receipt_sha256'], digest)
        with PrivateStore(self.store_root) as store:
            previous, previous_digest = store.read_record('probe-history', evidence['history_record'])
        self.assertEqual((previous, previous_digest), (original, digest))
        self.assertEqual(contents, {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in directory.iterdir()})
        self.assertEqual(self.f.f.added.read_bytes(), old_games)
        self.assertTrue(result['probe_registration']['prefix_absent'])
        self.assertFalse(result['prefix_created'])
        self.assertFalse(result['exe_executed'])
        self.assertFalse(result['registration_written'])
        self.assertFalse(result['preparation_complete'])
        self.assertEqual(len(result['writes']), 2)
        self.assertFalse((self.f.f.steam / 'steamapps/compatdata').exists())

    def test_creating_legacy_receipt_revalidates_and_keeps_creation_version(self):
        self.f.set_receipt_state(self.created, 'creating')
        with PrivateStore(self.store_root) as store, store.locked(self.key):
            record, digest = store.read_record('probe-runs', self.filename)
            record['tool_version'] = '0.14.1'
            store.write_record('probe-runs', self.filename, record, digest)
        self.apply()
        current, _ = self.receipt()
        self.assertEqual(current['tool_version'], '0.14.1')
        self.assertEqual(current['revalidation']['previous_state'], 'creating')

    def test_fixed_creation_failure_is_retained_after_revalidation(self):
        with PrivateStore(self.store_root) as store, store.locked(self.key):
            record, digest = store.read_record('probe-runs', self.filename)
            record['creation_failure'] = {'stage': 'verify-exe', 'kind': 'invalid', 'errno': None}
            store.write_record('probe-runs', self.filename, record, digest)
        self.apply()
        current, _ = self.receipt()
        self.assertEqual(current['creation_failure'], record['creation_failure'])
        self.assertTrue(self.f.verify(self.exe)['prefix_absent'])

    def test_changed_archive_is_not_bypassed_by_existing_matching_exe(self):
        plan = self.plan()
        self.f.f.archive.write_bytes(self.f.f.archive.read_bytes() + b'tamper')
        original = self.receipt()
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertEqual(self.receipt(), original)
        self.assertFalse((self.store_root / 'probe-history').exists())

    def test_changed_member_or_marker_refuses_plan(self):
        original = self.exe.read_bytes()
        self.exe.write_bytes(original + b'changed')
        with self.assertRaises(Invalid):
            self.plan()
        self.exe.write_bytes(original)
        marker = self.exe.parent / probe.MARKER
        content = json.loads(marker.read_bytes())
        content['additional'] = 'PRIVATE_SENTINEL'
        marker.write_text(json.dumps(content))
        with self.assertRaises(Invalid):
            self.plan()
        self.assertFalse((self.store_root / 'probe-history').exists())

    def test_existing_prefix_and_alias_refuse_recovery(self):
        base = self.f.f.steam / 'steamapps/compatdata'
        base.mkdir(parents=True)
        for name in ('12345', '00012345'):
            prefix = base / name
            prefix.mkdir()
            with self.assertRaises(Invalid):
                self.plan()
            self.assertTrue(prefix.is_dir())
            prefix.rmdir()
        self.assertFalse((self.store_root / 'probe-history').exists())

    def test_no_private_receipt_or_wrong_marker_cannot_be_adopted(self):
        path = self.store_root / 'probe-runs' / self.filename
        path.unlink()
        with self.assertRaises(Invalid):
            self.plan()
        self.assertTrue(self.exe.exists())

    def test_requires_matching_global_and_target_locks(self):
        plan = self.plan()
        with PrivateStore(self.store_root) as store:
            with self.assertRaises(Invalid):
                recovery.apply_probe_recovery(plan, self.plan, store)
            with store.locked('0' * 64), self.assertRaises(Invalid):
                recovery.apply_probe_recovery(plan, self.plan, store)
        self.assertFalse((self.store_root / 'probe-history').exists())

    def test_receipt_change_after_preview_refuses_update(self):
        plan = self.plan()
        self.f.set_receipt_state(self.created, 'creating')
        before = self.receipt()
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertEqual(self.receipt(), before)

    def test_mutated_plan_is_not_authorization(self):
        plan = self.plan()
        plan.pins.clear()
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertFalse((self.store_root / 'probe-history').exists())

    def test_failure_after_history_before_update_preserves_old_then_retry_reuses_backup(self):
        plan = self.plan()
        original = self.receipt()
        actual = PrivateStore.write_record
        def fail_update(store, directory, *args, **kwargs):
            if directory == 'probe-runs':
                raise OSError('synthetic interrupted update')
            return actual(store, directory, *args, **kwargs)
        with patch.object(PrivateStore, 'write_record', fail_update), self.assertRaises(OSError):
            self.apply(plan)
        self.assertEqual(self.receipt(), original)
        history = list((self.store_root / 'probe-history').glob('*.json'))
        self.assertEqual(len(history), 1)
        old_backup = history[0].read_bytes(), history[0].stat().st_mtime_ns
        result = self.apply(plan)
        self.assertFalse(result['history_created'])
        self.assertEqual(len(result['writes']), 1)
        self.assertEqual(old_backup, (history[0].read_bytes(), history[0].stat().st_mtime_ns))

    def test_input_change_during_atomic_update_callback_is_refused(self):
        plan = self.plan()
        actual = PrivateStore.write_record
        original = self.receipt()
        def mutate(store, directory, *args, **kwargs):
            if directory == 'probe-runs':
                self.exe.write_bytes(self.exe.read_bytes() + b'late-change')
            return actual(store, directory, *args, **kwargs)
        with patch.object(PrivateStore, 'write_record', mutate), self.assertRaises(Invalid):
            self.apply(plan)
        self.assertEqual(self.receipt(), original)
        self.assertTrue((self.store_root / 'probe-history').is_dir())

    def test_conflicting_backup_is_not_overwritten(self):
        plan = self.plan()
        name = recovery._history_name(plan)
        with PrivateStore(self.store_root) as store, store.locked(self.key):
            store.write_record('probe-history', name, {'unrecognized': True})
        backup = self.store_root / 'probe-history' / name
        raw = backup.read_bytes()
        original = self.receipt()
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertEqual(backup.read_bytes(), raw)
        self.assertEqual(self.receipt(), original)

    def test_already_revalidated_is_read_only_and_does_not_rewrite_history(self):
        self.apply()
        plan = self.plan()
        before = self.f.f.snapshot()
        result = self.apply(plan)
        self.assertEqual(result['mode'], 'probe-recovery-already-ready')
        self.assertEqual(result['writes'], [])
        self.assertEqual(before, self.f.f.snapshot())

    def test_missing_or_modified_history_blocks_normal_verification(self):
        self.apply()
        current, _ = self.receipt()
        path = self.store_root / 'probe-history' / current['revalidation']['history_record']
        path.unlink()
        with self.assertRaises(Invalid):
            self.f.verify(self.exe)

    def test_revalidation_does_not_authorize_different_new_registration_id(self):
        self.apply()
        games = json.loads(self.f.f.added.read_bytes())
        games[-1]['appid'] = 54321
        self.f.f.write_json(self.f.f.added, games)
        with self.assertRaises(Invalid):
            self.f.verify(self.exe, '54321')

    def test_revalidation_evidence_schema_is_strict(self):
        self.apply()
        record, _ = self.receipt()
        for key, value in [('schema_version', True), ('previous_state', 'probe-ready'), ('previous_receipt_sha256', 'invalid'),
                           ('archive_sha512', '0' * 128), ('history_record', '../outside.json'), ('registration_id', '4294967295')]:
            altered = copy.deepcopy(record)
            altered['revalidation'][key] = value
            with self.subTest(key=key), self.assertRaises(Invalid):
                probe._record_valid(altered)


class RecoveryWorkflowTests(unittest.TestCase):
    def setUp(self):
        fixture = runpy.run_path(str(HERE / 'test_preparation_selection.py'))
        self.f = fixture['SelectionTests']()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        source = self.f.fixture.source
        data = FIX['FIX']['FIXTURES']['pe']()
        with tarfile.open(source.archive, 'r:gz') as original:
            entries = [(copy.copy(member), original.extractfile(member).read() if member.isfile() else None) for member in original]
        root = self.f.config['payload']['root']
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
        sha = hashlib.sha512(source.archive.read_bytes()).hexdigest()
        self.config = copy.deepcopy(self.f.config)
        self.config['probe_material'] = True
        self.config['payload']['sha512'] = sha
        selection._private_report_directory(self.f.home, [])
        self.store_root = self.f.home / '.local/state/droiddeck-prefix-preparation/probe-store'
        plan = probe.plan_probe_material(source.archive, sha, root, self.f.fixture.game.added, self.f.steam, self.f.directory)
        self.key = hashlib.sha256(plan.record['destination'].encode()).hexdigest()
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.key):
            probe.create_probe_material(plan, lambda: probe.plan_probe_material(source.archive, sha, root,
                self.f.fixture.game.added, self.f.steam, self.f.directory, probe_id=plan.record['probe_id']), store)
            name = plan.record['probe_id'] + '.json'
            record, digest = store.read_record('probe-runs', name)
            record['status'] = 'probe-failed'
            store.write_record('probe-runs', name, record, digest)
        self.exe = Path(plan.record['destination']) / probe.EXE
        games = json.loads(self.f.fixture.game.added.read_bytes())
        games.append({'appid': 12345, 'exe': str(self.exe), 'name': 'Fresh probe'})
        self.f.fixture.game.write_json(self.f.fixture.game.added, games)

    def run_menu(self, text):
        output = io.StringIO()
        code, name = probe.interactive_workflow(self.f.directory, self.f.renderer, self.config,
            input_stream=io.StringIO(text), output_stream=output, environment=self.f.environment,
            steam=self.f.steam, settings=self.f.settings, home=self.f.home, runtime_root=self.f.fixture.context.root)
        report = json.loads((self.f.directory / name).read_bytes()) if name else None
        return code, report, output.getvalue()

    def test_cancel_selection_and_concrete_preview_write_nothing(self):
        before = self.f.fixture.snapshot()
        for answer in ('3\nq\n', '3\n1\nq\n', '3\n1\n', '3\n1\nyes\n'):
            code, report, _ = self.run_menu(answer)
            self.assertEqual((code, report), (0, None))
        self.assertEqual(before, self.f.fixture.snapshot())

    def test_explicit_recovery_continues_into_same_target_plan_without_another_user_round(self):
        exe_before = self.exe.read_bytes(), self.exe.stat().st_mtime_ns
        _, report, output = self.run_menu('3\n1\n1\n')
        self.assertEqual(report['mode'], 'probe-recovered', report)
        self.assertNotIn('error', report)
        self.assertTrue(report['receipt_revalidated_now'])
        self.assertFalse(report['preparation_complete'])
        followup = report['followup_plan']
        self.assertTrue(followup['probe_registration']['prefix_absent'])
        self.assertNotIn('new-test-registration-not-confirmed', followup['blockers'])
        self.assertIn('execution-not-exposed', followup['blockers'])
        self.assertEqual(len(report['writes']), 3)
        self.assertEqual((self.exe.read_bytes(), self.exe.stat().st_mtime_ns), exe_before)
        self.assertIn('私有記録を全照合の証拠付きで復帰', output)
        _, normal, _ = self.run_menu('1\n2\n')
        self.assertEqual(normal['mode'], 'selected-preparation-plan')
        self.assertEqual(normal['status'], 'blocked')
        self.assertTrue(normal['probe_registration']['new_id_relative_to_baseline'])

    def test_interrupted_acknowledgement_is_reported_and_retry_observes_ready_without_rewrite(self):
        actual = PrivateStore.write_record
        def fail_ack(store, directory, *args, **kwargs):
            result = actual(store, directory, *args, **kwargs)
            if directory == 'probe-runs':
                raise OSError('synthetic failure after atomic publication')
            return result
        with patch.object(PrivateStore, 'write_record', fail_ack):
            _, stopped, _ = self.run_menu('3\n1\n1\n')
        self.assertEqual(stopped['mode'], 'probe-recovery-stopped')
        self.assertTrue(stopped['private_receipt_may_have_changed'])
        self.assertEqual(stopped['writes'][0]['scope'], 'private-recovery-attempt-outcome-unknown')
        _, retried, _ = self.run_menu('3\n1\n')
        self.assertEqual(retried['mode'], 'probe-recovery-already-ready')
        self.assertNotIn('error', retried)
        self.assertEqual(len(retried['writes']), 1)

    def test_already_ready_has_no_confirmation_or_private_rewrite(self):
        self.run_menu('3\n1\n1\n')
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.store_root.rglob('*.json')}
        _, report, output = self.run_menu('3\n1\n')
        self.assertEqual(report['mode'], 'probe-recovery-already-ready')
        self.assertEqual(len(report['writes']), 1)
        self.assertNotIn('復帰する場合は1', output)
        self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.store_root.rglob('*.json')})


if __name__ == '__main__':
    unittest.main()
