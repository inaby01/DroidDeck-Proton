#!/usr/bin/env python3
"""Fresh-registration material with synthetic PE bytes; no Windows execution."""

import hashlib
import json
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / "test_preparation_payload.py"))
import fixture_legacy_builders as legacy
import preparation_probe as probe
from preparation_common import Invalid
from preparation_store import PrivateStore


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.f = FIX["PayloadTests"]()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.base = self.f.root / "probe-base"
        self.base.mkdir()
        self.store_root = self.f.root / "probe-store"
        self.data = FIX["FIXTURES"]["pe"]()
        self.entries = FIX["MEMBERS"] + [("files/lib", "directory", None, 0o755),
            ("files/lib/wine", "directory", None, 0o755), ("files/lib/wine/i386-windows", "directory", None, 0o755),
            (probe.MEMBER, "file", self.data, 0o444)]
        self.f.make_archive(self.entries)

    def plan(self, **kwargs):
        return legacy.plan_probe_material(self.f.archive, self.f.sha, FIX["ROOT"], self.f.added,
            self.f.steam, self.base, **kwargs)

    def create(self, plan=None):
        plan = self.plan() if plan is None else plan
        with PrivateStore(self.store_root, create=True) as store, \
             store.locked(hashlib.sha256(plan.record["destination"].encode()).hexdigest()):
            result = legacy.create_probe_material(plan, lambda: self.plan(probe_id=plan.record["probe_id"]), store)
        return plan, result

    def register(self, plan, key=12345):
        data = json.loads(self.f.added.read_bytes())
        data.append({"appid": key, "exe": str(Path(plan.record["destination"]) / probe.EXE), "name": "Test registration"})
        self.f.write_json(self.f.added, data)
        return Path(plan.record["destination"]) / probe.EXE

    def verify(self, exe, key="12345"):
        return probe.verify_probe_registration(exe, key, self.f.added, self.f.steam, self.store_root)

    def test_new_registration_verified_read_only(self):
        plan, _ = self.create()
        exe = self.register(plan)
        before = self.f.snapshot()
        result = self.verify(exe)
        self.assertTrue(result["new_id_relative_to_baseline"])
        self.assertTrue(result["prefix_absent"])
        self.assertFalse(result["preparation_complete"])
        self.assertEqual(before, self.f.snapshot())

    def test_baseline_id_cannot_be_reused(self):
        plan, _ = self.create()
        data = json.loads(self.f.added.read_bytes())
        data[0]["exe"] = str(Path(plan.record["destination"]) / probe.EXE)
        self.f.write_json(self.f.added, data)
        with self.assertRaises(Invalid):
            self.verify(Path(data[0]["exe"]), "4294967295")

    def test_stale_unrelated_registration_does_not_prevent_verification(self):
        plan, _ = self.create()
        exe = self.register(plan)
        self.f.exe.unlink()
        self.assertTrue(self.verify(exe)["prefix_absent"])

    def test_existing_prefix_or_noncanonical_alias_preserved(self):
        plan, _ = self.create()
        exe = self.register(plan, 4294967294)
        base = self.f.steam / "steamapps/compatdata"
        base.mkdir(parents=True)
        for name in ("4294967294", "-2", "04294967294"):
            prefix = base / name
            prefix.mkdir()
            with self.assertRaises(Invalid):
                self.verify(exe, "4294967294")
            self.assertTrue(prefix.is_dir())
            prefix.rmdir()  # Disposable test fixture only.

    def test_marker_receipt_and_bytes_all_required(self):
        plan, _ = self.create()
        exe = self.register(plan)
        exe.write_bytes(self.data + b"tamper")
        with self.assertRaises(Invalid):
            self.verify(exe)
        exe.write_bytes(self.data)
        marker = exe.parent / probe.MARKER
        marker.write_text('{}')
        with self.assertRaises(Invalid):
            self.verify(exe)

    def test_duplicate_registered_exe_refused(self):
        plan, _ = self.create()
        exe = self.register(plan)
        self.register(plan, 12346)
        with self.assertRaises(Invalid):
            self.verify(exe)

    def test_fixed_diagnostic_distinguishes_context_without_raw_paths(self):
        plan, _ = self.create()
        exe = self.register(plan)
        other_steam = self.f.root / 'PRIVATE_CONTEXT_SENTINEL'
        other_steam.mkdir()
        with self.assertRaises(Invalid) as caught:
            probe.verify_probe_registration(exe, '12345', self.f.added, other_steam, self.store_root)
        self.assertEqual(caught.exception.preparation_check, 'probe-steam-context')
        diagnostic = caught.exception.probe_registration_diagnostic
        self.assertEqual(diagnostic['checks'][-1], {'check': 'probe-steam-context', 'result': 'failed'})
        self.assertNotIn('PRIVATE_CONTEXT_SENTINEL', json.dumps(diagnostic))
        self.assertTrue(diagnostic['read_only'])
        self.assertTrue(all(x['result'] == 'passed' for x in diagnostic['checks'][:-1]))

    def test_samefile_failure_has_specific_check_and_preserves_files(self):
        plan, _ = self.create()
        exe = self.register(plan)
        before = self.f.snapshot()
        with patch.object(probe.os.path, 'samefile', return_value=False), self.assertRaises(Invalid) as caught:
            self.verify(exe)
        self.assertEqual(caught.exception.preparation_check, 'probe-exe-path-identity')
        self.assertEqual(before, self.f.snapshot())

    def test_missing_marker_has_read_step_not_generic_rejection(self):
        plan, _ = self.create()
        exe = self.register(plan)
        (exe.parent / probe.MARKER).unlink()
        with self.assertRaises(OSError) as caught:
            self.verify(exe)
        self.assertEqual(caught.exception.preparation_check, 'probe-marker-read')
        self.assertEqual(caught.exception.probe_registration_diagnostic['checks'][-1]['result'], 'failed')

    def test_previous_version_receipt_remains_readable_without_recreation(self):
        plan, _ = self.create()
        with PrivateStore(self.store_root) as store, \
             store.locked(hashlib.sha256(plan.record['destination'].encode()).hexdigest()):
            name = plan.record['probe_id'] + '.json'
            record, digest = store.read_record('probe-runs', name)
            record['tool_version'] = '0.14.1'
            store.write_record('probe-runs', name, record, digest)
        exe = self.register(plan)
        before = self.f.snapshot()
        self.assertTrue(self.verify(exe)['prefix_absent'])
        self.assertEqual(before, self.f.snapshot())

    def incomplete(self):
        plan, _ = self.create()
        exe = self.register(plan)
        self.set_receipt_state(plan, 'probe-failed')
        return plan, exe

    def set_receipt_state(self, plan, state):
        with PrivateStore(self.store_root) as store, \
             store.locked(hashlib.sha256(plan.record['destination'].encode()).hexdigest()):
            name = plan.record['probe_id'] + '.json'
            record, digest = store.read_record('probe-runs', name)
            record['status'] = state
            store.write_record('probe-runs', name, record, digest)

    def test_incomplete_observation_never_writes_finalizes_or_executes(self):
        plan, exe = self.incomplete()
        for state in ('creating', 'probe-failed'):
            self.set_receipt_state(plan, state)
            before = self.f.snapshot()
            with patch.object(PrivateStore, 'write_record', side_effect=AssertionError('no writes')), \
                 patch('subprocess.Popen', side_effect=AssertionError('no process')), \
                 patch.object(probe.os, 'fsync', side_effect=AssertionError('no fsync')), \
                 self.assertRaises(Invalid) as caught:
                self.verify(exe)
            self.assertEqual(caught.exception.preparation_check, 'probe-private-receipt-ready')
            diagnostic = caught.exception.incomplete_probe_material
            self.assertEqual(diagnostic['receipt_state'], state)
            self.assertFalse(diagnostic['receipt_finalized'])
            checks = {x['check']: x for x in diagnostic['checks']}
            self.assertEqual(checks['created-exe-matches-receipt']['result'], 'passed')
            self.assertEqual(checks['created-directory-guards-now']['result'], 'observed')
            self.assertTrue(checks['prefix-current-state']['metadata']['all_numeric_aliases_absent'])
            self.assertEqual(before, self.f.snapshot())

    def test_incomplete_observation_collects_multiple_mismatches_without_raw_data(self):
        _, exe = self.incomplete()
        exe.write_bytes(self.data + b'PRIVATE_EXE_SENTINEL')
        marker = exe.parent / probe.MARKER
        document = json.loads(marker.read_bytes())
        document['PRIVATE_MARKER_SENTINEL'] = 'PRIVATE_VALUE_SENTINEL'
        marker.write_text(json.dumps(document))
        before = self.f.snapshot()
        with self.assertRaises(Invalid) as caught:
            self.verify(exe)
        diagnostic = caught.exception.incomplete_probe_material
        checks = {x['check']: x for x in diagnostic['checks']}
        self.assertEqual(checks['created-exe-matches-receipt']['result'], 'mismatch')
        self.assertEqual(checks['created-marker-matches-receipt']['result'], 'mismatch')
        self.assertIn('private-receipt-stable', checks)
        for secret in ('PRIVATE_EXE_SENTINEL', 'PRIVATE_MARKER_SENTINEL', 'PRIVATE_VALUE_SENTINEL', str(self.f.root)):
            self.assertNotIn(secret, json.dumps(diagnostic))
        self.assertEqual(before, self.f.snapshot())

    def test_incomplete_observation_continues_when_created_path_is_missing(self):
        _, exe = self.incomplete()
        other = self.base / 'registered-copy'
        other.mkdir()
        copied = other / probe.EXE
        copied.write_bytes(exe.read_bytes())
        (other / probe.MARKER).write_bytes((exe.parent / probe.MARKER).read_bytes())
        exe.unlink()
        data = json.loads(self.f.added.read_bytes())
        data[-1]['exe'] = str(copied)
        self.f.write_json(self.f.added, data)
        before = self.f.snapshot()
        with self.assertRaises(Invalid) as caught:
            self.verify(copied)
        checks = {x['check']: x for x in caught.exception.incomplete_probe_material['checks']}
        self.assertEqual(checks['created-exe-matches-receipt']['result'], 'unavailable')
        self.assertEqual(checks['registered-exe-matches-receipt']['result'], 'passed')
        self.assertEqual(checks['private-receipt-stable']['result'], 'observed')
        self.assertEqual(before, self.f.snapshot())

    def test_incomplete_observation_reports_existing_prefix_without_reading_contents(self):
        _, exe = self.incomplete()
        prefix = self.f.steam / 'steamapps/compatdata/12345'
        prefix.mkdir(parents=True)
        (prefix / 'private.reg').write_text('PRIVATE_PREFIX_SENTINEL')
        before = self.f.snapshot()
        with self.assertRaises(Invalid) as caught:
            self.verify(exe)
        diagnostic = caught.exception.incomplete_probe_material
        checks = {x['check']: x for x in diagnostic['checks']}
        self.assertTrue(checks['prefix-current-state']['metadata']['canonical_exists'])
        self.assertFalse(checks['prefix-current-state']['metadata']['all_numeric_aliases_absent'])
        self.assertNotIn('PRIVATE_PREFIX_SENTINEL', json.dumps(diagnostic))
        self.assertEqual(before, self.f.snapshot())

    def test_probe_receipt_cannot_be_replaced_by_shared_marker(self):
        plan, _ = self.create()
        exe = self.register(plan)
        with self.assertRaises(OSError):
            probe.verify_probe_registration(exe, "12345", self.f.added, self.f.steam, self.f.root / "missing-store")


if __name__ == '__main__':
    unittest.main()
