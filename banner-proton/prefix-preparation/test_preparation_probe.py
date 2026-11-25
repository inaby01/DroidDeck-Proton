#!/usr/bin/env python3
"""Fresh-registration material with synthetic PE bytes; no Windows execution."""

import hashlib
import io
import json
import os
import runpy
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / "test_preparation_payload.py"))
import preparation_probe as probe
import preparation_selection as selection
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
        return probe.plan_probe_material(self.f.archive, self.f.sha, FIX["ROOT"], self.f.added,
            self.f.steam, self.base, **kwargs)

    def create(self, plan=None):
        plan = self.plan() if plan is None else plan
        with PrivateStore(self.store_root, create=True) as store, \
             store.locked(hashlib.sha256(plan.record["destination"].encode()).hexdigest()):
            result = probe.create_probe_material(plan, lambda: self.plan(probe_id=plan.record["probe_id"]), store)
        return plan, result

    def register(self, plan, key=12345):
        data = json.loads(self.f.added.read_bytes())
        data.append({"appid": key, "exe": str(Path(plan.record["destination"]) / probe.EXE), "name": "Test registration"})
        self.f.write_json(self.f.added, data)
        return Path(plan.record["destination"]) / probe.EXE

    def verify(self, exe, key="12345"):
        return probe.verify_probe_registration(exe, key, self.f.added, self.f.steam, self.store_root)

    def test_preview_no_write_no_execution_no_full_extraction(self):
        before = self.f.snapshot()
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")), \
             patch("tarfile.TarFile.extractall", side_effect=AssertionError("no extraction")):
            plan = self.plan()
        self.assertEqual(before, self.f.snapshot())
        self.assertEqual(plan.raw, self.data)
        self.assertEqual(plan.summary()["writes"], [])
        self.assertNotIn("raw", plan.summary())
        self.assertEqual(plan.summary()["planned_files"], [probe.EXE, probe.MARKER])

    def test_create_only_new_material_and_private_receipt(self):
        old_exe = self.f.exe.read_bytes()
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")):
            plan, result = self.create()
        directory = Path(plan.record["destination"])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), sorted([probe.EXE, probe.MARKER]))
        self.assertEqual((directory / probe.EXE).read_bytes(), self.data)
        self.assertEqual(self.f.exe.read_bytes(), old_exe)
        self.assertFalse(result["prefix_created"])
        self.assertFalse(result["registration_written"])
        self.assertFalse(result["exe_executed"])
        with PrivateStore(self.store_root) as store:
            receipt, _ = store.read_record("probe-runs", plan.record["probe_id"] + ".json")
        self.assertEqual(receipt["status"], "probe-ready")
        self.assertEqual((directory / probe.EXE).stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.f.steam / "steamapps/compatdata").exists())

    def test_existing_destination_never_reused_or_replaced(self):
        plan, _ = self.create()
        before = self.f.snapshot()
        with self.assertRaises(Invalid):
            self.plan(probe_id=plan.record["probe_id"])
        self.assertEqual(before, self.f.snapshot())

    def test_requires_matching_lock_and_refresh(self):
        plan = self.plan()
        with PrivateStore(self.store_root, create=True) as store:
            with self.assertRaises(Invalid):
                probe.create_probe_material(plan, lambda: plan, store)
            with store.locked(hashlib.sha256(plan.record["destination"].encode()).hexdigest()), self.assertRaises(Invalid):
                probe.create_probe_material(plan, self.plan, store)
        self.assertFalse(Path(plan.record["destination"]).exists())

    def test_registration_change_before_create_refused(self):
        plan = self.plan()
        self.f.write_json(self.f.added, [])
        with self.assertRaises(Invalid):
            self.create(plan)
        self.assertFalse(Path(plan.record["destination"]).exists())

    def test_archive_changed_before_create_refused(self):
        plan = self.plan()
        self.f.make_archive(self.entries[:-1] + [(probe.MEMBER, "file", self.data + b"changed", 0o444)])
        with self.assertRaises(Invalid):
            self.create(plan)
        self.assertFalse(Path(plan.record["destination"]).exists())

    def test_member_must_be_regular_bounded_x86_pe(self):
        cases = [(probe.MEMBER, "symlink", "../../../proton", 0o777),
                 (probe.MEMBER, "file", b"not PE", 0o444),
                 (probe.MEMBER, "file", FIX["FIXTURES"]["pe"](0x8664, 0x20B), 0o444),
                 (probe.MEMBER, "file", self.data + b"x" * probe.MAX_PROBE, 0o444)]
        for entry in cases:
            with self.subTest(kind=entry[1], size=len(entry[2])):
                self.f.make_archive(self.entries[:-1] + [entry])
                with self.assertRaises(Invalid):
                    self.plan()
        self.assertEqual(list(self.base.iterdir()), [])

    def test_capture_above_metadata_limit_without_relaxing_general_reader(self):
        self.data += b"x" * (1024**2 + 8192 - len(self.data))
        self.f.make_archive(self.entries[:-1] + [(probe.MEMBER, "file", self.data, 0o444)])
        self.assertEqual(len(self.plan().raw), 1024**2 + 8192)

    def test_symlink_base_rejected(self):
        alias = self.f.root / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        self.base = alias
        with self.assertRaises(Invalid):
            self.plan()

    def test_partial_creation_preserved_and_receipt_not_ready(self):
        plan = self.plan()
        actual = probe.load_json
        def fail_marker(path):
            if Path(path).name == probe.MARKER:
                raise OSError("synthetic failed post-check")
            return actual(path)
        with patch.object(probe, "load_json", side_effect=fail_marker), self.assertRaises(OSError):
            self.create(plan)
        self.assertTrue((Path(plan.record["destination"]) / probe.EXE).exists())
        with PrivateStore(self.store_root) as store:
            record, _ = store.read_record("probe-runs", plan.record["probe_id"] + ".json")
        self.assertEqual(record["status"], "probe-failed")
        self.assertEqual(record["creation_failure"], {"stage": "verify-marker", "kind": "os-error", "errno": None})
        exe = self.register(plan)
        with self.assertRaises(Invalid):
            self.verify(exe)

    def test_invalid_creator_postcheck_records_fixed_stage_without_exception_text(self):
        plan = self.plan()
        actual = probe.exe_identity
        def fail_postcheck(path):
            if Path(path).name == probe.EXE:
                raise Invalid('PRIVATE_CREATION_FAILURE_SENTINEL')
            return actual(path)
        with patch.object(probe, 'exe_identity', side_effect=fail_postcheck), self.assertRaises(Invalid) as caught:
            self.create(plan)
        self.assertEqual(caught.exception.preparation_check, 'probe-create-verify-exe')
        with PrivateStore(self.store_root) as store:
            record, _ = store.read_record('probe-runs', plan.record['probe_id'] + '.json')
        probe._record_valid(record)
        self.assertEqual(record['creation_failure']['stage'], 'verify-exe')
        self.assertEqual(record['creation_failure']['kind'], 'invalid')
        self.assertNotIn('PRIVATE_CREATION_FAILURE_SENTINEL', json.dumps(record))

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


class ProbeWorkflowTests(unittest.TestCase):
    def setUp(self):
        fixture = runpy.run_path(str(HERE / "test_preparation_selection.py"))
        self.f = fixture["SelectionTests"]()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.home = self.f.home
        (self.home / "Games").mkdir()
        source = self.f.fixture.source
        payload = FIX["PayloadTests"]()
        self.addCleanup(payload.doCleanups)
        payload.setUp()
        data = FIX["FIXTURES"]["pe"]()
        payload.make_archive(FIX["MEMBERS"] + [("files/lib", "directory", None, 0o755),
            ("files/lib/wine", "directory", None, 0o755), ("files/lib/wine/i386-windows", "directory", None, 0o755),
            (probe.MEMBER, "file", data, 0o444)])
        # Material creation needs the exact root/name and PE; not the installed tool fixture.
        self.config = {**self.f.config, "probe_material": True}
        with tarfile.open(source.archive, 'w:gz') as package, tarfile.open(payload.archive, 'r:gz') as original:
            for member in original:
                data = original.extractfile(member) if member.isfile() else None
                member.pax_headers = {}
                member.name = member.name.replace(FIX["ROOT"], self.config["payload"]["root"], 1)
                package.addfile(member, data)
        self.config["payload"]["sha512"] = hashlib.sha512(source.archive.read_bytes()).hexdigest()

    def run_workflow(self, text):
        output = io.StringIO()
        code, name = probe.interactive_workflow(self.f.directory, self.f.renderer, self.config,
            input_stream=io.StringIO(text), output_stream=output, environment=self.f.environment,
            steam=self.f.steam, settings=self.f.settings, home=self.home, runtime_root=self.f.fixture.context.root)
        return code, name, output.getvalue()

    def test_cancel_menu_and_preview_write_nothing(self):
        before = self.f.fixture.snapshot()
        for answer in ('q\n', '2\nq\n', '2\n', '2\nyes\n'):
            code, name, _ = self.run_workflow(answer)
            self.assertEqual((code, name), (0, None))
        self.assertEqual(before, self.f.fixture.snapshot())

    def test_explicit_creation_and_saved_write_scope(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            code, name, output = self.run_workflow('2\n1\n')
        self.assertEqual(code, 2)
        report = json.loads((self.f.directory / name).read_bytes())
        self.assertEqual(report['mode'], 'probe-material-created')
        self.assertEqual(len(report['writes']), 3)
        self.assertFalse(report['exe_executed'])
        self.assertIn('追加後も起動せず', output)
        self.assertEqual(list((self.home / 'Games').iterdir()), [])
        self.assertEqual(Path(report['destination']).parent, self.f.directory)
        self.assertEqual(self.f.directory / report['selection_hint']['relative_exe'], Path(report['exe']))
        self.assertIn('prepare.sh を置いたフォルダー', output)
        # Adding the probe is an Android action; this script has not added it.
        self.assertEqual(len(json.loads(self.f.fixture.game.added.read_bytes())), 1)

    def test_old_private_probe_is_preserved_without_moving_or_reusing(self):
        old = self.home / 'Games' / 'DroidDeck Prefix Test-previous'
        old.mkdir()
        old_exe = old / probe.EXE
        old_exe.write_bytes(b'PRIVATE_OLD_PROBE')
        before = old_exe.stat()
        _, name, _ = self.run_workflow('2\n1\n')
        report = json.loads((self.f.directory / name).read_bytes())
        self.assertEqual(Path(report['destination']).parent, self.f.directory)
        self.assertEqual(old_exe.read_bytes(), b'PRIVATE_OLD_PROBE')
        self.assertEqual(old_exe.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(list(old.iterdir()), [old_exe])

    def test_creation_does_not_require_home_games_and_reports_shared_path(self):
        (self.home / 'Games').rmdir()
        self.f.directory.chmod(0o770)
        _, name, _ = self.run_workflow('2\n1\n')
        path = Path(name)
        if not path.is_absolute():
            path = self.f.directory / name
        report = json.loads(path.read_bytes())
        self.assertEqual(report['mode'], 'probe-material-created')
        self.assertEqual(Path(report['exe']).parent.parent, self.f.directory)
        self.assertFalse((self.home / 'Games').exists())
        self.assertTrue(Path(report['exe']).is_file())
        self.assertFalse(report['exe_executed'])

    def test_registered_probe_connects_to_plan_without_unlocking_execution(self):
        _, name, _ = self.run_workflow('2\n1\n')
        created = json.loads((self.f.directory / name).read_bytes())
        data = json.loads(self.f.fixture.game.added.read_bytes())
        data.append({"appid": 12345, "exe": created["exe"], "name": "Fresh probe"})
        self.f.fixture.game.write_json(self.f.fixture.game.added, data)
        self.f.fixture.source.archive.rename(self.f.fixture.source.archive.with_suffix('.unavailable'))
        source, digest, games = selection.registration_catalog(self.f.environment)
        before = self.f.fixture.snapshot()
        report = selection.selected_plan(self.f.directory, self.config, '12345', source, digest, games,
            self.f.steam, self.f.settings, self.home, self.f.renderer, self.f.environment,
            runtime_root=self.f.fixture.context.root)
        self.assertTrue(report['probe_registration']['prefix_absent'])
        self.assertNotIn('new-test-registration-not-confirmed', report['blockers'])
        self.assertIn('registration-probe-only-not-game-profile', report['blockers'])
        self.assertIn('execution-not-exposed', report['blockers'])
        self.assertFalse(report['preparation_complete'])
        self.assertEqual(report['writes'], [])
        self.assertEqual(before, self.f.fixture.snapshot())

    def test_saved_rejection_includes_failed_step_without_shared_marker_data(self):
        _, name, _ = self.run_workflow('2\n1\n')
        created = json.loads((self.f.directory / name).read_bytes())
        data = json.loads(self.f.fixture.game.added.read_bytes())
        data.append({"appid": 12345, "exe": created["exe"], "name": "Fresh probe"})
        self.f.fixture.game.write_json(self.f.fixture.game.added, data)
        marker = Path(created['exe']).parent / probe.MARKER
        content = json.loads(marker.read_bytes())
        content['PRIVATE_MARKER_SENTINEL'] = 'DO_NOT_REPORT_MARKER_DATA'
        marker.write_text(json.dumps(content))
        before = self.f.fixture.game.snapshot()
        _, name, output = self.run_workflow('1\n2\n')
        report = json.loads((self.f.directory / name).read_bytes())
        self.assertEqual(report['status'], 'input-rejected')
        self.assertEqual(report['check'], 'probe-marker-receipt-match')
        self.assertEqual(report['probe_registration_diagnostic']['checks'][-1]['check'], report['check'])
        self.assertNotIn('PRIVATE_MARKER_SENTINEL', json.dumps(report) + output)
        self.assertNotIn('DO_NOT_REPORT_MARKER_DATA', json.dumps(report) + output)
        self.assertEqual(report['writes'], [{'scope': 'report-only', 'filename': name}])
        self.assertEqual(before, self.f.fixture.game.snapshot())

    def test_not_ready_saved_report_contains_read_only_material_observations(self):
        _, name, _ = self.run_workflow('2\n1\n')
        created = json.loads((self.f.directory / name).read_bytes())
        data = json.loads(self.f.fixture.game.added.read_bytes())
        data.append({"appid": 12345, "exe": created["exe"], "name": "Fresh probe"})
        self.f.fixture.game.write_json(self.f.fixture.game.added, data)
        root = self.home / '.local/state/droiddeck-prefix-preparation/probe-store'
        key = hashlib.sha256(created['destination'].encode()).hexdigest()
        with PrivateStore(root) as store, store.locked(key):
            filename = created['probe_id'] + '.json'
            record, digest = store.read_record('probe-runs', filename)
            record['status'] = 'probe-failed'
            store.write_record('probe-runs', filename, record, digest)
        _, name, _ = self.run_workflow('1\n2\n')
        report = json.loads((self.f.directory / name).read_bytes())
        self.assertEqual(report['check'], 'probe-private-receipt-ready')
        self.assertEqual(report['incomplete_probe_material']['receipt_state'], 'probe-failed')
        self.assertFalse(report['incomplete_probe_material']['material_modified'])
        self.assertEqual(report['writes'], [{'scope': 'report-only', 'filename': name}])
        self.assertNotIn('baseline_ids', json.dumps(report))

    def test_standalone_script_menu_cancels_without_writes(self):
        import subprocess
        script = self.f.directory / 'prepare.sh'
        script.write_text(selection.selection_script(self.config))
        before = self.f.fixture.snapshot()
        result = subprocess.run(['bash', str(script)], input='q\n', text=True, capture_output=True,
                                env={**os.environ, 'HOME': str(self.home)}, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('新規登録用', result.stdout)
        self.assertEqual(before, self.f.fixture.snapshot())


if __name__ == '__main__':
    unittest.main()
