#!/usr/bin/env python3
"""Cache, journal and lock tests using disposable files and generated PE headers."""

import copy
import hashlib
import json
import os
import runpy
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURES = runpy.run_path(str(Path(__file__).with_name("test_prepare_game.py")))
FOLDER = runpy.run_path(str(Path(__file__).with_name("test_preparation_folder_reads.py")))
ENGINE = FIXTURES["ENGINE"]
# The trusted entry point has already inserted the distribution path under -I.
import preparation_assets as assets
import preparation_store as storage

Invalid = storage.Invalid


def spec_for(data):
    return {"asset_id": "example-runtime", "revision": 1, "version": "example-1", "purpose": "synthetic-test",
            "filename": "Runtime 日本語 ; $(touch injected).exe", "format": "pe", "pe_machine": "x86",
            "expected_size": len(data), "expected_sha256": hashlib.sha256(data).hexdigest(),
            "hash_kind": "external-reference", "hash_reference": "synthetic fixture specification",
            "source_kind": "game-bundled", "source_reference": "synthetic fixture, not a real vendor assertion",
            "acquired_on": "2026-11-18", "provenance_status": "operator-reviewed", "terms_status": "personal-use-reviewed"}


class StorageTests(unittest.TestCase):
    write_json = FIXTURES["InspectionTests"].write_json
    snapshot = FIXTURES["InspectionTests"].snapshot
    report = FIXTURES["InspectionTests"].report

    def setUp(self):
        FIXTURES["InspectionTests"].setUp(self)
        self.source_root = self.root / "sources"
        self.source_root.mkdir()
        self.data = FIXTURES["pe"]()
        self.spec = spec_for(self.data)
        self.source = self.source_root / self.spec["filename"]
        self.source.write_bytes(self.data)
        self.manifest = self.root / "assets.json"
        self.write_json(self.manifest, {"schema_version": 1, "assets": [self.spec]})
        self.args.assets = self.manifest
        self.args.asset_root = self.source_root
        self.args.management_root = self.root / "private-store"
        self.args.resume_run = None
        self.store_root = self.args.management_root
        self.key = storage.target_key(self.report())

    def store(self, create=True):
        return storage.PrivateStore(self.store_root, create=create)

    def cache(self, store):
        return store.cache_asset(self.spec, self.source_root)

    def stage(self):
        return storage.stage_local(self.args, self.report)

    def run_files(self):
        return sorted((self.store_root / "runs").glob("run-*.json"))

    def test_asset_inspection_is_read_only_and_keeps_evidence_separate(self):
        before = self.snapshot()
        report = self.report()
        asset = report["assets"][0]
        self.assertEqual(asset["blockers"], [])
        self.assertEqual(asset["measured"]["sha256"], self.spec["expected_sha256"])
        self.assertEqual(asset["evidence_source"], "operator-declared")
        self.assertEqual(asset["execution"], "not-implemented")
        self.assertIn("assets-not-bound-to-executable-recipes", report["blockers"])
        self.assertEqual(report["writes"], [])
        self.assertEqual(before, self.snapshot())

    def test_missing_asset_and_unreviewed_origin_terms_hash_remain_blocked(self):
        self.source.unlink()
        spec = {**self.spec, "source_kind": "unknown", "provenance_status": "unconfirmed",
                "terms_status": "unconfirmed", "expected_sha256": None, "expected_size": None,
                "hash_kind": "local-measurement", "hash_reference": None}
        self.write_json(self.manifest, {"schema_version": 1, "assets": [spec]})
        blockers = self.report()["assets"][0]["blockers"]
        for expected in ("asset-missing", "provenance-unconfirmed", "terms-unconfirmed", "expected-hash-unknown",
                         "expected-size-unknown", "independent-hash-reference-unavailable"):
            self.assertIn(expected, blockers)
        with self.assertRaises(Invalid):
            self.stage()
        self.assertFalse(self.store_root.exists())

    def test_schema_fields_limits_and_paths_are_validated(self):
        cases = (("command", "touch injected"), ("schema_version", 99), ("format", "shell"),
                 ("expected_size", True), ("expected_size", 2**40), ("filename", "../escape"),
                 ("filename", "/absolute.exe"), ("acquired_on", "2026-02-30"), ("revision", False),
                 ("pe_machine", "host-default"), ("hash_kind", "verified"))
        for field, value in cases:
            document = {"schema_version": 1, "assets": [copy.deepcopy(self.spec)]}
            if field == "schema_version":
                document[field] = value
            else:
                document["assets"][0][field] = value
            with self.subTest(field=field), self.assertRaises(Invalid):
                assets.validate_manifest(document)
        with self.assertRaises(Invalid):
            assets.validate_manifest({"schema_version": 1, "assets": [self.spec, self.spec]})
        with self.assertRaises(Invalid):
            assets.source_path(self.source_root, {**self.spec, "filename": ".env.local"})

    def test_size_hash_and_pe_mismatch_are_distinct(self):
        for changes, expected in (({"expected_size": len(self.data) + 1}, "size-mismatch"),
                                  ({"expected_sha256": "0" * 64}, "hash-mismatch"),
                                  ({"pe_machine": "arm64"}, "pe-machine-mismatch")):
            document = {"schema_version": 1, "assets": [{**self.spec, **changes}]}
            self.assertIn(expected, assets.inspect_assets(document, self.source_root)[0]["blockers"])

    def test_created_cache_is_private_independent_and_revalidated_before_reuse(self):
        with self.store() as store, store.locked(self.key):
            self.assertEqual(self.cache(store)["action"], "created")
            before = self.snapshot()
            self.assertEqual(self.cache(store)["action"], "reused")
            self.assertEqual(before, self.snapshot())
            self.assertEqual(store.verify_asset(self.spec)["sha256"], self.spec["expected_sha256"])
        payload = self.store_root / "assets/example-runtime-r1/payload.bin"
        self.assertNotEqual(payload.stat().st_ino, self.source.stat().st_ino)
        self.assertEqual(payload.stat().st_nlink, 1)
        for path in (self.store_root, *self.store_root.rglob("*")):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.source.write_bytes(b"source replaced after pinning")
        with self.store(False) as store:
            self.assertEqual(store.verify_asset(self.spec)["sha256"], self.spec["expected_sha256"])
            self.assertEqual(store.inventory()["assets"][0]["status"], "integrity-checked")

    def test_asset_folder_timestamps_alone_do_not_stop_caching_and_the_private_copy_stays_strict(self):
        # Other callers (such as --stage-local) keep the strict read; only the prepare.sh folder is loose.
        with self.store() as store, store.locked(self.key), \
                patch.object(storage, "regular_open", side_effect=FOLDER["touching_open"](self.source)), \
                self.assertRaisesRegex(storage.Invalid, r"input changed during read \(mtime_ns"):
            self.cache(store)
        for leftover in sorted((self.store_root / "assets").rglob("*"), reverse=True):
            leftover.unlink() if leftover.is_file() else leftover.rmdir()
        with self.store() as store, store.locked(self.key), \
                patch.object(storage, "regular_open", side_effect=FOLDER["touching_open"](self.source)):
            self.assertEqual(store.cache_asset(self.spec, self.source_root, timestamps=False)["action"], "created")
        names = sorted(path.name for path in (self.store_root / "assets").rglob("*"))
        self.assertEqual(names, ["example-runtime-r1", "payload.bin", "receipt.json"])
        payload = self.store_root / "assets/example-runtime-r1/payload.bin"
        real = storage.measure_stream
        with self.store(False) as store, \
                patch.object(storage, "measure_stream", lambda stream, *args, **kwargs: real(FOLDER["Touching"](stream, payload), *args, **kwargs)), \
                self.assertRaisesRegex(storage.Invalid, r"input changed during read \(mtime_ns"):
            store.verify_asset(self.spec)

    def test_modified_cache_and_metadata_are_not_overwritten(self):
        with self.store() as store, store.locked(self.key):
            self.cache(store)
            with self.assertRaises(Invalid):
                store.cache_asset({**self.spec, "version": "changed-same-revision"}, self.source_root)
            payload = self.store_root / "assets/example-runtime-r1/payload.bin"
            payload.write_bytes(self.data + b"tampered")
            before = payload.read_bytes()
            with self.assertRaises(Invalid):
                self.cache(store)
            self.assertEqual(payload.read_bytes(), before)
            self.assertEqual(store.inventory()["assets"][0]["status"], "invalid")

    def test_copy_failure_remains_visible_and_cannot_be_reused(self):
        with self.store() as store, store.locked(self.key):
            with patch.object(storage, "measure_stream", side_effect=OSError("synthetic disk failure")), self.assertRaises(OSError):
                self.cache(store)
            folder = self.store_root / "assets/example-runtime-r1"
            self.assertFalse((folder / "receipt.json").exists())
            self.assertEqual(store.inventory()["assets"][0]["status"], "incomplete")
            with self.assertRaises(Invalid):
                self.cache(store)
            self.assertTrue(folder.exists())

    def test_midcopy_source_change_does_not_commit_a_receipt(self):
        original = storage.measure_stream
        test = self

        class MutatingWriter:
            def __init__(self, destination):
                self.destination = destination
                self.changed = False

            def write(self, value):
                self.destination.write(value)
                if not self.changed:
                    self.changed = True
                    with test.source.open("ab") as stream:
                        stream.write(b"changed-during-copy")

        def changed(stream, limit, kind, destination=None, timestamps=True):
            # A size change is detected even though the asset-folder read does not compare timestamps.
            return original(stream, limit, kind, MutatingWriter(destination) if destination is not None else None,
                            timestamps=timestamps)

        with self.store() as store, store.locked(self.key), patch.object(storage, "measure_stream", side_effect=changed):
            with self.assertRaises(Invalid):
                self.cache(store)
            self.assertFalse((self.store_root / "assets/example-runtime-r1/receipt.json").exists())

    def test_continuously_growing_source_is_rejected_at_initial_length(self):
        writes = []
        original = assets.measure_stream
        test = self

        class GrowingWriter:
            def write(self, _):
                writes.append(1)
                require_short = len(writes) <= 2
                if not require_short:
                    raise AssertionError("growth must stop at the initial file length")
                with test.source.open("ab") as stream:
                    stream.write(b"more")

        with assets.regular_open(self.source, assets.INPUT_LIMITS["pe"]) as source, self.assertRaises(Invalid):
            original(source, assets.INPUT_LIMITS["pe"], "pe", GrowingWriter())
        self.assertEqual(len(writes), 1)

    def test_source_changed_after_plan_is_not_accepted_as_same_asset(self):
        before = self.report()["input_digest"]
        self.source.write_bytes(self.data + b"updated")
        self.assertNotEqual(before, self.report()["input_digest"])
        with self.assertRaises(Invalid):
            self.stage()
        self.assertFalse(self.store_root.exists())

    def test_opaque_input_is_only_hashed_not_extracted(self):
        data = b"not an executable or archive"
        self.source.write_bytes(data)
        spec = {**self.spec, "format": "opaque", "pe_machine": None, "expected_size": len(data),
                "expected_sha256": hashlib.sha256(data).hexdigest()}
        with self.store() as store, store.locked(self.key):
            store.cache_asset(spec, self.source_root)
            self.assertIsNone(store.verify_asset(spec)["pe_machine"])
            self.assertEqual(sorted((self.store_root / "assets/example-runtime-r1").iterdir()),
                             [self.store_root / "assets/example-runtime-r1/payload.bin",
                              self.store_root / "assets/example-runtime-r1/receipt.json"])

    def test_untrusted_external_limit_cannot_raise_trusted_ceiling(self):
        with patch.dict(assets.INPUT_LIMITS, {"pe": 128}), self.assertRaises(Invalid):
            assets.validate_manifest({"schema_version": 1, "assets": [self.spec]})

    def test_symlink_hardlink_and_fifo_source_never_enter_cache(self):
        self.source.unlink()
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.source.symlink_to(self.exe)
                elif kind == "hardlink":
                    os.link(self.exe, self.source)
                else:
                    os.mkfifo(self.source)
                with self.assertRaises(Invalid):
                    assets.inspect_assets({"schema_version": 1, "assets": [self.spec]}, self.source_root)
                self.source.unlink()

    def test_existing_broad_permissions_unknown_root_or_marker_are_rejected(self):
        self.store_root.mkdir(mode=0o755)
        with self.assertRaises(Invalid):
            self.store()
        self.store_root.chmod(0o700)
        (self.store_root / "existing-user-data").write_text("must preserve")
        with self.assertRaises(Invalid):
            self.store()
        self.assertEqual((self.store_root / "existing-user-data").read_text(), "must preserve")

    def test_malicious_managed_links_do_not_write_outside_root(self):
        outside = self.root / "outside"
        outside.mkdir()
        with self.store() as store, store.locked(self.key):
            (self.store_root / "assets").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                self.cache(store)
        self.assertEqual(list(outside.iterdir()), [])

    def test_managed_payload_permissions_links_and_receipt_schema_are_checked(self):
        with self.store() as store, store.locked(self.key):
            self.cache(store)
            payload = self.store_root / "assets/example-runtime-r1/payload.bin"
            payload.chmod(0o644)
            with self.assertRaises(Invalid):
                store.verify_asset(self.spec)
            payload.chmod(0o600)
            link = self.root / "extra-link"
            os.link(payload, link)
            with self.assertRaises(Invalid):
                store.verify_asset(self.spec)
            link.unlink()
            receipt = payload.with_name("receipt.json")
            value = json.loads(receipt.read_text())
            value["schema_version"] = 99
            receipt.write_text(json.dumps(value))
            with self.assertRaises(Invalid):
                store.verify_asset(self.spec)

    def test_lock_order_contention_and_release_across_processes(self):
        script_dir = str(Path(__file__).resolve().parent)
        code = '''import sys
sys.path.insert(0, sys.argv[1])
from preparation_store import PrivateStore, Invalid
try:
    with PrivateStore(sys.argv[2]) as store, store.locked(sys.argv[3]):
        print("acquired")
except Invalid:
    print("blocked")
'''
        command = [sys.executable, "-I", "-B", "-c", code, script_dir, str(self.store_root), self.key]
        with self.store() as store:
            with store.locked(self.key):
                with self.assertRaises(Invalid), store.locked(self.key):
                    self.fail("nested lock accepted")
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout.strip(), "blocked")
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), "acquired")
            try:
                with store.locked(self.key):
                    raise RuntimeError("synthetic cancellation")
            except RuntimeError:
                pass
            with store.locked(self.key):
                pass

    def test_mutations_require_locks_and_root_identity(self):
        with self.store() as store:
            with self.assertRaises(Invalid):
                self.cache(store)
            with store.locked(self.key):
                renamed = self.store_root.with_name("old-store")
                self.store_root.rename(renamed)
                self.store_root.mkdir(mode=0o700)
                with self.assertRaises(Invalid):
                    self.cache(store)
                self.assertEqual(list(self.store_root.iterdir()), [])

    def test_replaced_lock_file_stops_all_mutations(self):
        with self.store() as store, store.locked(self.key):
            path = self.store_root / "locks/global.lock"
            path.unlink()
            path.touch(mode=0o600)
            with self.assertRaises(Invalid):
                self.cache(store)
            self.assertFalse((self.store_root / "assets").exists())

    def test_abrupt_process_exit_releases_lock_but_not_running_state(self):
        report = self.report()
        code = r'''import json, os, sys
sys.path.insert(0, sys.argv[1])
from preparation_store import PrivateStore, RunJournal, target_key
report = json.loads(sys.argv[3])
with PrivateStore(sys.argv[2], create=True) as store, store.locked(target_key(report)):
    journal = RunJournal(store, report, lambda: report)
    journal.transition("asset-cache", "running")
    print(journal.run_id, flush=True)
    os._exit(17)
'''
        command = [sys.executable, "-I", "-B", "-c", code, str(Path(__file__).resolve().parent),
                   str(self.store_root), json.dumps(report)]
        child = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(child.returncode, 17, child.stderr)
        with self.store(False) as store, store.locked(self.key):
            journal = storage.RunJournal(store, report, self.report, child.stdout.strip())
            with self.assertRaises(Invalid):
                journal.transition("asset-cache", "succeeded", lambda: [{"check_id": "file", "result": "passed"}], exit_code=0)
            journal.reinspect({})
            self.assertEqual(journal.record["steps"]["asset-cache"]["status"], "needs-user")

    def test_global_lock_blocks_other_target_too(self):
        with self.store() as first, self.store(False) as second, first.locked(self.key), self.assertRaises(Invalid), second.locked("0" * 64):
            self.fail("global lock ignored")

    def test_journal_transitions_require_postconditions_not_exit_code_alone(self):
        report = self.report()
        with self.store() as store, store.locked(self.key):
            journal = storage.RunJournal(store, report, self.report)
            journal.transition("asset-cache", "running")
            original = self.run_files()[0].read_bytes()
            for verify in (None, list, lambda: [{"check_id": "file", "result": "failed"}],
                           lambda: [{"check_id": "file", "result": "uninspected"}]):
                with self.assertRaises(Invalid):
                    journal.transition("asset-cache", "succeeded", verify, exit_code=0)
                self.assertEqual(original, self.run_files()[0].read_bytes())
                self.assertEqual(journal.record["steps"]["asset-cache"]["status"], "running")
            journal.transition("asset-cache", "failed", exit_code=1)
            journal.transition("asset-cache", "running")
            self.cache(store)
            journal.transition("asset-cache", "succeeded", lambda: [{"check_id": "cache", "result": "passed"}], exit_code=0)
            journal.transition("prefix-preparation", "needs-user")
            self.assertEqual(journal.record["steps"]["asset-cache"]["attempt"], 2)
            self.assertEqual(journal.record["status"], "needs-user")
            self.assertFalse(journal.record["preparation_complete"])
            self.assertEqual(journal.record["recipes"], {"runtime": 1})
            self.assertEqual(journal.record["assets"]["example-runtime"]["revision"], 1)
            self.assertEqual(journal.record["assets"]["example-runtime"]["sha256"], self.spec["expected_sha256"])
            self.assertEqual(journal.record["compatibility"]["status"], "unverified")
            self.assertIsNotNone(journal.record["steps"]["asset-cache"]["started_ns"])
            self.assertIsNotNone(journal.record["steps"]["asset-cache"]["finished_ns"])

    def test_interrupted_running_is_needs_user_on_reinspection(self):
        report = self.report()
        with self.store() as store, store.locked(self.key):
            original = storage.RunJournal(store, report, self.report)
            original.transition("asset-cache", "running")
            resumed = storage.RunJournal(store, report, self.report, original.run_id)
            resumed.reinspect({})
            self.assertEqual(resumed.record["steps"]["asset-cache"]["status"], "needs-user")
            self.assertEqual(resumed.record["steps"]["asset-cache"]["checks"][0]["check_id"], "interrupted")

    def test_persisted_success_is_rechecked_and_missing_cache_fails(self):
        result = self.stage()
        payload = self.store_root / "assets/example-runtime-r1/payload.bin"
        payload.unlink()
        with self.store(False) as store, store.locked(self.key):
            resumed = storage.RunJournal(store, self.report(), self.report, result["run_id"])
            def verify():
                store.verify_asset(self.spec)
                return [{"check_id": "cache", "result": "passed"}]
            resumed.reinspect({"asset-cache": verify})
            self.assertEqual(resumed.record["steps"]["asset-cache"]["status"], "failed")
            self.assertFalse(resumed.record["preparation_complete"])

    def test_configuration_exe_and_manifest_change_stop_stale_plan(self):
        for kind in ("config", "exe", "manifest"):
            with self.subTest(kind=kind):
                report = self.report()
                with self.store() as store, store.locked(self.key):
                    journal = storage.RunJournal(store, report, self.report)
                    before = (self.store_root / "runs" / (journal.run_id + ".json")).read_bytes()
                    path = {"config": self.config, "exe": self.exe, "manifest": self.manifest}[kind]
                    original = path.read_bytes()
                    path.write_bytes(original + (b" " if kind != "exe" else b"changed"))
                    with self.assertRaises(Invalid):
                        journal.transition("asset-cache", "running")
                    self.assertEqual(before, (self.store_root / "runs" / (journal.run_id + ".json")).read_bytes())
                    with self.assertRaises(Invalid):
                        storage.RunJournal(store, self.report(), self.report, journal.run_id)
                    path.write_bytes(original)

    def test_change_while_verifying_cannot_commit_success(self):
        with self.store() as store, store.locked(self.key):
            journal = storage.RunJournal(store, self.report(), self.report)
            journal.transition("asset-cache", "running")
            before = self.run_files()[0].read_bytes()
            def verify():
                self.config.write_text(self.config.read_text() + "\n")
                return [{"check_id": "cache", "result": "passed"}]
            with self.assertRaises(Invalid):
                journal.transition("asset-cache", "succeeded", verify, exit_code=0)
            self.assertEqual(before, self.run_files()[0].read_bytes())
            self.assertEqual(journal.record["steps"]["asset-cache"]["status"], "running")

    def test_atomic_journal_failure_preserves_previous_record(self):
        with self.store() as store, store.locked(self.key):
            journal = storage.RunJournal(store, self.report(), self.report)
            before = self.run_files()[0].read_bytes()
            with patch.object(storage.os, "replace", side_effect=OSError("synthetic failure")), self.assertRaises(OSError):
                journal.transition("asset-cache", "running")
            self.assertEqual(before, self.run_files()[0].read_bytes())
            self.assertEqual(journal.record["steps"]["asset-cache"]["status"], "pending")
            self.assertEqual(list((self.store_root / "runs").glob("tmp-*.json")), [])

    def test_configuration_change_during_json_flush_prevents_commit(self):
        with self.store() as store, store.locked(self.key):
            journal = storage.RunJournal(store, self.report(), self.report)
            before = self.run_files()[0].read_bytes()
            sync = storage.os.fsync
            changed = []
            def mutate(descriptor):
                sync(descriptor)
                if not changed:
                    changed.append(True)
                    self.config.write_text(self.config.read_text() + "\n")
            with patch.object(storage.os, "fsync", side_effect=mutate), self.assertRaises(Invalid):
                journal.transition("asset-cache", "running")
            self.assertTrue(changed)
            self.assertEqual(self.run_files()[0].read_bytes(), before)
            self.assertEqual(journal.record["steps"]["asset-cache"]["status"], "pending")

    def test_pipeline_copy_failure_records_failed_without_prefix_changes(self):
        with patch.object(storage.PrivateStore, "cache_asset", side_effect=OSError("synthetic failure")), self.assertRaises(OSError):
            self.stage()
        record = json.loads(self.run_files()[0].read_text())
        self.assertEqual(record["steps"]["asset-cache"]["status"], "failed")
        self.assertFalse(record["preparation_complete"])
        self.assertFalse((self.steam / "steamapps/compatdata").exists())

    def test_competing_journal_update_is_not_overwritten(self):
        with self.store() as store, store.locked(self.key):
            journal = storage.RunJournal(store, self.report(), self.report)
            path = self.run_files()[0]
            path.write_bytes(path.read_bytes() + b" ")
            before = path.read_bytes()
            with self.assertRaises(Invalid):
                journal.transition("asset-cache", "running")
            self.assertEqual(path.read_bytes(), before)

    def test_invalid_run_schema_and_injected_secret_field_are_rejected(self):
        result = self.stage()
        path = self.run_files()[0]
        original = json.loads(path.read_text())
        for changes in ({"schema_version": 99}, {"environment": {"secret": "DUMMY_PRIVATE_VALUE"}},
                        {"preparation_complete": True}, {"tool_version": "future"}):
            value = {**original, **changes}
            path.write_text(json.dumps(value))
            with self.store(False) as store, store.locked(self.key), self.assertRaises(Invalid):
                storage.RunJournal(store, self.report(), self.report, result["run_id"])
        self.assertNotIn("DUMMY_PRIVATE_VALUE", json.dumps(original))

    def test_marker_unknown_step_and_record_traversal_are_rejected(self):
        self.stage()
        with self.store(False) as store:
            with self.assertRaises(Invalid):
                store.read_record("runs", "../store.json")
            record = json.loads(self.run_files()[0].read_text())
            record["steps"]["arbitrary-step"] = record["steps"]["asset-cache"]
            with self.assertRaises(Invalid):
                storage.validate_run(record)
        marker = self.store_root / "store.json"
        marker.write_text(json.dumps({**storage.MARKER, "schema_version": True}))
        with self.assertRaises(Invalid):
            self.store(False)

    def test_object_count_and_record_size_are_bounded(self):
        with self.store() as store, store.locked(self.key):
            with self.assertRaises(Invalid):
                store.write_record("runs", "large.json", {"data": ["x" * 4096] * 300})
            with store.directory(("assets",), create=True) as fd:
                for name in ("slot-a", "slot-b", "slot-c"):
                    os.mkdir(name, mode=0o700, dir_fd=fd)
            with patch.object(storage, "MAX_OBJECTS", 2), self.assertRaises(Invalid):
                self.cache(store)

    def test_stage_and_resume_write_only_private_objects_and_never_prepare(self):
        protected = {path: path.read_bytes() for path in (self.exe, self.config, self.added, self.profile, self.recipes, self.manifest)}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("subprocess.run", side_effect=AssertionError("installer forbidden")), \
                patch("runpy.run_path", side_effect=AssertionError("external code forbidden")):
            first = self.stage()
            self.assertEqual(first["status"], "needs-user")
            self.assertFalse(first["preparation_complete"])
            self.args.resume_run = first["run_id"]
            resumed = self.stage()
        self.assertEqual(resumed["cached_assets"][0]["action"], "revalidated")
        self.assertEqual(len(self.run_files()), 1)
        for path, data in protected.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertFalse((self.steam / "steamapps/compatdata").exists())
        with self.store(False) as store:
            before = self.snapshot()
            inventory = store.inventory()
            self.assertEqual(inventory["runs"][0]["stored_status"], "needs-user")
            self.assertTrue(inventory["runs"][0]["reinspection_required"])
            self.assertEqual(before, self.snapshot())

    def test_management_root_must_be_disjoint_from_all_inputs(self):
        for root in (self.source_root / "cache", self.steam / "cache", self.exe_root / "cache", self.root):
            self.args.management_root = root
            with self.subTest(root=root), self.assertRaises(Invalid):
                self.stage()

    def test_cli_stage_list_resume_and_read_only_modes(self):
        script = str(Path(__file__).with_name("prepare-game.sh").resolve())
        command = ["/bin/bash", script, "--registrations", str(self.added), "--steam-root", str(self.steam),
                   "--settings-root", str(self.settings), "--app-id", "4294967295", "--exe-root", str(self.exe_root),
                   "--profile", str(self.profile), "--recipes", str(self.recipes),
                   "--assets", str(self.manifest), "--asset-root", str(self.source_root)]
        before = self.snapshot()
        inspected = subprocess.run(command + ["--inspect"], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(inspected.stdout)["writes"], [])
        self.assertEqual(before, self.snapshot())
        staged = subprocess.run(command + ["--stage-local", "--management-root", str(self.store_root)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(staged.returncode, 2, staged.stderr)
        result = json.loads(staged.stdout)
        self.assertFalse(result["preparation_complete"])
        before = self.snapshot()
        listed = subprocess.run(["/bin/bash", script, "--list-local", "--management-root", str(self.store_root)],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(listed.stdout)["writes"], [])
        self.assertEqual(before, self.snapshot())
        resumed = subprocess.run(command + ["--stage-local", "--management-root", str(self.store_root),
                                             "--resume-run", result["run_id"]], capture_output=True, text=True, check=False)
        self.assertEqual(resumed.returncode, 2, resumed.stderr)
        self.assertEqual(json.loads(resumed.stdout)["cached_assets"][0]["action"], "revalidated")
        (self.store_root / "assets/example-runtime-r1/payload.bin").write_bytes(b"DUMMY_PRIVATE_VALUE")
        failed = subprocess.run(command + ["--stage-local", "--management-root", str(self.store_root),
                                           "--resume-run", result["run_id"]], capture_output=True, text=True, check=False)
        self.assertEqual(failed.returncode, 1)
        self.assertIn("private cache/run files may remain", failed.stderr)
        self.assertNotIn("DUMMY_PRIVATE_VALUE", failed.stdout + failed.stderr)


if __name__ == "__main__":
    unittest.main()
