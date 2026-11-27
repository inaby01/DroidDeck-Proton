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
    write_json = FIXTURES["SettingsFixture"].write_json
    snapshot = FIXTURES["SettingsFixture"].snapshot

    def setUp(self):
        FIXTURES["SettingsFixture"].setUp(self)
        self.source_root = self.root / "sources"
        self.source_root.mkdir()
        self.data = FIXTURES["pe"]()
        self.spec = spec_for(self.data)
        self.source = self.source_root / self.spec["filename"]
        self.source.write_bytes(self.data)
        self.manifest = self.root / "assets.json"
        self.write_json(self.manifest, {"schema_version": 1, "assets": [self.spec]})
        self.store_root = self.root / "private-store"
        self.key = hashlib.sha256(str(self.steam / "steamapps/compatdata/4294967295").encode()).hexdigest()

    def store(self, create=True):
        return storage.PrivateStore(self.store_root, create=create)

    def cache(self, store):
        return store.cache_asset(self.spec, self.source_root)

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

    def test_global_lock_blocks_other_target_too(self):
        with self.store() as first, self.store(False) as second, first.locked(self.key), self.assertRaises(Invalid), second.locked("0" * 64):
            self.fail("global lock ignored")

    def test_object_count_and_record_size_are_bounded(self):
        with self.store() as store, store.locked(self.key):
            with self.assertRaises(Invalid):
                store.write_record("runs", "large.json", {"data": ["x" * 4096] * 300})
            with store.directory(("assets",), create=True) as fd:
                for name in ("slot-a", "slot-b", "slot-c"):
                    os.mkdir(name, mode=0o700, dir_fd=fd)
            with patch.object(storage, "MAX_OBJECTS", 2), self.assertRaises(Invalid):
                self.cache(store)

if __name__ == "__main__":
    unittest.main()
