#!/usr/bin/env python3
"""Saved slot verification data and version-agnostic installation records (0.31.0)."""

import hashlib
import json
import os
import runpy
import tempfile
import unittest
from pathlib import Path

ENGINE = runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
# The trusted entry point has already inserted the distribution path under -I.
import preparation_slot_manifest as manifest
import preparation_store as storage
from preparation_assets import digest_json
from preparation_payload import PayloadInventory
from preparation_tool_writer import validate_installation_record

Invalid = storage.Invalid
SLOT = "SoftDenchi-Prep-Proton 11-12.8-softdenchi3-beta2"


def inventory(content=b"x", count=1):
    entries = {f"files/data-{index}.bin": {"kind": "file", "mode": 0o644, "size": len(content),
                                          "sha256": hashlib.sha256(content).hexdigest()} for index in range(count)}
    entries["files"] = {"kind": "directory", "mode": 0o755}
    digest = digest_json({"root_mode": 0o755, "entries": entries})
    return PayloadInventory("DroidDeck-Proton 11-12.8-softdenchi3-beta2", "a" * 128, 0o755, entries, digest,
                            len(content) * count, 0)


def overlays(text=b"wrapper"):
    return {"droiddeck-proton-wrap": {"kind": "file", "mode": 0o755, "size": len(text),
                                      "sha256": hashlib.sha256(text).hexdigest()}}


def installation_record(directory=SLOT, status="installed-tree-verified", published=True, phase="post-verified",
                        version="0.30.0", **extra):
    token = os.urandom(16).hex()
    record = {"schema_version": 1, "tool_version": version, "installation_id": "installation-" + token,
              "app_id": "42", "input_digest": "b" * 64, "status": status, "phase": phase,
              "staging_name": ".prefix-preparation-staging-" + token, "directory": directory,
              "published": published, "preparation_complete": False}
    record.update(extra)
    return record


class SlotManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        base = Path(self.temporary.name) / "home" / "state"
        base.mkdir(parents=True, mode=0o700)
        self.root = base / "tool-store"

    def tearDown(self):
        self.temporary.cleanup()

    def store(self):
        return storage.PrivateStore(self.root, create=True)

    def save(self, record, directory=SLOT):
        with self.store() as store, store.locked("c" * 64):
            return manifest.save(store, directory, record)

    def test_save_once_then_same(self):
        record = manifest.build(SLOT, SLOT.replace(" ", "-", 1), inventory(), overlays(), "1234 DroidDeck-Proton")
        self.assertEqual(self.save(record), "created")
        again = manifest.build(SLOT, SLOT.replace(" ", "-", 1), inventory(), overlays(), "1234 DroidDeck-Proton")
        self.assertEqual(self.save(again), "same")  # Only the time differs.
        with self.store() as store:
            state, saved = manifest.state(store, SLOT)
        self.assertEqual(state, "same")
        self.assertTrue(manifest.usable(saved))
        self.assertEqual(manifest.inventory_of(saved), inventory())

    def test_different_payload_or_overlay_is_mismatch_and_not_overwritten(self):
        self.assertEqual(self.save(manifest.build(SLOT, "t", inventory(), overlays(), "v")), "created")
        path = self.root / manifest.DIRECTORY / manifest.record_name(SLOT)
        before = path.read_bytes()
        self.assertEqual(self.save(manifest.build(SLOT, "t", inventory(b"y"), overlays(), "v")), "mismatch")
        self.assertEqual(self.save(manifest.build(SLOT, "t", inventory(), overlays(b"other"), "v")), "mismatch")
        self.assertEqual(path.read_bytes(), before)

    def test_broken_record_is_not_rewritten(self):
        self.assertEqual(self.save(manifest.build(SLOT, "t", inventory(), overlays(), "v")), "created")
        path = self.root / manifest.DIRECTORY / manifest.record_name(SLOT)
        path.write_bytes(b"{not json")
        self.assertEqual(self.save(manifest.build(SLOT, "t", inventory(), overlays(), "v")), "broken")
        self.assertEqual(path.read_bytes(), b"{not json")
        record = json.loads(json.dumps(manifest.build(SLOT, "t", inventory(), overlays(), "v")))
        record["directory"] = SLOT + "x"
        path.write_text(json.dumps(record))
        with self.store() as store:
            self.assertEqual(manifest.state(store, SLOT)[0], "broken")  # Recorded for another slot name.

    def test_large_record_above_the_ordinary_limit(self):
        big = inventory(count=12000)
        record = manifest.build(SLOT, "t", big, overlays(), "v")
        self.assertGreater(len(json.dumps(record)), storage.MAX_JSON)
        self.assertEqual(self.save(record), "created")
        with self.store() as store:
            state, saved = manifest.state(store, SLOT)
        self.assertEqual((state, len(saved["inventory"]["entries"])), ("same", 12001))

    def test_missing_and_names(self):
        with self.store() as store:
            self.assertEqual(manifest.state(store, SLOT), ("missing", None))
        name = manifest.record_name(SLOT)
        self.assertRegex(name, r"\Am[0-9a-f]{64}\.json\Z")
        self.assertTrue(storage.COMPONENT.fullmatch(name))
        for bad in ("SoftDenchi-Proton x", SLOT + "/x", "", "SoftDenchi-Prep-Proton " + "x" * 200):
            with self.assertRaises(Invalid):
                manifest.record_name(bad)

    def test_unusable_with_other_rule_versions(self):
        record = manifest.build(SLOT, "t", inventory(), overlays(), "v")
        record["contracts"] = dict(record["contracts"], pycache="other")
        self.assertFalse(manifest.usable(record))
        self.assertFalse(manifest.usable(None))

    def test_the_same_contents_under_other_rule_versions_are_not_a_different_slot(self):
        record = manifest.build(SLOT, "t", inventory(), overlays(), "v")
        self.assertEqual(self.save(record), "created")
        path = self.root / manifest.DIRECTORY / manifest.record_name(SLOT)
        before = path.read_bytes()
        later = dict(manifest.build(SLOT, "t", inventory(), overlays(), "v"), contracts=dict(record["contracts"], pycache="2"))
        with self.store() as store:
            self.assertEqual(manifest.state(store, SLOT, later)[0], "rules-differ")
        self.assertEqual(self.save(later), "rules-differ")  # Not rewritten; a later version decides how to re-save.
        self.assertEqual(path.read_bytes(), before)
        other = dict(later, version_value="w")
        with self.store() as store:
            self.assertEqual(manifest.state(store, SLOT, other)[0], "mismatch")

    def test_write_requires_lock(self):
        record = manifest.build(SLOT, "t", inventory(), overlays(), "v")
        with self.store() as store, self.assertRaises(Invalid):
            manifest.save(store, SLOT, record)


class InstallationRecordTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        base = Path(self.temporary.name) / "home" / "state"
        base.mkdir(parents=True, mode=0o700)
        self.root = base / "tool-store"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, *records):
        with storage.PrivateStore(self.root, create=True) as store, store.locked("c" * 64):
            for record in records:
                store.write_record("installations", record["installation_id"] + ".json", record)

    def placed(self):
        with storage.PrivateStore(self.root, create=True) as store:
            return manifest.placed_slots(store)

    def test_earlier_versions_are_read_only_by_the_history_reader(self):
        old = installation_record()
        validate_installation_record(old, any_version=True)
        with self.assertRaises(Invalid):
            validate_installation_record(old)
        validate_installation_record(installation_record(version=ENGINE["VERSION"], created_ns=1))
        with self.assertRaises(Invalid):
            validate_installation_record(installation_record(created_ns=0), any_version=True)
        with self.assertRaises(Invalid):
            validate_installation_record(installation_record(extra_field=1), any_version=True)

    def test_placed_slots_rules(self):
        other = "SoftDenchi-Prep-Proton 11-12.8-softdenchi3-beta1"
        third = "SoftDenchi-Prep-Proton 11-12.8-softdenchi3-cleanup2"
        self.write(installation_record(), installation_record(directory=other),
                   installation_record(directory=other, status="running", published=False, phase="staging"),
                   installation_record(directory=third, status="failed", published=False, phase="staging"),
                   installation_record(directory=third),
                   installation_record(directory=third, status="needs-inspection", published=False, phase="publish-intent"),
                   installation_record(directory="SoftDenchi-Proton x"),
                   installation_record(directory=SLOT, version=ENGINE["VERSION"], created_ns=5))
        placed, unreadable = self.placed()
        self.assertEqual(placed, {SLOT: {"created_ns": 5}})
        self.assertEqual(unreadable, 0)

    def test_unreadable_record_is_counted(self):
        self.write(installation_record())
        (self.root / "installations" / "junk.json").write_bytes(b"{")
        (self.root / "installations" / "junk.json").chmod(0o600)
        placed, unreadable = self.placed()
        self.assertEqual((list(placed), unreadable), ([SLOT], 1))

    def test_no_records(self):
        self.assertEqual(self.placed(), ({}, 0))


if __name__ == "__main__":
    unittest.main()
