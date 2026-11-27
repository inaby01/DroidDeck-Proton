#!/usr/bin/env python3
"""Numbered target selection, current registration pins and short report launcher."""

import copy
import hashlib
import json
import os
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / "test_preparation_installation.py"))
import preparation_selection as selection
from preparation_common import Invalid


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FIX["InstallationTests"]()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        f = self.fixture
        self.directory = f.source.root
        self.home = f.game.root / "private-launch-home"
        self.home.mkdir()
        self.environment = {**f.context.environment, "BL_ADDED_GAMES": str(f.game.added)}
        self.config = {"schema_version": 1, "payload": {"archive": f.source.archive.name, "sha512": f.source.sha,
                        "root": FIX["CUSTOM"]["ROOT"], "mode": "cleanup"}, "runtime_reference": f.reference}
        self.renderer = FIX["CUSTOM"]["INSTALLER"]["render_installation"]
        self.steam, self.settings = f.game.steam, f.game.settings
        self.key = "4294967295"

    def catalog(self):
        return selection.registration_catalog(self.environment)

    def test_catalog_uses_environment_referenced_file_and_normalizes_id(self):
        source, digest, games = self.catalog()
        self.assertEqual(source, self.fixture.game.added)
        self.assertEqual(digest, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(list(games), [self.key])
        with self.assertRaises(Invalid):
            selection.registration_catalog({"BL_ADDED_GAMES": self.fixture.game.added.read_text()})

    def test_report_saving_is_exclusive_private_and_does_not_mutate_input(self):
        report = {"writes": [], "preparation_complete": False}
        existing = self.directory / "plan-aaaaaaaa.json"
        existing.write_bytes(b"KEEP")
        with patch.object(selection.secrets, "token_hex", side_effect=["aaaaaaaa", "bbbbbbbb"]):
            filename = selection.save_selection_report(self.directory, report)
        self.assertEqual(existing.read_bytes(), b"KEEP")
        self.assertEqual(filename, "plan-bbbbbbbb.json")
        self.assertEqual((self.directory / filename).stat().st_mode & 0o777, 0o600)
        self.assertEqual(report["writes"], [])

    def test_report_cannot_be_saved_inside_protected_or_symlink_folder(self):
        prefix = self.steam / "steamapps/compatdata/42"
        prefix.mkdir(parents=True)
        with self.assertRaises(Invalid):
            selection.save_selection_report(prefix, {}, (self.steam, self.settings))
        link = self.directory / "linked-report"
        link.symlink_to(self.home)
        with self.assertRaises(Invalid):
            selection.save_selection_report(link, {})
        self.assertEqual(list(prefix.iterdir()), [])

    def test_unknown_config_keys_layout_traversal_and_archive_root_are_rejected(self):
        for modification in ({"unknown": True}, {"payload": {**self.config["payload"], "alternate_relative_path": "../payload.tar.gz"}},
                             {"payload": {**self.config["payload"], "root": "Other"}}):
            config = {**copy.deepcopy(self.config), **modification}
            with self.subTest(keys=list(modification)), self.assertRaises(Invalid):
                selection.validate_selection_config(config)

    def test_superseded_slot_list(self):
        config = copy.deepcopy(self.config)
        config["payload"]["tool_slot"] = "preparation"
        older = "SoftDenchi-Prep-Proton 11-12.8-softdenchi3-beta1"
        own = "SoftDenchi-Prep-Proton " + config["payload"]["root"].removeprefix("DroidDeck-Proton ")
        selection.validate_selection_config({**config, "supersedes": [older]})
        for value in ([own], [older, older], "x", ["SoftDenchi-Proton x"], [older + "/x"], [None]):
            with self.subTest(value=value), self.assertRaises((Invalid, TypeError)):
                selection.validate_selection_config({**copy.deepcopy(config), "supersedes": value})
        legacy = copy.deepcopy(self.config)
        legacy["payload"].pop("tool_slot", None)
        with self.assertRaises(Invalid):
            selection.validate_selection_config({**legacy, "supersedes": [older]})

    def test_a_bundle_that_is_not_operational_emits_no_script(self):
        # The earlier single screen was removed in 1.0.1; only the four scripts of an operational bundle exist.
        for entry in ("prepare", "status", "diagnose", "recovery"):
            with self.subTest(entry=entry), self.assertRaises(Invalid):
                selection.selection_script(self.config, entry)
        with self.assertRaises(Invalid):
            selection.selection_script(None)

    def report(self):
        return {"schema_version": 1, "mode": "fixture-report", "writes": []}

    def test_shared_group_writable_folder_gets_private_original_and_export(self):
        self.directory.chmod(0o2770)
        before_mode = self.directory.stat().st_mode & 0o7777
        try:
            path, private = selection.save_selection_result(self.directory, self.home, self.report(), (self.steam,))
            self.assertEqual(path.parent, self.directory)
            self.assertEqual(private.parent, self.home / ".local/state/droiddeck-prefix-preparation/reports")
            self.assertEqual(private.read_bytes(), path.read_bytes())
            self.assertEqual(json.loads(path.read_bytes())["report_storage"]["authoritative"], "private-linux-home")
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            self.assertEqual(private.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(self.directory.stat().st_mode & 0o7777, before_mode)
        finally:
            self.directory.chmod(0o700)

    def test_shared_owner_metadata_does_not_require_chown_or_chmod(self):
        from types import SimpleNamespace
        original = os.fstat
        identity = self.directory.stat().st_dev, self.directory.stat().st_ino
        def emulated(fd):
            info = original(fd)
            if (info.st_dev, info.st_ino) == identity:
                return SimpleNamespace(st_uid=os.getuid()+1234, st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino)
            return info
        with patch("os.fstat", side_effect=emulated), patch("os.chown", side_effect=AssertionError("no ownership changes")), \
             patch("os.chmod", side_effect=AssertionError("no directory permission changes")):
            path, private = selection.save_selection_result(self.directory, self.home, self.report(), (self.steam,))
        self.assertIsNotNone(private)
        self.assertEqual(json.loads(path.read_bytes())["report_storage"]["authoritative"], "private-linux-home")

    def test_failed_shared_export_still_preserves_private_diagnostics(self):
        self.directory.chmod(0o2770)
        try:
            with patch.object(selection, "_export_report", side_effect=PermissionError("DUMMY_PRIVATE_DETAIL")):
                path, private = selection.save_selection_result(self.directory, self.home, self.report(), (self.steam,))
            self.assertIsNone(private)
            self.assertEqual(path.parent, self.home / ".local/state/droiddeck-prefix-preparation/reports")
            self.assertTrue(path.is_file())
            self.assertNotIn("DUMMY_PRIVATE_DETAIL", path.read_text())
        finally:
            self.directory.chmod(0o700)

    def test_private_report_ancestor_symlink_is_not_followed(self):
        self.directory.chmod(0o2770)
        local = self.home / ".local"
        local.mkdir()
        external = self.home / "external"
        external.mkdir()
        (local / "state").symlink_to(external, target_is_directory=True)
        try:
            with self.assertRaises((OSError, ValueError)):
                selection.save_selection_result(self.directory, self.home, self.report(), (self.steam,))
            self.assertEqual(list(external.iterdir()), [])
        finally:
            self.directory.chmod(0o700)

    def test_protected_directory_uses_private_result_without_export(self):
        path, original = selection.save_selection_result(self.steam, self.home, {"writes": []}, (self.steam, self.settings))
        self.assertIsNone(original)
        self.assertTrue(path.is_relative_to(self.home))
        self.assertEqual(list(self.steam.glob("plan-*.json")), [])

    def test_shared_export_collision_never_overwrites_existing_result(self):
        self.directory.chmod(0o2770)
        existing = self.directory / "plan-dddddddd.json"
        existing.write_bytes(b"KEEP")
        try:
            with patch.object(selection.secrets, "token_hex", return_value="dddddddd"):
                path, _ = selection.save_selection_result(self.directory, self.home, {"writes": []}, (self.steam,))
            self.assertTrue(path.is_relative_to(self.home))
            self.assertEqual(existing.read_bytes(), b"KEEP")
            self.assertNotEqual(path.read_bytes(), b"KEEP")
        finally:
            self.directory.chmod(0o700)

if __name__ == "__main__":
    unittest.main()
