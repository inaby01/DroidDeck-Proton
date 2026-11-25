#!/usr/bin/env python3
"""Synthetic tests: never access a real game, account, prefix or installer."""

import argparse
import copy
import hashlib
import json
import os
import runpy
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ENGINE = runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
Invalid = ENGINE["Invalid"]
PROFILE = {
    "schema_version": 1, "profile_id": "example", "revision": 1, "title": "Example",
    "edition": "Unknown", "edition_status": "unconfirmed", "droiddeck_versions": ["0.7.1"],
    "proton_versions": ["example-r1"], "dependencies": ["runtime"], "evidence": ["Synthetic"],
    "exe_sha256": None,
}
RECIPES = {"schema_version": 1, "dependencies": [
    {"dependency_id": "runtime", "revision": 1, "handler": "mfc-local", "requires": [],
     "status": "blocked", "reason": "Provenance and postconditions pending"}]}


def pe(machine=0x14C, magic=0x10B):
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    struct.pack_into("<H", data, 84, 2)
    struct.pack_into("<H", data, 88, magic)
    return bytes(data)


class InspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prefix-test-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.steam = self.root / "Steam"
        self.settings = self.root / "settings"
        self.exe_root = self.root / "games"
        self.exe = self.exe_root / "日本語 空白 ' ; $(touch injected)" / "Game.exe"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(pe())
        (self.steam / "config").mkdir(parents=True)
        self.settings.mkdir()
        self.added = self.root / "added.json"
        self.write_json(self.added, [{"appid": -1, "exe": str(self.exe), "title": "日本語\n\u001b[31m\u202e"}])
        self.write_json(self.settings / "games.json", {"version": 1, "games": {
            "4294967295": {"valve": False, "dir": "Example Proton"},
            "99": {"valve": True, "dir": "Keep"}}})
        self.config = self.steam / "config/config.vdf"
        self.config.write_text('''"InstallConfigStore" { "Software" { "Valve" { "Steam" {
          "Secret" "DUMMY_PRIVATE_VALUE" "CompatToolMapping" {
            "0" { "name" "default-tool" }
            "4294967295" { "name" "actual-tool" }
          }
        } } } }''')
        self.profile = self.root / "profile.json"
        self.recipes = self.root / "recipes.json"
        self.write_json(self.profile, PROFILE)
        self.write_json(self.recipes, RECIPES)
        self.args = argparse.Namespace(steam_root=self.steam, settings_root=self.settings, registrations=self.added,
                                       plan=True, app_id="4294967295", exe_root=self.exe_root,
                                       profile=self.profile, recipes=self.recipes,
                                       droiddeck_version="0.7.1", proton_version="example-r1")

    def write_json(self, path, data):
        path.write_text(json.dumps(data, ensure_ascii=False))

    def report(self):
        return ENGINE["build_report"](self.args)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns)
                if path.is_file() else "directory" for path in self.root.rglob("*")}

    def test_plan_is_read_only_and_explicitly_blocked(self):
        before = self.snapshot()
        with patch("subprocess.run", side_effect=AssertionError("process execution forbidden")), \
                patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("runpy.run_path", side_effect=AssertionError("helper execution forbidden")):
            report = self.report()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(report["writes"], [])
        self.assertIn("execution-not-implemented", report["blockers"])
        self.assertEqual(report["dependencies"][0]["inspection"], "uninspected")
        self.assertEqual(report["compatibility"]["status"], "unverified")
        self.assertEqual(report["prefix"]["dependencies"], "uninspected")
        self.assertIn("synchronization-impact", report["uninspected"])
        self.assertEqual(report["target"]["identity"]["sha256"], hashlib.sha256(pe()).hexdigest())
        self.assertEqual(report["selection"]["steam_game_tool"], "actual-tool")
        self.assertEqual(report["selection"]["steam_default_tool"], "default-tool")
        self.assertEqual(report["selection"]["ui_choice"]["dir"], "Example Proton")
        self.assertNotIn("DUMMY_PRIVATE_VALUE", ENGINE["display"](report))

    def test_list_and_default_inspect_do_not_require_profile(self):
        self.args.app_id = self.args.profile = self.args.recipes = None
        self.args.plan = False
        report = self.report()
        self.assertEqual(report["games"][0]["app_id"], "4294967295")
        self.assertIn("select-registration-id", report["blockers"])

    def test_signed_unsigned_registration_alias_is_rejected(self):
        self.write_json(self.added, [{"appid": value, "exe": str(self.exe)} for value in (-1, 4294967295)])
        with self.assertRaises(Invalid):
            self.report()

    def test_same_basename_does_not_select_another_registration(self):
        other = self.exe_root / "Another" / "Game.exe"
        other.parent.mkdir()
        other.write_bytes(pe(0x8664, 0x20B))
        self.write_json(self.added, [{"appid": 99, "exe": str(other)}, {"appid": -1, "exe": str(self.exe)}])
        self.assertEqual(self.report()["target"]["exe"], str(self.exe))
        self.args.app_id = "100"
        with self.assertRaises(Invalid):
            self.report()

    def test_changed_exe_changes_digest_and_reference_mismatch_blocks(self):
        profile = copy.deepcopy(PROFILE)
        profile["exe_sha256"] = hashlib.sha256(pe()).hexdigest()
        self.write_json(self.profile, profile)
        before = self.report()
        self.exe.write_bytes(pe() + b"changed")
        after = self.report()
        self.assertNotEqual(before["input_digest"], after["input_digest"])
        self.assertIn("exe-hash-mismatch", after["blockers"])

    def test_existing_prefix_and_signed_alias_never_reinitialized(self):
        prefix = self.steam / "steamapps/compatdata/-1"
        (prefix / "pfx").mkdir(parents=True)
        (prefix / "version").write_text("unknown-old-version\n")
        before = self.snapshot()
        report = self.report()
        self.assertIn("existing-prefix-read-only", report["blockers"])
        self.assertEqual(report["prefix"]["version"], "unknown-old-version")
        self.assertEqual(before, self.snapshot())
        (prefix.parent / "4294967295").mkdir()
        with self.assertRaises(Invalid):
            self.report()

    def test_symlink_parent_prefix_and_exe_are_rejected(self):
        link = self.root / "linked-games"
        link.symlink_to(self.exe_root, target_is_directory=True)
        self.write_json(self.added, [{"appid": -1, "exe": str(link / self.exe.relative_to(self.exe_root))}])
        with self.assertRaises(Invalid):
            self.report()
        self.write_json(self.added, [{"appid": -1, "exe": str(self.exe)}])
        base = self.steam / "steamapps/compatdata"
        base.mkdir(parents=True)
        (base / "4294967295").symlink_to(self.exe_root, target_is_directory=True)
        with self.assertRaises(Invalid):
            self.report()

    def test_exe_outside_root_and_path_traversal_are_rejected(self):
        self.args.exe_root = self.root / "elsewhere"
        with self.assertRaises(Invalid):
            self.report()
        self.args.exe_root = self.exe_root
        self.write_json(self.added, [{"appid": -1, "exe": str(self.exe.parent / ".." / "Game.exe")}])
        with self.assertRaises(Invalid):
            self.report()

    def test_symlink_hardlink_fifo_and_environment_file_inputs_rejected(self):
        for name, setup in (("link.json", lambda p: p.symlink_to(self.added)),
                            ("hard.json", lambda p: os.link(self.added, p)),
                            ("fifo.json", os.mkfifo),
                            (".env.local", lambda p: p.write_text("PRIVATE"))):
            with self.subTest(name=name):
                path = self.root / name
                setup(path)
                with self.assertRaises(Invalid):
                    ENGINE["load_json"](path)
                path.unlink()

    def test_pe_architecture_and_malformed_headers(self):
        for machine, magic, expected in ((0x14C, 0x10B, "x86"), (0x8664, 0x20B, "x86_64"), (0xAA64, 0x20B, "arm64")):
            self.exe.write_bytes(pe(machine, magic))
            self.assertEqual(self.report()["target"]["identity"]["pe_machine"], expected)
        for value in (b"MZ", b"bad", pe(0xAA64, 0x10B), pe()[:89]):
            self.exe.write_bytes(value)
            with self.assertRaises(Invalid):
                self.report()

    def test_control_characters_are_escaped(self):
        text = ENGINE["display"](self.report())
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("日本語", text)
        self.assertIn("\\u001b", text)
        self.assertIn("\\u202e", text)

    def test_untrusted_python_files_are_not_executed(self):
        (self.exe.parent / "user_settings.py").write_text("raise RuntimeError('must not run')")
        (self.root / "steam-compatibility").write_text("raise RuntimeError('must not run')")
        self.report()

    def test_cli_isolated_from_cwd_path_and_pythonpath(self):
        script = Path(__file__).with_name("prepare-game.sh").resolve()
        (self.root / "json.py").write_text("raise RuntimeError('CWD import')")
        (self.root / "sitecustomize.py").write_text("raise RuntimeError('PYTHONPATH import')")
        for module in ("preparation_common", "preparation_assets", "preparation_store", "preparation_vdf", "preparation_binding"):
            (self.root / (module + ".py")).write_text("raise RuntimeError('untrusted sibling import')")
        fake = self.root / "python3"
        fake.write_text("#!/bin/sh\ntouch injected\nexit 99\n")
        fake.chmod(0o700)
        fake_dirname = self.root / "dirname"
        fake_dirname.write_text("#!/bin/sh\ntouch injected\nexit 99\n")
        fake_dirname.chmod(0o700)
        command = ["/bin/bash", str(script), "--registrations", str(self.added), "--steam-root", str(self.steam),
                   "--settings-root", str(self.settings), "--exe-root", str(self.exe_root), "--app-id", "-1"]
        before = self.snapshot()
        # Neither Python nor dirname may be selected through PATH.
        env = {**os.environ, "PYTHONPATH": str(self.root), "PATH": str(self.root) + ":/usr/bin:/bin"}
        inspected = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertEqual(json.loads(inspected.stdout)["mode"], "inspect")
        planned = subprocess.run(command + ["--plan"], cwd=self.root, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(planned.returncode, 2, planned.stderr)
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.root / "injected").exists())
        rejected = subprocess.run(command + ["--app-id", "bogus\u001bSECRET"], cwd=self.root, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(rejected.returncode, 1)
        self.assertNotIn("SECRET", rejected.stderr)
        self.assertNotIn("\u001b", rejected.stderr)
        for mode in ([], ["--plan"]):
            entry = subprocess.run(command + mode + ["--script-entry", "status"], cwd=self.root, env=env,
                                   capture_output=True, text=True, check=False)
            self.assertEqual(entry.returncode, 1, mode)
            self.assertIn("Input rejected", entry.stderr)

    def test_unknown_version_is_not_implicitly_supported(self):
        self.args.droiddeck_version = "future"
        report = self.report()
        self.assertIn("droiddeck-version-unknown-or-incompatible", report["blockers"])
        self.assertEqual(report["compatibility"]["status"], "unverified")

    def test_unknown_or_malformed_settings_fail_closed(self):
        for text in ('"InstallConfigStore" {', '"InstallConfigStore" {} garbage',
                     '"InstallConfigStore" {} "InstallConfigStore" {}'):
            self.config.write_text(text)
            with self.assertRaises(Invalid):
                self.report()
        self.write_json(self.settings / "games.json", {"version": 99, "games": {}})
        with self.assertRaises(Invalid):
            self.report()


class ValidationTests(unittest.TestCase):
    def test_invalid_ids(self):
        for value in (True, 0, "0", "01", "１２", "1; echo test", 2**32, -(2**31) - 1, "1\n"):
            with self.subTest(value=value), self.assertRaises(Invalid):
                ENGINE["app_id"](value)

    def test_profile_unknown_fields_types_schema_and_ids(self):
        for key, value in (("schema_version", 2), ("schema_version", True), ("revision", True),
                           ("profile_id", "../escape"), ("shell", "touch test"), ("dependencies", ["r", "r"]),
                           ("exe_sha256", "bad"), ("edition_status", "verified")):
            profile = copy.deepcopy(PROFILE)
            profile[key] = value
            with self.subTest(key=key), self.assertRaises(Invalid):
                ENGINE["validate_profile"](profile)

    def test_json_duplicate_keys_nonfinite_depth_size_and_string_limits(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp") as folder:
            path = Path(folder).resolve() / "input.json"
            for raw in ('{"x":1,"x":2}', '[NaN]', '[1.2]', '[' * 40 + '0' + ']' * 40,
                        json.dumps("x" * 4097), '{"x": "\\ud800"}', ' ' * (1024 * 1024 + 1)):
                path.write_text(raw)
                with self.subTest(size=len(raw)), self.assertRaises(Invalid):
                    ENGINE["load_json"](path)

    def test_recipe_unknown_handlers_commands_and_success_are_rejected(self):
        for key, value in (("handler", "shell"), ("command", "touch test"), ("status", "succeeded"), ("revision", False)):
            document = copy.deepcopy(RECIPES)
            document["dependencies"][0][key] = value
            with self.subTest(key=key), self.assertRaises(Invalid):
                ENGINE["validate_recipes"](document)

    def test_dependency_cycles_missing_references_duplicates_depth_and_count(self):
        for kind in ("cycle", "unknown", "duplicate", "depth", "count"):
            document = copy.deepcopy(RECIPES)
            entry = document["dependencies"][0]
            if kind in ("cycle", "unknown"):
                entry["requires"] = ["runtime" if kind == "cycle" else "missing"]
            elif kind == "duplicate":
                document["dependencies"].append(copy.deepcopy(entry))
            else:
                count = 17 if kind == "depth" else 129
                document["dependencies"] = [{**entry, "dependency_id": "node" + str(i),
                                             "requires": ["node" + str(i + 1)] if i + 1 < count else []}
                                            for i in range(count)]
            with self.subTest(kind=kind), self.assertRaises(Invalid):
                ENGINE["validate_recipes"](document)

    def test_dense_dag_is_bounded_and_dependencies_ordered(self):
        entry = RECIPES["dependencies"][0]
        document = {"schema_version": 1, "dependencies": [
            {**entry, "dependency_id": "node" + str(i), "requires": ["node" + str(j) for j in range(i)]}
            for i in range(16)]}
        recipes = ENGINE["validate_recipes"](document)
        profile = {**PROFILE, "dependencies": ["node15"]}
        self.assertEqual(ENGINE["dependency_order"](profile, recipes), ["node" + str(i) for i in range(16)])
        profile["dependencies"] = ["missing"]
        with self.assertRaises(Invalid):
            ENGINE["dependency_order"](profile, recipes)

    def test_report_size_is_bounded(self):
        with self.assertRaises(Invalid):
            ENGINE["display"]({"title": "x" * (1024 * 1024)})

    def test_change_during_read_is_rejected(self):
        before = argparse.Namespace(st_ino=1, st_dev=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
        after = argparse.Namespace(**{**vars(before), "st_mtime_ns": 2})
        with self.assertRaises(Invalid):
            ENGINE["unchanged"](before, after)


if __name__ == "__main__":
    unittest.main()
