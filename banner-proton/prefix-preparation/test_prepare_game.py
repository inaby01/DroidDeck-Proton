#!/usr/bin/env python3
"""Synthetic tests: never access a real game, account, prefix or installer."""

import argparse
import json
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
Invalid = ENGINE["Invalid"]
COMMON = sys.modules["preparation_common"].__dict__
TEMP = "/private/tmp" if Path("/private/tmp").exists() else "/tmp"


def pe(machine=0x14C, magic=0x10B):
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    struct.pack_into("<H", data, 84, 2)
    struct.pack_into("<H", data, 88, magic)
    return bytes(data)


class SettingsFixture(unittest.TestCase):
    """Disposable Steam/settings roots and one registration, shared by other test files
    (``SettingsFixture.setUp(self)`` in their own setUp). Not a test case itself."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prefix-test-", dir=TEMP)
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

    def write_json(self, path, data):
        path.write_text(json.dumps(data, ensure_ascii=False))

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns)
                if path.is_file() else "directory" for path in self.root.rglob("*")}


class CommandLineTests(unittest.TestCase):
    """prepare_game.py is the build-time tool (1.0.1): script emission and the runtime audit only."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prefix-test-", dir=TEMP)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns)
                if path.is_file() else "directory" for path in self.root.rglob("*")}

    def test_symlink_hardlink_fifo_and_environment_file_inputs_rejected(self):
        source = self.root / "input.json"
        source.write_text("{}")
        for name, setup in (("link.json", lambda p: p.symlink_to(source)),
                            ("hard.json", lambda p: os.link(source, p)),
                            ("fifo.json", os.mkfifo),
                            (".env.local", lambda p: p.write_text("PRIVATE"))):
            with self.subTest(name=name):
                path = self.root / name
                setup(path)
                with self.assertRaises(Invalid):
                    ENGINE["load_json"](path)
                path.unlink()

    def test_control_characters_are_escaped(self):
        text = ENGINE["display"]({"title": "日本語\n\u001b[31m\u202e"})
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("日本語", text)
        self.assertIn("\\u001b", text)
        self.assertIn("\\u202e", text)

    def test_cli_isolated_from_cwd_path_and_pythonpath(self):
        script = Path(__file__).with_name("prepare-game.sh").resolve()
        (self.root / "json.py").write_text("raise RuntimeError('CWD import')")
        (self.root / "sitecustomize.py").write_text("raise RuntimeError('PYTHONPATH import')")
        for module in ("preparation_common", "preparation_runtime", "preparation_selection", "preparation_store"):
            (self.root / (module + ".py")).write_text("raise RuntimeError('untrusted sibling import')")
        fake = self.root / "python3"
        fake.write_text("#!/bin/sh\ntouch injected\nexit 99\n")
        fake.chmod(0o700)
        fake_dirname = self.root / "dirname"
        fake_dirname.write_text("#!/bin/sh\ntouch injected\nexit 99\n")
        fake_dirname.chmod(0o700)
        before = self.snapshot()
        # Neither Python nor dirname may be selected through PATH.
        env = {**os.environ, "PYTHONPATH": str(self.root), "PATH": str(self.root) + ":/usr/bin:/bin"}

        def run(*arguments):
            return subprocess.run(["/bin/bash", str(script), *arguments], cwd=self.root, env=env,
                                  capture_output=True, text=True, check=False)

        audit = run("--emit-runtime-audit")
        self.assertEqual(audit.returncode, 0, audit.stderr)
        self.assertTrue(audit.stdout)
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.root / "injected").exists())
        # The earlier modes are gone, and every mode needs its own inputs only.
        for arguments in ((), ("--inspect",), ("--plan",), ("--emit-runtime-audit", "--runtime-root", str(self.root)),
                          ("--emit-selection-script",), ("--inspect-runtime",),
                          ("--emit-runtime-audit", "--script-entry", "status")):
            with self.subTest(arguments=arguments):
                result = run(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(result.stdout)
        rejected = run("--emit-selection-script", "--selection-config", str(self.root / "bogus\u001bSECRET.json"))
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("Input rejected", rejected.stderr)
        self.assertNotIn("SECRET", rejected.stderr)
        self.assertNotIn("\u001b", rejected.stderr)

    def test_a_bundle_that_is_not_operational_is_rejected(self):
        bundle = self.root / "bundle.json"
        bundle.write_text(json.dumps({"schema_version": 1}))
        result = subprocess.run(["/bin/bash", str(Path(__file__).with_name("prepare-game.sh").resolve()),
                                 "--emit-selection-script", "--selection-config", str(bundle)],
                                cwd=self.root, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.stdout)


class ValidationTests(unittest.TestCase):
    def test_invalid_ids(self):
        for value in (True, 0, "0", "01", "１２", "1; echo test", 2**32, -(2**31) - 1, "1\n"):
            with self.subTest(value=value), self.assertRaises(Invalid):
                COMMON["app_id"](value)

    def test_pe_architecture_and_malformed_headers(self):
        import io
        assets = sys.modules["preparation_assets"] if "preparation_assets" in sys.modules else __import__("preparation_assets")
        for machine, magic, expected in ((0x14C, 0x10B, "x86"), (0x8664, 0x20B, "x86_64"), (0xAA64, 0x20B, "arm64")):
            data = pe(machine, magic)
            self.assertEqual(assets.pe_machine(io.BytesIO(data), len(data)), expected)
        for data in (b"MZ", b"bad", pe(0xAA64, 0x10B), pe()[:89]):
            with self.subTest(data=data[:8]), self.assertRaises(Invalid):
                assets.pe_machine(io.BytesIO(data), len(data))

    def test_json_duplicate_keys_nonfinite_depth_size_and_string_limits(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as folder:
            path = Path(folder).resolve() / "input.json"
            for raw in ('{"x":1,"x":2}', '[NaN]', '[1.2]', '[' * 40 + '0' + ']' * 40,
                        json.dumps("x" * 4097), '{"x": "\\ud800"}', ' ' * (1024 * 1024 + 1)):
                path.write_text(raw)
                with self.subTest(size=len(raw)), self.assertRaises(Invalid):
                    ENGINE["load_json"](path)

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
