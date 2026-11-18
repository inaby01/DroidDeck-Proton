#!/usr/bin/env python3
"""Preflight boundaries, native probes and standalone delivery, no actual game."""

import contextlib
import ctypes
import errno
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ENGINE = runpy.run_path(str(HERE / "prepare_game.py"))
import preparation_preflight as preflight
from preparation_common import Invalid

LINUX = sys.platform == "linux"


class PreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.steam = self.root / "Steam"
        self.settings = self.root / "settings"
        self.steam.mkdir()
        self.settings.mkdir()
        prefix = self.steam / "steamapps/compatdata/42"
        prefix.mkdir(parents=True)
        self.sentinel = prefix / "existing-prefix-sentinel"
        self.sentinel.write_bytes(b"DO_NOT_READ_OR_MODIFY")
        (self.settings / "games.json").write_bytes(b"DUMMY_PRIVATE_SETTINGS")

    def inspect(self, probe=False, env=None):
        return preflight.inspect_preflight(self.steam, self.settings, probe, {} if env is None else env)

    def snapshot(self):
        return {str(p): (p.lstat().st_mode, p.lstat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob("*")}

    def test_default_is_read_only_and_does_not_launch_or_load_native_libraries(self):
        before = self.snapshot()
        with patch("subprocess.Popen", side_effect=AssertionError("no child")), \
             patch("ctypes.CDLL", side_effect=AssertionError("no dynamic load")), \
             patch("os.mkdir", side_effect=AssertionError("no writes")):
            report = self.inspect()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(report["writes"], [])
        self.assertEqual(report["probes"]["status"], "not-requested")
        self.assertFalse(report["prefix_contents_read"])
        self.assertFalse(report["settings_contents_read"])
        self.assertFalse(report["preparation_complete"])

    def test_path_and_capacity_report_use_existing_ancestor_without_creating_tools(self):
        report = self.inspect()
        self.assertFalse(report["paths"]["tools"]["exists"])
        self.assertEqual(report["paths"]["tools"]["existing_ancestor"], str(self.steam))
        self.assertGreaterEqual(report["paths"]["tools"]["available_bytes"], 0)
        self.assertEqual(report["paths"]["tools"]["write_permission"], "unverified")
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_root_overlap_and_symlink_paths_are_rejected(self):
        with self.assertRaises(Invalid):
            preflight.inspect_preflight(self.steam, self.steam / "settings")
        link = self.root / "linked"
        link.symlink_to(self.steam)
        with self.assertRaises(Invalid):
            preflight.inspect_preflight(link, self.settings)

    def test_missing_steam_skips_probes_without_falling_back_to_tmp(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no child")):
            report = preflight.inspect_preflight(self.root / "absent", self.settings, True, {})
        self.assertEqual(report["probes"]["status"], "requires-linux-and-existing-steam-root")
        self.assertEqual(report["writes"], [])

    @unittest.skipUnless(LINUX, "native preflight requires Linux")
    def test_native_temporary_probes_observe_child_rename_and_preserve_existing_data(self):
        before = self.snapshot()
        report = self.inspect(True)
        probes = report["probes"]
        self.assertEqual(probes["rename"]["status"], "non-replacing-rename-supported")
        self.assertTrue(probes["rename"]["empty_collision_preserved"])
        self.assertEqual(probes["process"]["status"], "native-child-observed-and-cleared")
        self.assertTrue(probes["process"]["child_exited"])
        self.assertFalse(probes["process"]["device_namespace_verified"])
        self.assertEqual(probes["cleanup"], "removed-own-empty-probe-directory")
        self.assertEqual(report["probe_filesystem_scope"], "steam-root-tools-parent-absent")
        self.assertEqual(len(report["writes"]), 1)
        # Creating/removing a child legitimately changes the Steam directory mtime.
        after = self.snapshot()
        for name in before:
            if name != str(self.steam):
                self.assertEqual(before[name], after[name])
        self.assertEqual(set(before), set(after))
        for value in ("DO_NOT_READ_OR_MODIFY", "DUMMY_PRIVATE_SETTINGS"):
            self.assertNotIn(value, json.dumps(report))

    @unittest.skipUnless(LINUX, "native rename requires Linux")
    def test_probe_runs_on_existing_tool_parent_filesystem(self):
        tools = self.steam / "compatibilitytools.d"
        tools.mkdir()
        report = self.inspect(True)
        self.assertEqual(report["probe_filesystem_scope"], "existing-tool-parent")
        self.assertEqual(Path(report["probes"]["temporary_path"]).parent, tools)
        self.assertEqual(list(tools.iterdir()), [])

    @unittest.skipUnless(LINUX, "native temporary probes require Linux")
    def test_unsafe_probe_parent_is_refused_before_creating_anything(self):
        self.steam.chmod(0o777)
        try:
            report = self.inspect(True)
            self.assertEqual(report["probes"]["cleanup"], "not-created")
            self.assertEqual(report["writes"], [])
            self.assertEqual(list(self.steam.glob(".droiddeck-preflight-*")), [])
        finally:
            self.steam.chmod(0o755)

    @unittest.skipUnless(LINUX, "native temporary probes require Linux")
    def test_unsupported_rename_preserves_errno_and_never_replaces(self):
        def unsupported(*_):
            ctypes.set_errno(errno.EINVAL)
            return -1
        with patch.object(preflight, "_rename_function", return_value=unsupported):
            report = self.inspect(True)
        self.assertEqual(report["probes"]["rename"]["errno"], errno.EINVAL)
        self.assertEqual(report["probes"]["cleanup"], "removed-own-empty-probe-directory")
        self.assertEqual(report["probes"]["process"]["status"], "native-child-observed-and-cleared")

    @unittest.skipUnless(LINUX, "native temporary probes require Linux")
    def test_unknown_native_child_fields_are_not_promoted_to_verified(self):
        with patch.object(preflight, "_child_fields", return_value={"status": "unavailable", "stage": "child-environ", "errno": errno.EACCES}):
            report = self.inspect(True)
        process = report["probes"]["process"]
        self.assertEqual(process["status"], "unavailable")
        self.assertEqual(process["child_fields"]["errno"], errno.EACCES)
        self.assertTrue(process["child_exited"])
        self.assertFalse(report["preparation_complete"])

    @unittest.skipUnless(LINUX, "native temporary probes require Linux")
    def test_unexpected_temporary_contents_are_retained_without_recursive_deletion(self):
        original = preflight._rename_probe
        def extra(fd, guard, objects):
            result = original(fd, guard, objects)
            out = os.open("unexpected", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
            os.write(out, b"KEEP")
            os.close(out)
            return result
        with patch.object(preflight, "_rename_probe", side_effect=extra):
            report = self.inspect(True)
        self.assertEqual(report["probes"]["cleanup"], "retained-needs-inspection")
        folder = Path(report["probes"]["temporary_path"])
        self.assertEqual((folder / "unexpected").read_bytes(), b"KEEP")
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(LINUX, "native temporary probes require Linux")
    def test_replaced_fixed_probe_object_is_not_deleted(self):
        original = preflight._rename_probe
        def replace_object(fd, guard, objects):
            result = original(fd, guard, objects)
            os.rename("collision", "detached", src_dir_fd=fd, dst_dir_fd=fd)
            os.mkdir("collision", 0o700, dir_fd=fd)
            return result
        with patch.object(preflight, "_rename_probe", side_effect=replace_object):
            report = self.inspect(True)
        self.assertEqual(report["probes"]["cleanup"], "retained-needs-inspection")
        self.assertTrue((Path(report["probes"]["temporary_path"]) / "collision").is_dir())

    def test_gui_probe_rejects_network_display_without_launching(self):
        for display in ("example.invalid:0", "localhost:10.0", ":invalid", ""):
            with self.subTest(display=display), patch("subprocess.Popen", side_effect=AssertionError("no remote GUI")):
                self.assertEqual(preflight._gui_probe({"DISPLAY": display})["status"], "unset-or-unsupported-local-display")

    def test_gui_probe_records_only_outcome_and_strips_unrelated_loader_values(self):
        child = SimpleNamespace(returncode=0, wait=lambda timeout: None)
        env = {"DISPLAY": ":7", "HOME": "/private/home", "XAUTHORITY": "/private/gui-secret", "PROOT_FP_KEY": "DUMMY_SECRET",
               "LD_PRELOAD": "/private/unknown.so", "PYTHONPATH": "/private/imports"}
        with patch("subprocess.Popen", return_value=child) as popen:
            result = preflight._gui_probe(env)
        self.assertEqual(result["status"], "x11-display-opened-and-closed")
        self.assertFalse(result["window_created"])
        self.assertFalse(result["wine_gui_verified"])
        for key in ("PROOT_FP_KEY", "LD_PRELOAD", "PYTHONPATH"):
            self.assertNotIn(key, popen.call_args.kwargs["env"])
        for value in ("DUMMY_SECRET", "/private/gui-secret", "/private/home"):
            self.assertNotIn(value, json.dumps(result))

    @unittest.skipUnless(LINUX, "temporary cleanup requires Linux")
    def test_invalid_gui_authority_is_rejected_without_skipping_probe_cleanup(self):
        with patch.object(preflight, "_gui_probe", wraps=preflight._gui_probe):
            report = self.inspect(True, {"DISPLAY": ":7", "XAUTHORITY": str(self.root / ".env.private")})
        self.assertEqual(report["probes"]["gui"]["stage"], "gui-input")
        self.assertEqual(report["probes"]["cleanup"], "removed-own-empty-probe-directory")

    def test_gui_failures_and_deadline_are_distinct_from_success(self):
        for code, status in ((2, "x11-display-open-failed"), (3, "system-xlib-unavailable"), (-14, "gui-probe-failed-or-deadline")):
            with self.subTest(code=code), patch("subprocess.Popen", return_value=SimpleNamespace(returncode=code, wait=lambda timeout: None)):
                self.assertEqual(preflight._gui_probe({"DISPLAY": ":7"})["status"], status)

    @unittest.skipUnless(LINUX, "native GUI child deadline requires Linux")
    def test_native_gui_probe_without_server_reports_failure_without_window(self):
        result = preflight._gui_probe({"DISPLAY": ":98765", "HOME": str(self.root)})
        self.assertIn(result["status"], ("x11-display-open-failed", "system-xlib-unavailable", "gui-probe-failed-or-deadline"))
        self.assertFalse(result["window_created"])

    def test_cli_has_separate_preflight_mode_and_requires_opt_in(self):
        with patch("sys.argv", ["prepare_game.py", "--inspect-preflight", "--steam-root", str(self.steam), "--settings-root", str(self.settings)]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = ENGINE["main"]()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["writes"], [])
        with patch("sys.argv", ["prepare_game.py", "--inspect", "--probe-temporary"]), contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit) as result:
            ENGINE["main"]()
        self.assertEqual(result.exception.code, 1)

    def test_emitter_is_inert_and_rejects_inputs(self):
        with patch("sys.argv", ["prepare_game.py", "--emit-preflight-script"]), \
             patch("subprocess.Popen", side_effect=AssertionError("emitter must not execute")), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ENGINE["main"](), 0)
        self.assertTrue(output.getvalue().startswith("#!/bin/bash\n"))
        with patch("sys.argv", ["prepare_game.py", "--emit-preflight-script", "--steam-root", str(self.steam)]), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            ENGINE["main"]()
        self.assertEqual(result.exception.code, 1)

    def test_standalone_script_uses_embedded_trusted_modules_and_no_bytecode(self):
        script = self.root / "inspect-preflight.sh"
        script.write_text(preflight.preflight_script())
        subprocess.run(["/bin/bash", "-n", str(script)], check=True, capture_output=True)
        (self.root / "preparation_common.py").write_text("raise RuntimeError('untrusted CWD must not import')\n")
        env = {**os.environ, "HOME": str(self.root), "PYTHONPATH": str(self.root)}
        completed = subprocess.run(["/bin/bash", str(script), "--steam-root", str(self.steam), "--settings-root", str(self.settings)],
                                   check=False, cwd=self.root, env=env, capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["writes"], [])
        self.assertEqual(report["probes"]["status"], "not-requested")
        self.assertEqual(list(self.root.rglob("__pycache__")), [])

    @unittest.skipUnless(LINUX, "standalone native probes require Linux")
    def test_standalone_script_explicit_probe_produces_report_and_cleans_temporary_directory(self):
        script = self.root / "inspect-preflight.sh"
        script.write_text(preflight.preflight_script())
        completed = subprocess.run(["/bin/bash", str(script), "--probe-temporary", "--steam-root", str(self.steam), "--settings-root", str(self.settings)],
                                   check=False, env={"HOME": str(self.root), "PATH": "/usr/bin:/bin"}, capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["probes"]["rename"]["status"], "non-replacing-rename-supported")
        self.assertEqual(result["probes"]["process"]["status"], "native-child-observed-and-cleared")
        self.assertEqual(result["probes"]["cleanup"], "removed-own-empty-probe-directory")
        self.assertFalse(result["preparation_complete"])

    def test_standalone_rejection_does_not_echo_private_paths(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = preflight.preflight_main(["--steam-root", str(self.root / ".env.private"), "--settings-root", str(self.settings)])
        self.assertEqual(code, 1)
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["stage"], "preflight-input")


if __name__ == "__main__":
    unittest.main()
