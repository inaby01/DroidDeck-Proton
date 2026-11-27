#!/usr/bin/env python3
"""diagnose.sh: read-only comparison of DroidDeck's runtime with the bundle reference."""

import copy
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURES = runpy.run_path(str(Path(__file__).with_name("test_preparation_runtime.py")))
import preparation_runtime as runtime
from preparation_diagnose import compare, interactive_diagnose


class DiagnoseTests(unittest.TestCase):
    def setUp(self):
        FIXTURES["RuntimeTests"].setUp(self)
        source_patch = patch.dict(runtime.SOURCES, self.hashes, clear=True)
        source_patch.start()
        self.addCleanup(source_patch.stop)
        self.environment = {"DISPLAY": ":7", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": str(self.root / "private-run"),
                            "PULSE_SERVER": "unix:" + str(self.root / "private-pulse"), "PROOT_FP_KEY": "DUMMY_PROTOCOL_SECRET"}
        self.reference = runtime.inspect_runtime(self.root, self.environment)
        self.reference.update(view="current-root", auditor_architecture="aarch64")
        self.reference["process_observation_basis"]["umask"] = "0077"
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        (self.work / "share").mkdir(mode=0o700)
        (self.work / "home").mkdir(mode=0o700)

    def run_diagnose(self, environment=None):
        output = io.StringIO()
        status, saved = interactive_diagnose(self.work / "share", None, {"runtime_reference": self.reference},
                                             output_stream=output, environment=environment or self.environment,
                                             home=self.work / "home", runtime_root=self.root)
        report = json.loads(Path(saved).read_text()) if saved else None
        return status, output.getvalue(), report

    def test_no_difference_reports_passed_check(self):
        status, text, report = self.run_diagnose()
        self.assertEqual(status, 2)
        self.assertIn("違いはありません", text)
        self.assertEqual((report["mode"], report["status"], report["different"]), ("droiddeck-diagnosis", "reported", 0))
        self.assertEqual(report["tool_check"], {"result": "passed"})
        self.assertFalse(report["writes_other_than_result"])
        self.assertNotIn("DUMMY_PROTOCOL_SECRET", json.dumps(report))
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_changed_script_is_named_and_the_tool_check_stops(self):
        name = next(iter(runtime.SOURCES))
        (self.root / name).write_bytes(b"#!/bin/sh\n# updated by DroidDeck\n")
        status, text, report = self.run_diagnose()
        self.assertEqual(status, 2)
        self.assertIn("script: " + name, text)
        self.assertIn("止まります", text)
        different = [item for item in report["items"] if not item["same"]]
        self.assertEqual([(item["group"], item["name"]) for item in different], [("script", name)])
        self.assertEqual(report["tool_check"]["result"], "stopped")

    def test_environment_presence_difference(self):
        environment = dict(self.environment)
        del environment["PULSE_SERVER"]
        _, text, report = self.run_diagnose(environment)
        self.assertIn("environment: PULSE_SERVER", text)
        self.assertEqual(report["tool_check"]["result"], "stopped")

    def test_measurement_failure_is_saved(self):
        with patch.object(runtime, "inspect_runtime", side_effect=OSError("gone")):
            status, text, report = self.run_diagnose()
        self.assertEqual(status, 2)
        self.assertEqual((report["status"], report["error_class"]), ("stopped", "OSError"))
        self.assertIn("測れませんでした", text)

    def test_a_stop_outside_the_compared_items_shows_its_reason(self):
        environment = dict(self.environment, LD_PRELOAD="/elsewhere/libother.so")
        _, text, report = self.run_diagnose(environment)
        self.assertEqual(report["different"], 0)
        self.assertNotIn("LD_PRELOAD", {item["name"] for item in report["items"]})
        self.assertEqual(report["tool_check"]["result"], "stopped")
        self.assertIn("前提と違う項目: 0件（ツールの確認: 止まります）", text)
        self.assertIn("ツールの確認が止まる理由: unknown inherited preload", text)
        self.assertNotIn("/elsewhere", json.dumps(report))

    def test_a_malformed_reference_is_reported_not_raised(self):
        for reference in (None, {"runtime_sources": [], "libraries": "x", "process_observation_basis": 3}):
            with self.subTest(reference=reference):
                self.reference = reference
                status, _text, report = self.run_diagnose()
                self.assertEqual(status, 2)
                self.assertEqual(report["status"], "stopped" if reference is None else "reported")

    def test_a_bundle_cannot_put_values_or_paths_into_the_report(self):
        self.reference["environment_presence"]["DISPLAY"] = ":7 secret-display"
        self.reference["label"] = {"status": "measured", "sha256": "a" * 64, "path": "/opt/leak/label"}
        self.reference["runtime_sources"]["../../opt/leak/x"] = {"status": "matched", "sha256": "b" * 64}
        self.reference["os_release"] = {"ID": "ubuntu", "VERSION_ID": "26.04", "NAME": "/private/path"}
        _, _, report = self.run_diagnose()
        raw = json.dumps(report)
        for text in ("secret-display", "opt/leak", "/private/path"):
            self.assertNotIn(text, raw)

    def test_an_unusable_home_is_reported_without_measuring(self):
        (self.work / "linked-home").symlink_to(self.work / "home")
        output = io.StringIO()
        status, saved = interactive_diagnose(self.work / "share", None, {"runtime_reference": self.reference},
                                             output_stream=output, environment=self.environment,
                                             home=self.work / "linked-home", runtime_root=self.root)
        self.assertEqual((status, saved), (1, None))
        self.assertIn("ホームのフォルダーを確かめられないため", output.getvalue())
        self.assertEqual(list((self.work / "share").iterdir()), [])

    def test_compare_live_adds_architecture_and_umask(self):
        fresh = copy.deepcopy(self.reference)
        fresh["auditor_architecture"] = "x86_64"
        names = {item["name"]: item["same"] for item in compare(self.reference, fresh)}
        self.assertFalse(names["architecture"])
        self.assertTrue(names["umask"])
        self.assertNotIn("architecture", {item["name"] for item in compare(self.reference, fresh, live=False)})


if __name__ == "__main__":
    unittest.main()
