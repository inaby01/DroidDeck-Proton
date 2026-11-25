#!/usr/bin/env python3
"""Rendering checks for the slot files the preparation tool writes; nothing is installed."""

import json
import runpy
import unittest
from pathlib import Path

RENDER = runpy.run_path(str(Path(__file__).with_name("install-softdenchi.py")))["render_installation"]
VERSION = "11-12.8-softdenchi-r1"
ARCHIVE = "DroidDeck-Proton-" + VERSION + "-aarch64.tar.gz"
DIGEST = "a" * 128
SOURCE_VERSION = ("123 DroidDeck-Proton-" + VERSION + "\n").encode()


class RenderTests(unittest.TestCase):
    def test_cleanup_only_without_debug_log(self):
        files = RENDER(ARCHIVE, DIGEST, "cleanup", SOURCE_VERSION,
                       b'user_settings = {"PROTON_USE_WOW64": "1"}\n')
        settings = {}
        exec(compile(files["user_settings.py"], "user_settings.py", "exec"), settings)
        self.assertEqual(settings["user_settings"], {"PROTON_USE_WOW64": "1", "PROTON_SOFTDENCHI_CLEANUP": "1"})
        catalog = files["compatibilitytool.vdf"].decode()
        self.assertIn('"SoftDenchi-Proton-' + VERSION + '"', catalog)
        self.assertIn('"display_name" "SoftDenchi-Proton ' + VERSION + '"', catalog)
        receipt = json.loads(files["softdenchi-install.json"])
        self.assertEqual(receipt, {"source_archive": ARCHIVE, "sha512": DIGEST, "source_build": "DroidDeck-Proton-" + VERSION,
                                   "installed_dir": "SoftDenchi-Proton " + VERSION, "mode": "cleanup"})

    def test_other_upstream_versions_are_accepted(self):
        version = "11-14.1-softdenchi-r12"
        files = RENDER("DroidDeck-Proton-" + version + "-aarch64.tar.gz", DIGEST, "cleanup",
                       ("1 DroidDeck-Proton-" + version + "\n").encode())
        self.assertIn(b"PROTON_SOFTDENCHI_CLEANUP", files["user_settings.py"])

    def test_refusals(self):
        cases = [("DroidDeck-Proton-11-12.8-softdenchi3-r1-aarch64.tar.gz", DIGEST, "cleanup", SOURCE_VERSION),
                 ("DroidDeck-Proton-11-12.8-aarch64.tar.gz", DIGEST, "cleanup", SOURCE_VERSION),
                 (ARCHIVE, DIGEST, "observe", SOURCE_VERSION),
                 (ARCHIVE, DIGEST, "off", SOURCE_VERSION),
                 (ARCHIVE, "A" * 128, "cleanup", SOURCE_VERSION),
                 (ARCHIVE, DIGEST, "cleanup", b"123 DroidDeck-Proton-11-12.8-softdenchi-r2\n"),
                 (ARCHIVE, DIGEST, "cleanup", "text"),
                 (ARCHIVE, DIGEST, "cleanup", SOURCE_VERSION, b"x" * (1024 * 1024 + 1))]
        for args in cases:
            with self.subTest(args=args[:3]), self.assertRaises(ValueError):
                RENDER(*args)


if __name__ == "__main__":
    unittest.main()
