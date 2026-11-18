#!/usr/bin/env python3
"""Check one-command setup without starting Wine or changing real settings."""

import contextlib
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SETUP = runpy.run_path(str(Path(__file__).with_name("setup-softdenchi.py")))


class SetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.steam = self.home / ".local/share/Steam"
        self.settings = self.home / ".local/share/droiddeck-compat"
        (self.steam / "config").mkdir(parents=True)
        self.settings.mkdir(parents=True)
        self.config = self.steam / "config/config.vdf"
        self.config.write_text("original config")
        self.directory = self.steam / "compatibilitytools.d/SoftDenchi-Proton test"
        self.directory.mkdir(parents=True)
        self.choice = {"valve": False, "dir": self.directory.name}
        self.games = {"42": {"valve": False, "dir": "old"}, "99": {"valve": True, "dir": "keep"}}
        self.state = {"tools": [], "games_applied": dict(self.games), "default": "unchanged"}
        (self.settings / "games.json").write_text(json.dumps({"version": 1, "games": self.games}))
        (self.settings / "state.json").write_text(json.dumps(self.state))

        def read_games(directory):
            text = (Path(directory) / "games.json").read_text()
            return json.loads(text)["games"], text

        def write_games(requests, original, directory):
            file = Path(directory) / "games.json"
            if file.read_text() != original:
                return False
            file.write_text(json.dumps({"version": 1, "games": requests}))
            return True

        self.compatibility = {
            "steam_running": Mock(return_value=False), "live_helper_running": Mock(return_value=False),
            "locked": lambda _: contextlib.nullcontext(), "read_game_requests": read_games,
            "write_game_requests": write_games,
            "write_json": lambda path, value: Path(path).write_text(json.dumps(value)),
        }

    def test_selects_one_game_and_backs_up_without_changing_other_choices(self):
        backup = SETUP["select_game"](self.steam, self.settings, self.directory, "42", self.compatibility)
        games, _ = self.compatibility["read_game_requests"](self.settings)
        state = json.loads((self.settings / "state.json").read_text())
        self.assertEqual(games["42"], self.choice)
        self.assertEqual(games["99"], self.games["99"])
        self.assertNotIn("42", state["games_applied"])
        self.assertEqual(state["games_applied"]["99"], self.games["99"])
        self.assertEqual(state["default"], "unchanged")
        self.assertEqual((backup / "config.vdf").read_text(), "original config")
        self.assertEqual(json.loads((backup / "games.json").read_text())["games"], self.games)

    def test_legacy_state_marks_only_requested_game_as_pending(self):
        self.state.pop("games_applied")
        (self.settings / "state.json").write_text(json.dumps(self.state))
        SETUP["select_game"](self.steam, self.settings, self.directory, "42", self.compatibility)
        applied = json.loads((self.settings / "state.json").read_text())["games_applied"]
        self.assertEqual(applied, {"99": self.games["99"]})

    def test_running_session_prevents_install_and_changes(self):
        self.compatibility["steam_running"].return_value = True
        installer = {"install": Mock()}
        with self.assertRaises(ValueError):
            SETUP["setup"](Path("archive"), "42", "cleanup", self.home, self.compatibility, installer, Mock())
        installer["install"].assert_not_called()
        self.assertEqual(self.config.read_text(), "original config")

    def test_concurrent_choice_change_is_rejected(self):
        self.compatibility["write_game_requests"] = Mock(return_value=False)
        with self.assertRaises(ValueError):
            SETUP["select_game"](self.steam, self.settings, self.directory, "42", self.compatibility)
        self.assertEqual(json.loads((self.settings / "state.json").read_text()), self.state)

    def test_identical_choice_is_safe_to_reapply(self):
        self.games["42"] = self.choice
        (self.settings / "games.json").write_text(json.dumps({"version": 1, "games": self.games}))
        self.compatibility["write_game_requests"] = Mock(return_value=False)
        SETUP["select_game"](self.steam, self.settings, self.directory, "42", self.compatibility)
        state = json.loads((self.settings / "state.json").read_text())
        self.assertNotIn("42", state["games_applied"])

    def test_existing_install_is_reused_only_when_metadata_matches(self):
        installer = runpy.run_path(str(Path(__file__).with_name("install-softdenchi.py")))
        version = "11-12.8-softdenchi3-cleanup2"
        archive = self.home / ("DroidDeck-Proton-" + version + "-aarch64.tar.gz")
        directory = self.steam / "compatibilitytools.d" / ("SoftDenchi-Proton " + version)
        directory.mkdir()
        (directory / "softdenchi-install.json").write_text(json.dumps({
            "source_archive": archive.name, "mode": "cleanup", "sha512": "fixture"}))
        (directory / "version").write_text("123 DroidDeck-Proton-" + version)
        (directory / "proton").write_text("keep")
        installer["verify"] = Mock(return_value="fixture")
        installer["install"] = Mock()
        result = SETUP["install_or_reuse"](archive, directory.parent, "cleanup", installer)
        self.assertEqual(result, directory)
        installer["install"].assert_not_called()
        with self.assertRaises(ValueError):
            SETUP["install_or_reuse"](archive, directory.parent, "observe", installer)
        self.assertEqual((directory / "proton").read_text(), "keep")

    def test_prepare_tool_leaves_selection_and_sync_for_later(self):
        before = (self.settings / "games.json").read_bytes()
        state = (self.settings / "state.json").read_bytes()
        with patch.dict(SETUP["prepare_tool"].__globals__, install_or_reuse=Mock(return_value=self.directory)):
            result = SETUP["prepare_tool"](Path("archive"), "cleanup", self.home, self.compatibility, {})
        self.assertEqual(result, self.directory)
        self.assertEqual((self.settings / "games.json").read_bytes(), before)
        self.assertEqual((self.settings / "state.json").read_bytes(), state)
        self.assertFalse((self.settings / "backups").exists())

    def test_finish_binding_is_separate_from_installation(self):
        self.compatibility.update({"tool_catalog": Mock(return_value=[]), "requested_tool": Mock(return_value="wanted"),
                                   "read_config_mapping": Mock(return_value={"42": "wanted"})})
        sync = Mock()
        with patch.dict(SETUP["finish_binding"].__globals__, install_or_reuse=Mock(side_effect=AssertionError("install forbidden"))):
            result = SETUP["finish_binding"]("42", self.directory, self.home, self.compatibility, sync)
        sync.assert_called_once_with(self.steam)
        self.assertTrue(result["selection_verified"])

    def test_failed_synchronization_is_not_reported_as_success(self):
        self.compatibility.update({
            "tool_catalog": Mock(return_value=[]),
            "requested_tool": Mock(return_value="wanted"),
            "read_config_mapping": Mock(return_value={"42": "old"}),
        })
        with patch.dict(SETUP["setup"].__globals__, install_or_reuse=lambda *args: self.directory), \
                self.assertRaisesRegex(ValueError, "一致しません"):
            SETUP["setup"](Path("archive"), "42", "cleanup", self.home,
                           self.compatibility, {}, Mock())


if __name__ == "__main__":
    unittest.main()
