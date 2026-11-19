#!/usr/bin/env python3
"""Target-only binding against disposable settings, never a real game or helper."""

import ast
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
ENGINE = FIXTURES["ENGINE"]
import preparation_binding as binding
from preparation_common import MAX_DEPTH, MAX_JSON, MAX_STRING, Invalid
from preparation_store import PrivateStore
from preparation_vdf import Document, parse_vdf, patch_game_mapping


class BindingTests(unittest.TestCase):
    write_json = FIXTURES["InspectionTests"].write_json
    snapshot = FIXTURES["InspectionTests"].snapshot

    def setUp(self):
        FIXTURES["InspectionTests"].setUp(self)
        self.key = "4294967295"
        self.directory = "Example Proton"
        self.tool = self.steam / "compatibilitytools.d" / self.directory
        self.tool.mkdir(parents=True)
        (self.tool / "compatibilitytool.vdf").write_text('"compatibilitytools" { "compat_tools" { "Example-Proton" { "install_path" "." "from_oslist" "windows" "to_oslist" "linux" } } }')
        (self.tool / "toolmanifest.vdf").write_text('"manifest" { "commandline" "/droiddeck-proton-wrap %verb%" }')
        for name in ("proton", "droiddeck-proton-wrap"):
            file = self.tool / name
            file.write_text("#!/bin/sh\nexit 0\n")
            file.chmod(0o755)
        self.games = self.settings / "games.json"
        self.state = self.settings / "state.json"
        old_games = json.loads(self.games.read_text())
        old_games["games"][self.key] = {"valve": False, "dir": "Prior Target"}
        self.write_json(self.games, old_games)
        self.original_state = {"default": "default-tool", "written": "default-tool", "source": "app",
                               "tools": [{"name": "existing-tool"}], "other-secret": "DUMMY_STATE_SECRET",
                               "games_applied": {"99": {"valve": True, "dir": "Prior Choice"}},
                               "auto": {self.key: "actual-tool", "99": "old-auto"},
                               "picked": ["99"], "native_choices": ["99", self.key]}
        self.write_json(self.state, self.original_state)
        self.config.write_text(self.config.read_text().replace('"Secret"', '// preserved comment\n "Secret"'))
        self.store_root = self.root / "private-store"
        self.lock_key = hashlib.sha256(str(self.steam / "steamapps/compatdata" / self.key).encode()).hexdigest()

    def plan(self):
        return binding.plan_binding(self.steam, self.settings, self.key, self.directory)

    def apply(self, plan=None, ready=None):
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
            return binding.apply_binding(plan or self.plan(), self.steam, self.settings, store,
                                         ready or (lambda: {"target": True, "dependencies": True, "payload": True, "stopped": True}))

    def record(self):
        paths = sorted((self.store_root / "bindings").glob("binding-*.json"))
        return json.loads(paths[-1].read_text())

    def test_plan_is_read_only_and_has_no_raw_settings_or_secret(self):
        before = self.snapshot()
        with patch("subprocess.run", side_effect=AssertionError("no process")), patch("runpy.run_path", side_effect=AssertionError("no helper")):
            plan = self.plan()
        self.assertEqual(before, self.snapshot())
        summary = plan.summary()
        self.assertEqual(summary["writes"], [])
        self.assertEqual(summary["other_pending_count"], 1)
        self.assertFalse(summary["default_changed"])
        self.assertFalse(summary["other_games_changed"])
        self.assertNotIn("DUMMY", json.dumps(summary))
        self.assertNotIn("DUMMY", repr(plan))
        self.assertIn("payload-integrity-unverified", summary["blockers"])

    def test_diagnostic_rejections_never_echo_raw_errors_or_config(self):
        self.games.write_text('{"version": 1, "games": {"PRIVATE_ID": {"SECRET": "value"}}}')
        self.state.write_text('{"games_applied": null, "picked": ["SECRET_ID"]}')
        before = self.snapshot()
        report = binding.inspect_binding_inputs(self.steam, self.settings, self.key, self.directory)
        self.assertEqual(report["checks"]["games-schema"]["status"], "rejected")
        self.assertEqual(report["checks"]["state-games_applied"]["status"], "rejected")
        self.assertEqual(report["checks"]["state-picked"]["status"], "rejected")
        self.assertFalse(report["coherent_plan"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(before, self.snapshot())
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("PRIVATE_ID", json.dumps(report))
        for error in (Invalid("SECRET_EXCEPTION"), OSError(5, "SECRET_PATH")):
            self.assertNotIn("SECRET", json.dumps(binding.binding_error(error)))

    def test_diagnostic_tool_read_identifies_file_without_exposing_contents(self):
        (self.tool / "proton").write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(Invalid) as raised:
            self.plan()
        self.assertEqual(raised.exception.preparation_check, "binding-tool-read-proton")
        report = binding.inspect_binding_inputs(self.steam, self.settings, self.key, self.directory)
        self.assertEqual(report["checks"]["registered-tool"]["check"], "binding-tool-read-proton")
        self.assertEqual(report["checks"]["target-mapping"]["status"], "accepted")

    def test_preserves_long_unrelated_values_in_binding_plan_and_guarded_writer(self):
        value = "DUMMY_PRIVATE_VALUE_" * 500
        self.config.write_text(self.config.read_text().replace('"Secret"', '"Untouched" "' + value + '" "Secret"'))
        before = self.config.read_bytes()
        plan = self.plan()
        self.assertIn(value.encode(), plan.after["config"])
        self.assertEqual(patch_game_mapping(plan.after["config"], self.key, "Example-Proton"), plan.after["config"])
        legacy = binding.inspect_steam_config(self.steam)
        self.assertEqual(legacy["checks"]["legacy-string-limit"]["condition"], "vdf-string-length")
        self.assertEqual(legacy["checks"]["preserve-bounded-values"]["status"], "accepted")
        self.assertEqual(legacy["input_sha256"], hashlib.sha256(before).hexdigest())
        self.assertNotIn(value, json.dumps(legacy))
        self.assertNotIn(value, json.dumps(plan.summary()))
        self.apply(plan)
        self.assertEqual(self.config.read_bytes(), plan.after["config"])

    def test_long_vdf_keys_still_rejected_and_default_parser_stays_strict(self):
        for raw in (('"' + 'k' * (MAX_STRING + 1) + '" "v"').encode(),):
            with self.assertRaises(Invalid):
                Document(raw, value_limit=MAX_JSON)
        with self.assertRaises(Invalid):
            Document(('"key" "' + 'v' * (MAX_STRING + 1) + '"').encode())
        for limit in (MAX_JSON + 1, MAX_STRING - 1, True):
            with self.assertRaises(Invalid):
                Document(b'"key" "value"', value_limit=limit)

    def test_bounded_preservation_still_rejects_size_depth_duplicates_and_bad_syntax(self):
        for raw in (b' ' * (MAX_JSON + 1),
                    (('"k" {' * (MAX_DEPTH + 2)) + ('}' * (MAX_DEPTH + 2))).encode(),
                    b'"key" "x" "key" "y"', b'"key" unquoted', b'}'):
            with self.assertRaises(Invalid):
                Document(raw, value_limit=MAX_JSON)

    def test_every_vdf_validation_has_a_fixed_diagnostic_code(self):
        tree = ast.parse(Path(binding.__file__).with_name("preparation_vdf.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "require":
                message = ast.literal_eval(node.args[1])
                with self.subTest(message=message):
                    self.assertNotEqual(binding.binding_error(Invalid(message))["condition"], "input-rejected")

    def test_parser_diagnostic_handles_missing_and_non_utf8_without_exposing_data(self):
        self.config.unlink()
        self.assertIn("error", binding.inspect_steam_config(self.steam))
        self.config.write_bytes(b'"PRIVATE_KEY" "\xffPRIVATE_VALUE"')
        result = binding.inspect_steam_config(self.steam)
        for item in result["checks"].values():
            self.assertEqual(item["condition"], "text-encoding")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_changes_only_target_mapping_and_preserves_other_config_bytes(self):
        plan = self.plan()
        before, after = parse_vdf(plan.before["config"]), parse_vdf(plan.after["config"])
        for value in (before, after):
            node = value
            for name in binding.STEAM_PATH:
                node = node[name]
            node["CompatToolMapping"].pop(self.key)
        self.assertEqual(before, after)
        prefix, suffix = plan.before["config"].split(b'"actual-tool"')
        self.assertEqual(plan.after["config"], prefix + b'"Example-Proton"' + suffix)
        self.assertIn(b"// preserved comment", plan.after["config"])

    def test_target_only_apply_preserves_pending_other_choices_defaults_and_history(self):
        before_games = json.loads(self.games.read_text())
        request = self.settings / "request.json"
        request.write_text('{"version":1,"dir":"pending-global-choice"}')
        before_request = request.read_bytes()
        plan = self.plan()
        result = self.apply(plan)
        self.assertEqual(result["status"], "binding-verified")
        self.assertFalse(result["preparation_complete"])
        games, state = json.loads(self.games.read_text()), json.loads(self.state.read_text())
        self.assertEqual(games["games"]["99"], before_games["games"]["99"])
        self.assertEqual(state["games_applied"]["99"], self.original_state["games_applied"]["99"])
        self.assertEqual(state["auto"], {"99": "old-auto"})
        self.assertEqual(state["native_choices"], ["99"])
        self.assertEqual(state["picked"], ["99", self.key])
        for field in ("tools", "default", "written", "source", "other-secret"):
            self.assertEqual(state[field], self.original_state[field])
        self.assertEqual(request.read_bytes(), before_request)
        self.assertEqual(state["games_applied"][self.key], games["games"][self.key])
        self.assertFalse((self.steam / "steamapps/compatdata").exists())

    def test_legacy_applied_history_is_materialized_without_losing_other_games(self):
        state = {"tools": [], "default": "keep"}
        self.write_json(self.state, state)
        old_games = json.loads(self.games.read_text())["games"]
        self.assertEqual(self.plan().other_pending_count, 0)
        self.apply()
        state = json.loads(self.state.read_text())
        self.assertEqual(state["games_applied"]["99"], old_games["99"])
        self.assertEqual(state["default"], "keep")

    def test_missing_games_and_state_can_be_created_without_global_default_changes(self):
        self.games.unlink()
        self.state.unlink()
        before = self.config.read_bytes()
        self.apply()
        self.assertEqual(set(json.loads(self.games.read_text())["games"]), {self.key})
        self.assertNotIn("default", json.loads(self.state.read_text()))
        self.assertEqual(self.config.read_bytes().split(b'"Example-Proton"'), before.split(b'"actual-tool"'))

    def test_absent_auto_history_preserves_implicit_stock_followers_except_target(self):
        state = copy.deepcopy(self.original_state)
        state.pop("auto")
        self.write_json(self.state, state)
        raw = self.config.read_text().replace('"4294967295"', '"88" {"name" "droiddeck-proton-arm64"}\n"4294967295"')
        self.config.write_text(raw)
        after = json.loads(self.plan().after["state"])
        self.assertEqual(after["auto"], {"88": "droiddeck-proton-arm64"})

    def test_pending_clear_request_is_counted_and_preserved(self):
        games = json.loads(self.games.read_text())
        games["games"]["77"] = None
        self.write_json(self.games, games)
        self.assertEqual(self.plan().other_pending_count, 2)
        self.apply()
        self.assertIsNone(json.loads(self.games.read_text())["games"]["77"])

    def test_backup_is_private_and_contains_exact_original_settings(self):
        plan = self.plan()
        result = self.apply(plan)
        backup = self.store_root / "backups" / result["binding_id"]
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        for name, original in plan.before.items():
            file = backup / (name + ".backup")
            self.assertEqual(file.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        self.assertNotIn("DUMMY", json.dumps(self.record()))

    def test_unverified_prerequisite_stops_before_settings_lock_or_backup(self):
        for field in ("target", "dependencies", "payload", "stopped"):
            before = {path: path.read_bytes() for path in (self.games, self.state, self.config)}
            with self.subTest(field=field), self.assertRaises(Invalid):
                self.apply(ready=lambda field=field: {key: key != field for key in ("target", "dependencies", "payload", "stopped")})
            for path, raw in before.items():
                self.assertEqual(path.read_bytes(), raw)
            self.assertFalse((self.settings / "lock").exists())
            self.assertFalse((self.store_root / "backups").exists())

    def test_no_cli_flags_can_assert_dependency_or_payload_verification(self):
        command = ["/bin/bash", str(Path(__file__).with_name("prepare-game.sh").resolve()), "--dependencies-verified"]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.store_root.exists())

    def test_stale_config_choice_state_or_payload_stops_before_settings_write(self):
        for path in (self.config, self.games, self.state, self.tool / "proton"):
            plan = self.plan()
            before = path.read_bytes()
            path.write_bytes(before + b"\n")
            with self.subTest(path=path.name), self.assertRaises(Invalid):
                self.apply(plan)
            self.assertEqual(path.read_bytes(), before + b"\n")
            self.assertFalse((self.store_root / "bindings").exists())
            path.write_bytes(before)

    def test_ready_callback_is_rechecked_before_each_change(self):
        calls = []
        def ready():
            calls.append(1)
            return {"target": True, "dependencies": True, "payload": True, "stopped": len(calls) < 3}
        before = self.games.read_bytes()
        with self.assertRaises(Invalid):
            self.apply(ready=ready)
        self.assertEqual(self.games.read_bytes(), before)
        self.assertEqual(self.record()["status"], "binding-failed")

    def test_config_failure_records_partial_application_and_never_rolls_back_whole_files(self):
        atomic = binding._atomic
        plan = self.plan()
        def fail(path, *args):
            if path == self.config:
                raise OSError("synthetic write failure")
            return atomic(path, *args)
        with patch.object(binding, "_atomic", side_effect=fail), self.assertRaises(OSError):
            self.apply(plan)
        record = self.record()
        self.assertEqual(record["status"], "binding-failed")
        self.assertEqual(record["completed_files"], ["games"])
        self.assertEqual(self.config.read_bytes(), plan.before["config"])
        self.assertEqual(self.state.read_bytes(), plan.before["state"])
        self.assertEqual(self.games.read_bytes(), plan.after["games"])
        self.assertEqual(self.apply()["status"], "binding-verified")

    def test_failure_after_replace_still_records_that_file_as_changed(self):
        atomic = binding._atomic
        def fail(path, *args):
            atomic(path, *args)
            raise OSError("synthetic failure after replace")
        with patch.object(binding, "_atomic", side_effect=fail), self.assertRaises(OSError):
            self.apply()
        self.assertEqual(self.record()["completed_files"], ["games"])
        self.assertEqual(self.record()["status"], "binding-failed")

    def test_external_change_between_files_is_retained_and_stops_further_writes(self):
        atomic = binding._atomic
        state_before = self.state.read_bytes()
        changed = b"\n// external setting change\n"
        def modify(path, *args):
            atomic(path, *args)
            if path == self.games:
                self.config.write_bytes(self.config.read_bytes() + changed)
        with patch.object(binding, "_atomic", side_effect=modify), self.assertRaises(Invalid):
            self.apply()
        self.assertTrue(self.config.read_bytes().endswith(changed))
        self.assertEqual(self.state.read_bytes(), state_before)
        self.assertEqual(self.record()["status"], "binding-failed")

    def test_repeated_binding_is_idempotent_and_does_not_rewrite_settings(self):
        self.apply()
        plan = self.plan()
        self.assertEqual(plan.summary()["planned_files"], [])
        times = {path: path.stat().st_mtime_ns for path in (self.games, self.state, self.config)}
        result = self.apply(plan)
        self.assertEqual(result["completed_files"], [])
        self.assertEqual(times, {path: path.stat().st_mtime_ns for path in times})

    def test_droiddeck_lock_conflicts_across_processes_and_is_released(self):
        code = '''import sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
from preparation_binding import droiddeck_lock
from preparation_common import MAX_DEPTH, MAX_JSON, MAX_STRING, Invalid
try:
    with droiddeck_lock(Path(sys.argv[2])):
        print("acquired")
except Invalid:
    print("blocked")
'''
        command = [sys.executable, "-I", "-B", "-c", code, str(Path(__file__).resolve().parent), str(self.settings)]
        with binding.droiddeck_lock(self.settings):
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), "blocked")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "acquired")

    def test_replaced_droiddeck_lock_stops_commit(self):
        def ready():
            lock = self.settings / "lock"
            if lock.exists():
                lock.unlink()
                lock.touch(mode=0o600)
            return {"target": True, "dependencies": True, "payload": True, "stopped": True}
        before = self.games.read_bytes()
        with self.assertRaises(Invalid):
            self.apply(ready=ready)
        self.assertEqual(self.games.read_bytes(), before)

    def test_wrong_preparation_lock_cannot_bind(self):
        with PrivateStore(self.store_root, create=True) as store, store.locked("0" * 64), self.assertRaises(Invalid):
            binding.apply_binding(self.plan(), self.steam, self.settings, store,
                                  lambda: {"target": True, "dependencies": True, "payload": True, "stopped": True})

    def test_missing_registration_wrapper_or_unexpected_commandline_is_rejected(self):
        manifest = self.tool / "toolmanifest.vdf"
        original = manifest.read_bytes()
        manifest.write_text('"manifest" {"commandline" "/proton %verb%"}')
        with self.assertRaises(Invalid):
            self.plan()
        manifest.write_bytes(original)
        (self.tool / "droiddeck-proton-wrap").unlink()
        with self.assertRaises(FileNotFoundError):
            self.plan()

    def test_symlink_or_hardlink_control_file_is_rejected(self):
        original = self.games.read_bytes()
        self.games.unlink()
        self.games.symlink_to(self.state)
        with self.assertRaises(Invalid):
            self.plan()
        self.games.unlink()
        self.games.write_bytes(original)
        os.link(self.games, self.root / "extra-link")
        with self.assertRaises(Invalid):
            self.plan()

    def test_unknown_state_history_shapes_and_alias_ids_are_rejected(self):
        for change in ({"auto": []}, {"games_applied": []}, {"picked": "42"}, {"native_choices": [True]}):
            self.write_json(self.state, {**self.original_state, **change})
            with self.subTest(change=change), self.assertRaises(Invalid):
                self.plan()
        self.write_json(self.state, self.original_state)
        games = json.loads(self.games.read_text())
        games["games"]["-1"] = games["games"][self.key]
        self.write_json(self.games, games)
        with self.assertRaises(Invalid):
            self.plan()

    def test_plan_mutation_cannot_redirect_the_writer(self):
        plan = self.plan()
        original = plan.paths["config"]
        decoy = self.root / "decoy.vdf"
        decoy.write_bytes(original.read_bytes())
        plan.paths["config"] = decoy
        before = decoy.read_bytes()
        with self.assertRaises(Invalid):
            self.apply(plan)
        self.assertEqual(decoy.read_bytes(), before)

    def test_inventory_shows_binding_failure_and_backup_without_raw_settings(self):
        result = self.apply()
        with PrivateStore(self.store_root) as store:
            before = self.snapshot()
            inventory = store.inventory()
            self.assertEqual(inventory["bindings"][0]["status"], "binding-verified")
            self.assertEqual(inventory["backups"][0]["backup_id"], result["binding_id"])
            self.assertEqual(inventory["backups"][0]["files"], ["config.backup", "games.backup", "state.backup"])
            self.assertNotIn("DUMMY", json.dumps(inventory))
            self.assertEqual(before, self.snapshot())
            path = self.store_root / "bindings" / (result["binding_id"] + ".json")
            value = json.loads(path.read_text())
            value["preparation_complete"] = True
            path.write_text(json.dumps(value))
            self.assertEqual(store.inventory()["bindings"][0]["status"], "invalid")

    def test_cli_exposes_only_read_only_target_binding_plan(self):
        self.args.tool_directory = self.directory
        before = self.snapshot()
        report = ENGINE["build_report"](self.args)
        self.assertEqual(report["binding_plan"]["tool"], "Example-Proton")
        self.assertEqual(report["writes"], [])
        self.assertEqual(before, self.snapshot())
        self.assertIn("binding-writer-not-exposed", report["blockers"])
        self.assertNotIn("DUMMY_STATE_SECRET", ENGINE["display"](report))
        self.assertIn("binding", report["input_hashes"])


class VdfTests(unittest.TestCase):
    def config(self, content):
        return ('"InstallConfigStore" {"Software" {"Valve" {"Steam" {' + content + '}}}}').encode()

    def test_insert_missing_mapping_block_preserves_all_existing_bytes(self):
        raw = self.config('"Secret" "keep" // keep this comment\n')
        changed = patch_game_mapping(raw, "42", "Example-Proton")
        self.assertIn(b'"Secret" "keep" // keep this comment\n', changed)
        node = parse_vdf(changed)
        for name in binding.STEAM_PATH:
            node = node[name]
        self.assertEqual(node["CompatToolMapping"]["42"]["name"], "Example-Proton")

    def test_insert_missing_game_preserves_default_other_and_unknown_entries(self):
        raw = self.config('"CompatToolMapping" { "0" {"name" "keep"} "99" {"name" "other"} }')
        changed = patch_game_mapping(raw, "42", "Example-Proton")
        self.assertIn(b'"0" {"name" "keep"} "99" {"name" "other"}', changed)

    def test_insert_missing_name_preserves_target_other_fields(self):
        raw = self.config('"CompatToolMapping" {"42" {"config" "preserve" "priority" "123"}}')
        changed = patch_game_mapping(raw, "42", "Example-Proton")
        self.assertIn(b'"config" "preserve" "priority" "123"', changed)

    def test_reject_default_alias_and_command_injection_tool_names(self):
        raw = self.config('"CompatToolMapping" {}')
        for key, tool in (("0", "Example"), ("-1", "Example"), ("42", 'x";touch bad'), ("42", "x\n")):
            with self.subTest(key=key, tool=tool), self.assertRaises(Invalid):
                patch_game_mapping(raw, key, tool)

    def test_reject_duplicate_mapping_and_unknown_vdf_syntax(self):
        for text in ('"CompatToolMapping" {} "CompatToolMapping" {}', '"CompatToolMapping" {"42" "scalar"}', 'garbage'):
            with self.subTest(text=text), self.assertRaises(Invalid):
                patch_game_mapping(self.config(text), "42", "Example")


if __name__ == "__main__":
    unittest.main()
