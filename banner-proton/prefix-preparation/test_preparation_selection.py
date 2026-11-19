#!/usr/bin/env python3
"""Numbered target selection, current registration pins and short report launcher."""

import contextlib
import copy
import hashlib
import io
import json
import os
import runpy
import subprocess
import tarfile
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
        self.key = f.game.args.app_id

    def catalog(self):
        return selection.registration_catalog(self.environment)

    def plan(self, renderer=None):
        source, digest, games = self.catalog()
        return selection.selected_plan(self.directory, self.config, self.key, source, digest, games,
            self.steam, self.settings, self.home, self.renderer if renderer is None else renderer, self.environment,
            runtime_root=self.fixture.context.root)

    def run_menu(self, text="1\n", config=True, stream=None):
        output = io.StringIO()
        code, name = selection.interactive_selection(self.directory, self.renderer, self.config if config else None,
            input_stream=io.StringIO(text) if stream is None else stream, output_stream=output,
            environment=self.environment, steam=self.steam, settings=self.settings, home=self.home,
            runtime_root=self.fixture.context.root)
        report = json.loads((self.directory / name).read_bytes()) if name else None
        return code, report, output.getvalue(), name

    def test_catalog_uses_environment_referenced_file_and_normalizes_id(self):
        source, digest, games = self.catalog()
        self.assertEqual(source, self.fixture.game.added)
        self.assertEqual(digest, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(list(games), [self.key])
        with self.assertRaises(Invalid):
            selection.registration_catalog({"BL_ADDED_GAMES": self.fixture.game.added.read_text()})

    def test_menu_selects_exact_id_and_saves_report_without_launch_or_prefix_writes(self):
        before = self.fixture.game.snapshot()
        with patch("subprocess.Popen", side_effect=AssertionError("no executable")), \
             patch("tarfile.TarFile.extractall", side_effect=AssertionError("no extraction")):
            code, report, output, name = self.run_menu()
        self.assertEqual(code, 2)
        self.assertEqual(report["target"]["app_id"], self.key)
        self.assertTrue(report["registration"]["rechecked"])
        self.assertEqual(report["registration"]["android_export_freshness"], "unverified")
        self.assertEqual(report["installation_plan"]["action"], "install-new")
        self.assertEqual(report["writes"], [{"scope": "report-only", "filename": name}])
        self.assertIn("結果を保存しました", output)
        self.assertEqual(before, self.fixture.game.snapshot())
        self.assertIn("new-test-registration-not-confirmed", report["blockers"])
        self.assertFalse(report["preparation_complete"])

    def test_direct_plan_is_read_only_and_does_not_save_a_report(self):
        before = self.fixture.snapshot()
        plan = self.plan()
        self.assertEqual(plan["writes"], [])
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual(list(self.directory.glob("plan-*.json")), [])

    def test_existing_empty_signed_prefix_is_preserved(self):
        prefix = self.steam / "steamapps/compatdata/-1"
        prefix.mkdir(parents=True)
        (prefix / "secret.reg").write_bytes(b"PRIVATE_PREFIX_DATA")
        report = self.plan()
        self.assertEqual(report["prefix"]["action"], "preserve-existing")
        self.assertIn("existing-prefix-preserve", report["blockers"])
        self.assertNotIn(str(prefix), [item["path"] for item in report["planned_writes"]])
        self.assertNotIn("PRIVATE_PREFIX_DATA", json.dumps(report))
        (prefix.parent / self.key).mkdir()
        with self.assertRaises(Invalid):
            self.plan()

    def test_noncanonical_long_prefix_alias_is_not_missed(self):
        prefix = self.steam / "steamapps/compatdata/04294967295"
        prefix.mkdir(parents=True)
        before = self.fixture.game.snapshot()
        with self.assertRaises(Invalid):
            self.plan()
        self.assertEqual(before, self.fixture.game.snapshot())

    def test_reuse_connects_binding_plan_without_changing_settings(self):
        self.fixture.install_fixture()
        before = self.fixture.game.snapshot()
        report = self.plan()
        self.assertEqual(report["installation_plan"]["action"], "reuse-verified-tree")
        self.assertEqual(report["binding_plan"]["payload"], "verified-expected-tree")
        self.assertNotIn("payload-integrity-unverified", report["binding_plan"]["blockers"])
        self.assertFalse(report["binding_plan"]["other_games_changed"])
        self.assertFalse(report["binding_plan"]["default_changed"])
        self.assertIn("launcher-inputs", report["initialization_inputs"]["checks"])
        self.assertFalse(report["initialization_inputs"]["execution_authorized"])
        self.assertEqual(report["initialization_inputs"]["writes"], [])
        self.assertEqual(before, self.fixture.game.snapshot())

    def test_rejected_binding_keeps_verified_installation_and_remaining_plan(self):
        self.fixture.install_fixture()
        self.fixture.game.config.write_text('"PRIVATE_CONFIG" { "duplicate" "x" "duplicate" "y" }')
        before = self.fixture.game.snapshot()
        report = self.plan()
        self.assertEqual(report["installation_plan"]["action"], "reuse-verified-tree")
        self.assertEqual(report["binding_plan"]["status"], "blocked")
        self.assertEqual(report["binding_plan"]["error"]["check"], "binding-steam-config")
        self.assertEqual(report["binding_plan"]["error"]["condition"], "vdf-duplicate-or-incomplete")
        self.assertIn("binding-input-rejected", report["blockers"])
        self.assertIn("input_digest", report)
        self.assertFalse(report["preparation_complete"])
        self.assertFalse(report["binding_plan"]["execution_authorized"])
        self.assertEqual(before, self.fixture.game.snapshot())
        self.assertNotIn("PRIVATE_CONFIG", json.dumps(report))

    def test_binding_failure_reports_multiple_independent_input_failures(self):
        self.fixture.install_fixture()
        (self.settings / "games.json").write_text('{"version": 2, "games": {}}')
        (self.settings / "state.json").write_text('{"auto": [], "picked": {}, "private-secret": "SECRET_VALUE"}')
        before = self.fixture.game.snapshot()
        report = self.plan()
        checks = report["binding_diagnostics"]["checks"]
        self.assertEqual(checks["games-schema"]["condition"], "choices-version")
        self.assertEqual(checks["state-auto"]["condition"], "auto-history")
        self.assertEqual(checks["state-picked"]["condition"], "selection-history")
        self.assertEqual(checks["target-mapping"]["status"], "accepted")
        self.assertEqual(before, self.fixture.game.snapshot())
        self.assertNotIn("SECRET_VALUE", json.dumps(report))
        self.assertNotIn("private-secret", json.dumps(report))

    def test_reuse_preserves_long_config_values_and_reports_both_parser_profiles(self):
        self.fixture.install_fixture()
        value = "DUMMY_PRIVATE_SCALAR" * 500
        config = self.fixture.game.config
        config.write_text(config.read_text().replace('"Secret"', '"Untouched" "' + value + '" "Secret"'))
        before = self.fixture.game.snapshot()
        report = self.plan()
        self.assertEqual(report["binding_plan"]["payload"], "verified-expected-tree")
        self.assertEqual(report["steam_config_validation"]["checks"]["legacy-string-limit"]["condition"], "vdf-string-length")
        self.assertEqual(report["steam_config_validation"]["checks"]["preserve-bounded-values"]["status"], "accepted")
        self.assertNotIn("binding-input-rejected", report["blockers"])
        self.assertNotIn(value, json.dumps(report))
        self.assertEqual(before, self.fixture.game.snapshot())

    def test_preparation_plan_preserves_mismatched_legacy_tool(self):
        legacy = self.fixture.install_fixture()
        (legacy / "proton").write_bytes(b"DUMMY_LEGACY_BINARY")
        before = self.fixture.game.snapshot()
        self.config["payload"]["tool_slot"] = "preparation"
        _, report, output, _ = self.run_menu()
        self.assertEqual(report["status"], "blocked")
        installation = report["installation_plan"]
        self.assertEqual(installation["tool_slot"], "preparation")
        self.assertEqual(installation["action"], "install-new")
        self.assertNotEqual(Path(installation["destination"]), legacy)
        self.assertFalse(installation["legacy_tool_observation"]["strict_match"])
        self.assertFalse(installation["legacy_tool_observation"]["modified_by_tool"])
        self.assertIn("既存のProtonはそのまま保持", output)
        self.assertEqual(before, self.fixture.game.snapshot())

    def test_legacy_rejection_keeps_structural_diagnostic_in_result(self):
        legacy = self.fixture.install_fixture()
        legacy.chmod(0o700)
        _, report, _, _ = self.run_menu()
        self.assertEqual(report["reason"], "installed-tool-differs")
        self.assertEqual(report["installed_tree_diagnostic"]["variants"][0]["check"], "root-mode")
        self.assertEqual(legacy.stat().st_mode & 0o777, 0o700)

    def test_registration_change_while_menu_is_open_is_rejected(self):
        source = self.fixture.game.added
        def choose(_):
            source.write_text(source.read_text() + " ")
            return "1\n"
        stream = type("Input", (), {"readline": staticmethod(choose)})()
        code, report, _, _ = self.run_menu(stream=stream)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "input-rejected")
        self.assertEqual(report["stage"], "selected-plan")

    def test_executable_change_during_plan_is_rejected(self):
        def change_exe(*args):
            self.fixture.game.exe.write_bytes(self.fixture.game.exe.read_bytes() + b"changed")
            return self.renderer(*args)
        with self.assertRaises(Invalid):
            self.plan(change_exe)

    def test_config_file_change_while_menu_is_open_is_rejected(self):
        path = self.directory / "prepare-plan.json"
        path.write_text(json.dumps(self.config))
        def choose(_):
            path.write_text(path.read_text() + " ")
            return "1\n"
        stream = type("Input", (), {"readline": staticmethod(choose)})()
        _, report, _, _ = self.run_menu(config=False, stream=stream)
        self.assertEqual(report["status"], "input-rejected")

    def test_missing_archive_keeps_target_evidence_and_requires_material(self):
        self.fixture.source.archive.unlink()
        _, report, output, _ = self.run_menu()
        self.assertEqual(report["target"]["app_id"], self.key)
        self.assertIn("archive-missing-or-ambiguous", report["blockers"])
        self.assertNotIn("installation_plan", report)
        self.assertIn("必要なファイル", output)
        self.assertFalse(report["preparation_complete"])

    def test_duplicate_archive_locations_are_not_automatically_chosen(self):
        folder = self.directory / "payload"
        folder.mkdir()
        (folder / self.fixture.source.archive.name).write_bytes(self.fixture.source.archive.read_bytes())
        self.config["payload"]["alternate_relative_path"] = "payload/" + self.fixture.source.archive.name
        self.assertIn("archive-missing-or-ambiguous", self.plan()["blockers"])

    def test_declared_checksum_and_runtime_changes_are_rejected(self):
        original = self.config["payload"]["sha512"]
        self.config["payload"]["sha512"] = "0" * 128
        with self.assertRaises(Invalid):
            self.plan()
        self.config["payload"]["sha512"] = original
        (self.fixture.context.root / "usr/local/lib/libfakeinput.so").write_bytes(b"changed")
        with self.assertRaises(Invalid):
            self.plan()

    def test_partial_capacity_is_never_total_preparation_approval(self):
        report = self.plan()
        capacity = report["prefix_capacity"]
        self.assertIsNone(capacity["template_allocation_estimate_bytes"])
        self.assertIsNone(capacity["initialization_growth_bytes"])
        self.assertIsNone(capacity["dependencies_bytes"])
        self.assertFalse(capacity["complete_preparation_fits"])
        self.assertIn("prefix-template-baseline-unavailable", report["blockers"])

    def test_shipped_default_template_estimate_is_not_dependency_template(self):
        archive = self.fixture.source.archive
        original = []
        with tarfile.open(archive, "r:gz") as package:
            for member in package:
                original.append((member, package.extractfile(member).read() if member.isfile() else None))
        root = self.config["payload"]["root"]
        directories = []
        for name in ("files", "files/share", "files/share/default_pfx_arm64"):
            directory = tarfile.TarInfo(root + "/" + name)
            directory.type, directory.mode = tarfile.DIRTYPE, 0o755
            directories.append((directory, None))
        file = tarfile.TarInfo(root + "/files/share/default_pfx_arm64/data")
        file.size, file.mode = 7, 0o644
        with tarfile.open(archive, "w:gz") as package:
            for member, raw in original + directories + [(file, b"fixture")]:
                package.addfile(member, io.BytesIO(raw) if raw is not None else None)
        self.config["payload"]["sha512"] = hashlib.sha512(archive.read_bytes()).hexdigest()
        capacity = self.plan()["prefix_capacity"]
        self.assertEqual(capacity["basis"], "shipped-files/share/default_pfx_arm64-only")
        self.assertGreaterEqual(capacity["template_allocation_estimate_bytes"], 7)
        self.assertFalse(capacity["dependency_prepared_template"])
        self.assertFalse(capacity["complete_preparation_fits"])

    def test_cancel_and_eof_do_not_save_or_prepare_anything(self):
        for text in ("q\n", ""):
            with self.subTest(text=text):
                code, report, _, _ = self.run_menu(text)
                self.assertEqual(code, 0)
                self.assertIsNone(report)
                self.assertEqual(list(self.directory.glob("plan-*.json")), [])

    def test_invalid_choice_and_missing_environment_save_fixed_diagnostics(self):
        code, report, _, _ = self.run_menu("$(touch injected)\n")
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "input-rejected")
        self.assertFalse((self.directory / "injected").exists())
        self.environment.pop("BL_ADDED_GAMES")
        _, report, _, _ = self.run_menu()
        self.assertEqual(report["stage"], "registration-catalog")
        self.assertNotIn("DUMMY_PROTOCOL_SECRET", json.dumps(report))

    def test_duplicate_normalized_ids_are_rejected_before_selection(self):
        self.fixture.game.added.write_text(json.dumps([{"appid": -1, "exe": str(self.fixture.game.exe)},
                                                     {"appid": 4294967295, "exe": str(self.fixture.game.exe)}]))
        _, report, _, _ = self.run_menu()
        self.assertEqual(report["status"], "input-rejected")
        self.assertEqual(report["stage"], "registration-catalog")

    def test_terminal_controls_and_ignored_registration_fields_are_not_disclosed(self):
        self.fixture.game.added.write_text(json.dumps([{"appid": -1, "exe": str(self.fixture.game.exe),
            "title": "Example\n\u001b[31m\u202e", "secret": "DUMMY_REGISTRATION_SECRET"}]))
        _, report, output, _ = self.run_menu()
        self.assertNotIn("\u001b", output)
        self.assertNotIn("\u202e", output)
        self.assertNotIn("DUMMY_REGISTRATION_SECRET", output + json.dumps(report))

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

    def test_standalone_short_launcher_preserves_menu_input_and_saves_next_to_script(self):
        folder = self.home / "launcher"
        folder.mkdir()
        script = folder / "prepare.sh"
        script.write_text(selection.selection_script(self.config))
        (self.home / ".local/share/Steam").mkdir(parents=True)
        (self.home / ".local/share/droiddeck-compat").mkdir(parents=True)
        fake_cwd = self.home / "untrusted-cwd"
        fake_cwd.mkdir()
        (fake_cwd / "preparation_selection.py").write_text("raise RuntimeError('must not import CWD')\n")
        env = {**os.environ, "HOME": str(self.home), "BL_ADDED_GAMES": str(self.fixture.game.added), "PYTHONPATH": str(fake_cwd)}
        completed = subprocess.run(["/bin/bash", str(script)], input=b"1\n", cwd=fake_cwd, env=env,
                                   capture_output=True, timeout=15, check=False)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        reports = list(folder.glob("plan-*.json"))
        self.assertEqual(len(reports), 1)
        report = json.loads(reports[0].read_bytes())
        self.assertEqual(report["target"]["app_id"], self.key)
        self.assertIn("archive-missing-or-ambiguous", report["blockers"])
        self.assertEqual(list(fake_cwd.glob("plan-*.json")), [])
        self.assertEqual(list(self.home.rglob("__pycache__")), [])
        self.assertFalse((self.home / ".local/share/Steam/steamapps/compatdata" / self.key).exists())
        rejected = subprocess.run(["/bin/bash", str(script), "--probe-temporary"], env=env,
                                  capture_output=True, check=False, timeout=5)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(len(list(folder.glob("plan-*.json"))), 1)

    def test_rejection_reason_is_closed_and_never_echoes_exception_content(self):
        with patch.object(selection, "selected_plan", side_effect=Invalid("existing installation differs from approved generated trees")):
            _, report, _, _ = self.run_menu()
        self.assertEqual(report["reason"], "installed-tool-differs")
        with patch.object(selection, "selected_plan", side_effect=ValueError("DUMMY_PRIVATE_EXCEPTION_CONTENT")):
            _, report, output, _ = self.run_menu()
        self.assertEqual(report["reason"], "input-rejected")
        self.assertNotIn("DUMMY_PRIVATE_EXCEPTION_CONTENT", output + json.dumps(report))

    def test_shared_group_writable_launcher_folder_gets_private_original_and_export(self):
        before = self.fixture.game.exe.read_bytes()
        self.directory.chmod(0o2770)
        before_mode = self.directory.stat().st_mode & 0o7777
        try:
            code, report, output, name = self.run_menu()
            self.assertEqual(code, 2)
            self.assertEqual(report["report_storage"]["authoritative"], "private-linux-home")
            private = self.home / ".local/state/droiddeck-prefix-preparation/reports" / name
            self.assertEqual(private.read_bytes(), (self.directory / name).read_bytes())
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            self.assertEqual(private.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(self.directory.stat().st_mode & 0o7777, before_mode)
            self.assertIn("原本", output)
            self.assertEqual(self.fixture.game.exe.read_bytes(), before)
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
            code, report, _, _ = self.run_menu()
        self.assertEqual(code, 2)
        self.assertEqual(report["report_storage"]["authoritative"], "private-linux-home")

    def test_failed_shared_export_still_preserves_private_diagnostics(self):
        self.directory.chmod(0o2770)
        try:
            with patch.object(selection, "_export_report", side_effect=PermissionError("DUMMY_PRIVATE_DETAIL")):
                code, report, output, name = self.run_menu()
            self.assertEqual(code, 2)
            self.assertTrue(Path(name).is_absolute())
            self.assertEqual(Path(name).parent, self.home / ".local/state/droiddeck-prefix-preparation/reports")
            self.assertTrue(Path(name).is_file())
            self.assertIn(str(Path(name)), output)
            self.assertNotIn("DUMMY_PRIVATE_DETAIL", output + json.dumps(report))
        finally:
            self.directory.chmod(0o700)

    def test_protected_directory_uses_private_result_without_export(self):
        path, original = selection.save_selection_result(self.steam, self.home, {"writes": []}, (self.steam, self.settings))
        self.assertIsNone(original)
        self.assertTrue(path.is_relative_to(self.home))
        self.assertEqual(list(self.steam.glob("plan-*.json")), [])

    def test_private_report_ancestor_symlink_is_not_followed(self):
        self.directory.chmod(0o2770)
        local = self.home / ".local"
        local.mkdir()
        external = self.home / "external"
        external.mkdir()
        (local / "state").symlink_to(external, target_is_directory=True)
        try:
            code, report, _, _ = self.run_menu()
            self.assertEqual(code, 1)
            self.assertIsNone(report)
            self.assertEqual(list(external.iterdir()), [])
        finally:
            self.directory.chmod(0o700)

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

    def test_strict_exe_link_refusal_includes_metadata_and_console_reason(self):
        os.link(self.fixture.game.exe, self.fixture.game.exe.with_name("linked-fixture.exe"))
        _, report, output, _ = self.run_menu()
        self.assertEqual(report["reason"], "input-link-metadata-rejected")
        self.assertEqual(report["check"], "target-registration-exe")
        self.assertEqual(report["selected_exe_metadata"]["fd"]["link_count"], 2)
        self.assertTrue(report["selected_exe_metadata"]["fd"]["regular"])
        self.assertIn("target-registration-exe", output)
        self.assertIn("input-link-metadata-rejected", output)
        self.assertEqual(report["status"], "input-rejected")

    def test_archive_failure_has_fixed_check_even_if_report_save_fails(self):
        self.config["payload"]["sha512"] = "0" * 128
        with patch.object(selection, "save_selection_result", side_effect=PermissionError("DUMMY_SAVE_SECRET")):
            code, report, output, _ = self.run_menu()
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("payload-archive", output)
        self.assertNotIn("DUMMY_SAVE_SECRET", output)

    def test_cli_emitter_does_not_run_menu_or_save_reports(self):
        config_path = self.directory / "bundle.json"
        config_path.write_text(json.dumps(self.config))
        with patch("sys.argv", ["prepare_game.py", "--emit-selection-script", "--selection-config", str(config_path)]), \
             patch.object(selection, "interactive_selection", side_effect=AssertionError("no execution")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(FIX["ENGINE"]["main"](), 0)
        self.assertTrue(output.getvalue().startswith("#!/bin/bash"))
        self.assertEqual(list(self.directory.glob("plan-*.json")), [])


if __name__ == "__main__":
    unittest.main()
