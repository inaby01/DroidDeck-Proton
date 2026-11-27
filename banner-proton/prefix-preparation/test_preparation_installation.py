#!/usr/bin/env python3
"""Composed plans using generated archives/runtime/registrations, without Wine."""

import copy
import json
import os
import runpy
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CUSTOM = runpy.run_path(str(HERE / "test_preparation_customization.py"))
CONTEXT = runpy.run_path(str(HERE / "test_preparation_runtime_context.py"))
GAME = runpy.run_path(str(HERE / "test_prepare_game.py"))
import preparation_customization as customization
import preparation_runtime as runtime
from preparation_common import Invalid
from preparation_installation import plan_installation


def extract_fixture(archive, tools, mode):
    """What the removed manual installer did before its own renames: extract the archive with the
    data filter (keeping the process umask) and name the folder as SoftDenchi-Proton <version>."""
    import tarfile
    import tempfile
    assert mode == "cleanup"
    version = archive.name.removeprefix("DroidDeck-Proton-").removesuffix("-aarch64.tar.gz")
    tools.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".fixture-extract-", dir=tools))
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(staging, filter="data")
    (root,) = list(staging.iterdir())
    destination = tools / ("SoftDenchi-Proton " + version)
    root.rename(destination)
    staging.rmdir()
    return destination

class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.source = CUSTOM["CustomizationTests"]()
        self.addCleanup(self.source.doCleanups)
        self.source.setUp()
        self.context = CONTEXT["RuntimeContextTests"]()
        self.addCleanup(self.context.doCleanups)
        self.context.setUp()
        helper_name = "usr/local/bin/steam-compatibility"
        helper = self.context.root / helper_name
        helper.write_bytes(self.source.helper.read_bytes())
        source_patch = patch.dict(runtime.SOURCES, {helper_name: self.source.helper_hash})
        source_patch.start()
        self.addCleanup(source_patch.stop)
        helper_patch = patch.object(customization, "HELPER_SHA256", self.source.helper_hash)
        helper_patch.start()
        self.addCleanup(helper_patch.stop)
        self.game = GAME["SettingsFixture"]()
        self.addCleanup(self.game.doCleanups)
        self.game.setUp()
        reference = runtime.inspect_runtime(self.context.root, self.context.environment)
        reference.update(view="current-root", auditor_architecture="aarch64")
        reference["process_observation_basis"]["umask"] = "0077"
        self.reference = reference
        self.options = {"archive": self.source.archive, "sha512": self.source.sha, "archive_root": CUSTOM["ROOT"],
                        "mode": "cleanup", "runtime_root": self.context.root, "runtime_audit": reference,
                        "registrations": self.game.added, "registration_id": "4294967295",
                        "exe_root": self.game.exe_root, "steam": self.game.steam,
                        "renderer": CUSTOM["INSTALLER"]["render_installation"], "parent_environment": self.context.environment}

    def plan(self, **changes):
        return plan_installation(**(self.options | changes))

    def snapshot(self):
        result = {}
        for root in (self.source.root, self.context.root, self.game.root):
            for path in root.rglob("*"):
                info = path.lstat()
                result[str(path)] = (info.st_mode, info.st_size, info.st_mtime_ns,
                                     path.read_bytes() if path.is_file() else None)
        return result

    def install_fixture(self, mask=0o077):
        plan = self.plan()
        directory = Path(plan.summary()["destination"])
        # Model an archive-mode-preserving installer, then generated metadata.
        # Legacy data_filter extraction under 0077 is separately rejected below.
        previous = os.umask(0o022)
        try:
            directory = extract_fixture(self.source.archive, directory.parent, "cleanup")
        finally:
            os.umask(previous)
        expected = customization.plan_customizations(plan.inventory, self.source.archive.name, "cleanup",
                     self.context.root / "usr/local/bin/steam-compatibility", CUSTOM["INSTALLER"]["render_installation"],
                     label=plan.runtime.label, umask=mask)
        for name, raw in expected.files.items():
            (directory / name).write_bytes(raw)
            (directory / name).chmod(expected.overlays[name]["mode"])
        return directory

    def test_new_plan_is_read_only_without_importing_runtime_or_launching(self):
        before = self.snapshot()
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")), \
             patch("runpy.run_path", side_effect=AssertionError("no runtime import")), \
             patch("tarfile.TarFile.extractall", side_effect=AssertionError("no extraction")):
            report = self.plan().summary()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(report["action"], "install-new")
        self.assertEqual(report["customization"]["expected_files"], sorted(self.plan().customization.files))
        self.assertEqual(report["writes"], [])
        self.assertEqual(len(report["planned_writes"]), 2)
        self.assertFalse(report["preparation_complete"])
        self.assertIn("runtime-snapshot-cannot-authorize-execution", report["blockers"])

    def test_runtime_mask_selects_expected_created_file_permissions(self):
        plan = self.plan()
        self.assertEqual(plan.customization.overlays["toolmanifest.vdf"]["mode"], 0o600)
        self.assertEqual(plan.runtime.umask, "0077")

    def test_capacity_is_installation_only_and_accounts_for_metadata_and_reserve(self):
        plan = self.plan()
        capacity = plan.summary()["capacity"]
        self.assertGreater(capacity["estimated_additional_bytes"], plan.inventory.expanded_bytes + capacity["reserve_bytes"])
        self.assertIsNone(capacity["prefix_and_dependencies_bytes"])
        self.assertFalse(capacity["total_preparation_capacity_verified"])
        self.assertEqual(capacity["write_permission"], "unverified")
        self.assertFalse(Path(plan.summary()["destination"]).parent.exists())

    def test_low_capacity_remains_a_blocked_report(self):
        fs = SimpleNamespace(f_frsize=4096, f_bsize=4096, f_bavail=1)
        with patch("preparation_installation.os.statvfs", return_value=fs):
            report = self.plan().summary()
        self.assertFalse(report["capacity"]["estimate_fits"])
        self.assertIn("insufficient-estimated-installation-capacity", report["blockers"])

    def test_reuse_verifies_all_files_and_accepts_only_generated_creation_masks(self):
        directory = self.install_fixture(0o022)
        for mask in (0o022, 0o077):
            with self.subTest(mask=mask):
                plan = self.plan()
                expected = customization.plan_customizations(plan.inventory, self.source.archive.name, "cleanup",
                    self.context.root / "usr/local/bin/steam-compatibility", CUSTOM["INSTALLER"]["render_installation"], umask=mask)
                for name, item in expected.overlays.items():
                    (directory / name).chmod(item["mode"])
                before = self.snapshot()
                report = self.plan().summary()
                self.assertEqual(report["action"], "reuse-verified-tree")
                self.assertEqual(report["reused_creation_umask"], format(mask, "04o"))
                self.assertEqual(report["planned_writes"], [])
                self.assertEqual(report["capacity"]["estimated_additional_bytes"], 0)
                self.assertEqual(before, self.snapshot())
        # A mixed creation policy must not be silently approved.
        (directory / "toolmanifest.vdf").chmod(0o644)
        with self.assertRaises(Invalid):
            self.plan()

    def test_legacy_private_mask_directory_modes_are_not_silently_accepted(self):
        plan = self.plan()
        previous = os.umask(0o077)
        try:
            directory = extract_fixture(self.source.archive, Path(plan.summary()["destination"]).parent, "cleanup")
        finally:
            os.umask(previous)
        for name, raw in plan.customization.files.items():
            (directory / name).write_bytes(raw)
            (directory / name).chmod(plan.customization.overlays[name]["mode"])
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(Invalid):
            self.plan()

    def test_root_mode_mismatch_has_bounded_metadata_diagnostics(self):
        directory = self.install_fixture()
        directory.chmod(0o700)
        with self.assertRaises(Invalid) as failure:
            self.plan()
        diagnostic = failure.exception.installed_tree_diagnostic
        self.assertFalse(diagnostic["strict_match"])
        for variant in diagnostic["variants"]:
            self.assertEqual(variant["check"], "root-mode")
            self.assertEqual(variant["expected_mode"], "0755")
            self.assertEqual(variant["actual_mode"], "0700")
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_binary_mismatch_diagnostic_does_not_record_file_contents(self):
        directory = self.install_fixture()
        (directory / "proton").write_bytes(b"DUMMY_PRIVATE_MODIFIED_CONTENT")
        with self.assertRaises(Invalid) as failure:
            self.plan()
        diagnostic = failure.exception.installed_tree_diagnostic
        self.assertTrue(any("sha256" in item.get("differing_fields", []) for item in diagnostic["variants"]))
        self.assertNotIn("DUMMY_PRIVATE_MODIFIED_CONTENT", json.dumps(diagnostic))
        self.assertNotIn(str(self.game.root), json.dumps(diagnostic))

    def test_modified_binary_or_extra_file_prevents_reuse(self):
        directory = self.install_fixture()
        proton = directory / "proton"
        raw = proton.read_bytes()
        proton.write_bytes(raw + b"changed")
        with self.assertRaises(Invalid):
            self.plan()
        proton.write_bytes(raw)
        (directory / "unexpected").write_bytes(b"unknown")
        with self.assertRaises(Invalid):
            self.plan()

    def test_symlink_destination_or_parent_is_rejected_without_writes(self):
        destination = Path(self.plan().summary()["destination"])
        destination.parent.symlink_to(self.source.root, target_is_directory=True)
        before = self.snapshot()
        with self.assertRaises(Invalid):
            self.plan()
        self.assertEqual(before, self.snapshot())

    def test_any_partial_or_signed_prefix_is_preserved_and_blocks_initialization(self):
        directory = self.game.steam / "steamapps/compatdata/-1"
        directory.mkdir(parents=True)
        before = self.snapshot()
        report = self.plan().summary()
        self.assertEqual(report["prefix"]["action"], "preserve-existing")
        self.assertEqual(report["prefix"]["compatdata"], str(directory))
        self.assertIn("existing-prefix-preserve", report["blockers"])
        self.assertEqual(before, self.snapshot())
        (directory.parent / "4294967295").mkdir()
        with self.assertRaises(Invalid):
            self.plan()

    def test_changed_checksum_runtime_or_unknown_mode_is_rejected(self):
        for changes in ({"sha512": "0" * 128}, {"mode": "unknown"},
                        {"runtime_audit": {**self.reference, "os_release": {}}}):
            with self.subTest(changes=list(changes)), self.assertRaises(Invalid):
                self.plan(**changes)

    def test_changed_registration_and_archive_change_composed_identity(self):
        before = self.plan().digest
        self.game.exe.write_bytes(self.game.exe.read_bytes() + b"changed")
        self.assertNotEqual(before, self.plan().digest)
        before = self.plan().digest
        self.source.make_archive(settings=b'user_settings={"CUSTOM":"changed"}\n')
        self.assertNotEqual(before, self.plan(sha512=self.source.sha).digest)

    def test_private_environment_and_label_values_never_appear_in_summaries(self):
        label = self.context.root / "etc/steam-compatibility-label"
        label.write_bytes(b"DUMMY_PRIVATE_LABEL")
        reference = copy.deepcopy(self.reference)
        reference["label"] = runtime.inspect_runtime(self.context.root, self.context.environment)["label"]
        plan = self.plan(runtime_audit=reference)
        for value in (json.dumps(plan.summary()), repr(plan)):
            self.assertNotIn("DUMMY_PRIVATE_LABEL", value)
            self.assertNotIn("DUMMY_PROTOCOL_SECRET", value)
            self.assertNotIn("user_settings=", value)
        report = plan.summary()
        report["runtime"]["environment_names"].append("mutated")
        self.assertNotIn("mutated", plan.summary()["runtime"]["environment_names"])

if __name__ == "__main__":
    unittest.main()
