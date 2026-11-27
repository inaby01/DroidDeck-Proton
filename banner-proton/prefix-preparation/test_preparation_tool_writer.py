#!/usr/bin/env python3
"""Synthetic Linux staging/publication/failure contracts. No Wine or device writes."""

import contextlib
import ctypes
import errno
import hashlib
import io
import json
import os
import runpy
import sys
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIXTURE = runpy.run_path(str(HERE / "test_preparation_installation.py"))
import preparation_tool_writer as writer
from preparation_common import Invalid, require
from preparation_payload import verify_tree
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore


@unittest.skipUnless(sys.platform == "linux", "writer requires Linux non-replacing renameat2")
class ToolWriterTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FIXTURE["InstallationTests"]()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.root = self.fixture.context.root
        self.settings = self.root / "client-settings"
        self.settings.mkdir()
        self.exe_root = self.root / "client-games"
        self.exe_root.mkdir()
        self.exe = self.exe_root / "Example.exe"
        self.exe.write_bytes(FIXTURE["GAME"]["pe"]())
        self.added = self.root / "client-registrations.json"
        self.added.write_text(json.dumps([{"appid": 42, "exe": str(self.exe), "name": "Example"}]))
        self.proc = self.root / "fixture-proc"
        (self.proc / str(os.getpid())).mkdir(parents=True)
        self.store_root = self.root / "private-management"
        self.checks = {key: True for key in ("target", "payload", "runtime", "stopped")}
        self.environment = self.fixture.context.environment
        environment = patch.dict(os.environ, self.environment, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.select_steam("client-Steam")

    def select_steam(self, name):
        self.steam = self.root / name
        self.steam.mkdir()
        self.fixture.options.update(steam=self.steam, exe_root=self.exe_root, registrations=self.added, registration_id="42")
        self.compatdata = self.steam / "steamapps/compatdata/42"
        self.lock_key = hashlib.sha256(str(self.compatdata).encode()).hexdigest()
        self.stop_check = ProcessStopCheck(self.compatdata, self.proc)

    def plan(self):
        return self.fixture.plan()

    def destination(self):
        return self.steam / "compatibilitytools.d" / self.plan().customization.directory

    @contextlib.contextmanager
    def store(self):
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
            yield store

    def apply(self, store, plan=None, refresh=None):
        """The shared tree transaction with a minimal readiness callback (the tool's caller is
        apply_static_placement; the full-readiness wrapper of earlier versions was removed in 1.0.1)."""
        plan = self.plan() if plan is None else plan

        def ready(published=False):
            store._guard()
            require(all(value is True for value in self.checks.values()), "installation prerequisites unverified")
            require(self.stop_check.check()["clear_in_view"], "active or unknown prefix process")
            plan.target.verify()
            plan.runtime.verify()
        return writer._write_installation_tree(plan, self.plan if refresh is None else refresh, store, self.settings, ready)

    def record(self, store):
        inventory = store.inventory()["installations"]
        self.assertEqual(len(inventory), 1)
        self.assertTrue(inventory[0]["reinspection_required"])
        return store.read_record("installations", inventory[0]["installation_id"] + ".json")[0]

    def assert_new_install(self, mask):
        plan = self.plan()
        before = self.exe.read_bytes(), self.added.read_bytes()
        previous = os.umask(mask)
        try:
            with self.store() as store, patch("subprocess.Popen", side_effect=AssertionError("no executable")), \
                 patch("tarfile.TarFile.extractall", side_effect=AssertionError("no extractall")), \
                 patch("runpy.run_path", side_effect=AssertionError("no runtime import")):
                result = self.apply(store, plan)
                self.assertEqual(result, self.record(store))
                self.assertEqual(result["status"], "installed-tree-verified")
                self.assertTrue(result["published"])
                self.assertFalse(result["preparation_complete"])
                self.assertNotIn("DUMMY_PROTOCOL_SECRET", json.dumps(result))
        finally:
            os.umask(previous)
        destination = Path(plan.summary()["destination"])
        self.assertTrue(verify_tree(destination, plan.inventory, plan.customization.overlays)["tree_matches"])
        self.assertEqual(destination.stat().st_mode & 0o777, plan.inventory.root_mode)
        self.assertEqual((destination / "toolmanifest.vdf").stat().st_mode & 0o777, 0o600)
        self.assertEqual(before, (self.exe.read_bytes(), self.added.read_bytes()))
        self.assertFalse(self.compatdata.exists())
        self.assertEqual(list(destination.parent.glob(".prefix-preparation-staging-*")), [])
        self.assertFalse((self.settings / "games.json").exists())
        self.assertFalse((self.settings / "state.json").exists())

    def test_new_install_under_private_umask_preserves_archive_modes(self):
        self.assert_new_install(0o077)

    def test_new_install_under_public_umask_uses_pinned_metadata_modes(self):
        self.assert_new_install(0o022)

    def test_preparation_slot_publication_keeps_existing_legacy_tree(self):
        with self.store() as store:
            self.apply(store)
            legacy = self.destination()
            (legacy / "proton").write_bytes(b"KEEP_EXISTING_TOOL")
            before = {str(path): (path.read_bytes(), path.stat().st_mtime_ns) for path in legacy.rglob("*") if path.is_file()}
            self.fixture.options["tool_slot"] = "preparation"
            plan = self.plan()
            result = self.apply(store, plan)
            self.assertEqual(result["status"], "installed-tree-verified")
            destination = Path(plan.summary()["destination"])
            self.assertNotEqual(destination, legacy)
            self.assertTrue(verify_tree(destination, plan.inventory, plan.customization.overlays)["tree_matches"])
            self.assertEqual(before, {str(path): (path.read_bytes(), path.stat().st_mtime_ns) for path in legacy.rglob("*") if path.is_file()})
            self.assertFalse(self.compatdata.exists())

    def test_reuse_rechecks_whole_tree_without_installation_writes(self):
        with self.store() as store:
            self.apply(store)
            destination = self.destination()
            before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in destination.rglob("*") if p.is_file()}
            with patch.object(writer, "_stream_tree", side_effect=AssertionError("no extraction on reuse")):
                result = self.apply(store)
            self.assertEqual(result["status"], "reused-tree-verified")
            self.assertFalse(result["published"])
            self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in destination.rglob("*") if p.is_file()})
            self.assertEqual(len(store.inventory()["installations"]), 2)

    def test_a_refusing_readiness_callback_stops_before_any_write(self):
        # The callback is the caller's (apply_static_placement in the tool); the writer must call it
        # before it writes anything, and stop when it refuses.
        with self.store() as store:
            for key in self.checks:
                self.checks[key] = False
                with self.subTest(key=key), self.assertRaises(Invalid):
                    self.apply(store)
                self.checks[key] = True
            self.assertEqual(store.inventory()["installations"], [])
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_a_callback_refusing_on_the_process_view_stops_before_any_write(self):
        (self.proc / "12345").mkdir()
        with self.store() as store, self.assertRaises(Invalid):
            self.apply(store)
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_mutated_plan_expected_bytes_are_rejected(self):
        plan = self.plan()
        plan.customization.files["droiddeck-proton-wrap"] += b"changed"
        with self.store() as store, self.assertRaises(Invalid):
            self.apply(store, plan)
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_changed_registration_invalidates_original_plan_before_writes(self):
        plan = self.plan()
        self.exe.write_bytes(self.exe.read_bytes() + b"changed")
        with self.store() as store, self.assertRaises(Invalid):
            self.apply(store, plan)
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_mid_staging_failure_preserves_tree_and_records_phase(self):
        plan = self.plan()
        with self.store() as store:
            with patch.object(writer, "_customize", side_effect=OSError(errno.ENOSPC, "synthetic full disk")), self.assertRaises(OSError):
                self.apply(store, plan)
            record = self.record(store)
            self.assertEqual((record["status"], record["phase"], record["published"]), ("failed", "staging", False))
            stage = self.steam / "compatibilitytools.d" / record["staging_name"]
            self.assertTrue((stage / "tree/proton").is_file())
            self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
        self.assertFalse(Path(plan.summary()["destination"]).exists())
        self.assertFalse(self.compatdata.exists())

    def test_archive_bytes_changed_during_staging_are_rejected(self):
        plan = self.plan()
        original = writer._stream_tree
        def changed_archive(*args):
            self.fixture.source.archive.write_bytes(b"not gzip")
            return original(*args)
        with self.store() as store:
            with patch.object(writer, "_stream_tree", side_effect=changed_archive), self.assertRaises(OSError):
                self.apply(store, plan)
            self.assertEqual(self.record(store)["status"], "failed")
        self.assertFalse(Path(plan.summary()["destination"]).exists())

    def test_completed_tree_corruption_is_detected_before_publication(self):
        plan = self.plan()
        original = writer._customize
        def corrupt(fd, current, directories):
            original(fd, current, directories)
            with os.fdopen(os.open("proton", os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, dir_fd=fd), "wb") as out:
                out.write(b"corrupted")
        with self.store() as store:
            with patch.object(writer, "_customize", side_effect=corrupt), self.assertRaises(Invalid):
                self.apply(store, plan)
            self.assertEqual(self.record(store)["status"], "failed")
        self.assertFalse(Path(plan.summary()["destination"]).exists())

    def collision(self, kind):
        plan = self.plan()
        destination = Path(plan.summary()["destination"])
        original = writer._publish
        def race(*args):
            if kind == "file":
                destination.write_bytes(b"KEEP")
            elif kind == "directory":
                destination.mkdir()
            else:
                destination.symlink_to(self.exe)
            return original(*args)
        with self.store() as store:
            with patch.object(writer, "_publish", side_effect=race), self.assertRaises(OSError) as error:
                self.apply(store, plan)
            self.assertEqual(error.exception.errno, errno.EEXIST)
            record = self.record(store)
            self.assertEqual((record["status"], record["phase"]), ("needs-inspection", "publish-intent"))
            self.assertTrue((destination.parent / record["staging_name"] / "tree/proton").exists())
        if kind == "file":
            self.assertEqual(destination.read_bytes(), b"KEEP")
        elif kind == "directory":
            self.assertEqual(list(destination.iterdir()), [])
        else:
            self.assertTrue(destination.is_symlink())
            self.assertEqual(os.readlink(destination), str(self.exe))

    def test_racing_file_is_never_replaced(self):
        self.collision("file")

    def test_racing_empty_directory_is_never_replaced(self):
        self.collision("directory")

    def test_racing_symlink_is_never_replaced(self):
        self.collision("symlink")

    def test_unsupported_libc_stops_without_installation_writes(self):
        plan = self.plan()
        with self.store() as store:
            with patch.object(writer, "_rename_function", side_effect=Invalid("unsupported")), self.assertRaises(Invalid):
                self.apply(store, plan)
            self.assertEqual(self.record(store)["status"], "failed")
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_unsupported_filesystem_never_falls_back_to_replace(self):
        def unsupported(*_):
            ctypes.set_errno(errno.EINVAL)
            return -1
        with self.store() as store:
            with patch.object(writer, "_rename_function", return_value=unsupported), \
                 patch("os.replace", wraps=os.replace) as replace, self.assertRaises(OSError) as error:
                self.apply(store)
            self.assertEqual(error.exception.errno, errno.EINVAL)
            # Journal updates use os.replace; it must never publish a directory.
            self.assertTrue(all(call.args[1].endswith(".json") for call in replace.call_args_list))
            self.assertEqual(self.record(store)["status"], "needs-inspection")

    def test_target_changes_after_publish_preserve_installed_tree(self):
        plan = self.plan()
        original = writer._publish
        def change_target(*args):
            original(*args)
            self.exe.write_bytes(self.exe.read_bytes() + b"changed")
        with self.store() as store:
            with patch.object(writer, "_publish", side_effect=change_target), self.assertRaises(Invalid):
                self.apply(store, plan)
            record = self.record(store)
            self.assertEqual((record["status"], record["published"]), ("needs-inspection", True))
        self.assertTrue(verify_tree(Path(plan.summary()["destination"]), plan.inventory, plan.customization.overlays)["tree_matches"])
        self.assertFalse(self.compatdata.exists())

    def test_record_failure_after_publication_preserves_last_durable_intent(self):
        plan = self.plan()
        with self.store() as store:
            original = store.write_record
            def fail_after_publish(directory, name, value, *args, **kwargs):
                if directory == "installations" and value["phase"] == "published":
                    raise OSError(errno.ENOSPC, "synthetic journal full")
                return original(directory, name, value, *args, **kwargs)
            with patch.object(store, "write_record", side_effect=fail_after_publish), self.assertRaises(OSError):
                self.apply(store, plan)
            record = self.record(store)
            self.assertEqual((record["status"], record["phase"], record["published"]), ("running", "publish-intent", False))
            self.assertTrue(verify_tree(Path(plan.summary()["destination"]), plan.inventory, plan.customization.overlays)["tree_matches"])

    def test_parent_replacement_does_not_redirect_publication(self):
        plan = self.plan()
        original = writer._customize
        tools = self.steam / "compatibilitytools.d"
        detached = self.steam / "detached-tools"
        def replace_parent(*args):
            original(*args)
            tools.rename(detached)
            tools.mkdir()
            (tools / "keep").write_bytes(b"UNCHANGED")
        with self.store() as store:
            with patch.object(writer, "_customize", side_effect=replace_parent), self.assertRaises(Invalid):
                self.apply(store, plan)
            self.assertEqual(self.record(store)["status"], "failed")
        self.assertEqual((tools / "keep").read_bytes(), b"UNCHANGED")
        self.assertEqual(len(list(detached.glob(".prefix-preparation-staging-*/tree/proton"))), 1)
        self.assertFalse(Path(plan.summary()["destination"]).exists())

    def test_insufficient_capacity_rejected_before_staging(self):
        plan = self.plan()
        from types import SimpleNamespace
        fs = SimpleNamespace(f_frsize=4096, f_bsize=4096, f_bavail=1)
        with self.store() as store:
            # PrivateStore has its own capacity check; restrict this patch to planner.
            original = self.plan
            def low_capacity():
                with patch("preparation_installation.os.statvfs", return_value=fs):
                    return original()
            with self.assertRaises(Invalid):
                self.apply(store, plan, low_capacity)
            self.assertEqual(self.record(store)["status"], "failed")
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_settings_lock_conflict_stops_before_staging(self):
        with self.store() as store, writer.droiddeck_lock(self.settings), self.assertRaises(Invalid):
            self.apply(store)
        self.assertFalse((self.steam / "compatibilitytools.d").exists())

    def test_existing_prefix_contents_are_preserved_during_tool_install(self):
        self.compatdata.mkdir(parents=True)
        sentinel = self.compatdata / "do-not-touch"
        sentinel.write_bytes(b"PRIVATE_EXISTING_PREFIX")
        before = sentinel.stat()
        with self.store() as store:
            result = self.apply(store)
        self.assertEqual(result["status"], "installed-tree-verified")
        self.assertEqual(sentinel.read_bytes(), b"PRIVATE_EXISTING_PREFIX")
        self.assertEqual((before.st_ino, before.st_mtime_ns), (sentinel.stat().st_ino, sentinel.stat().st_mtime_ns))
        self.assertEqual(list(self.compatdata.iterdir()), [sentinel])

    def test_interruption_preserves_staging_and_records_failure(self):
        plan = self.plan()
        with self.store() as store:
            with patch.object(writer, "_customize", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                self.apply(store, plan)
            record = self.record(store)
            self.assertEqual(record["status"], "failed")
            self.assertTrue((self.steam / "compatibilitytools.d" / record["staging_name"] / "tree/proton").exists())
        self.assertFalse(Path(plan.summary()["destination"]).exists())

    def test_invalid_completion_record_is_not_reported_as_verified(self):
        with self.store() as store:
            result = self.apply(store)
            result["published"] = False
            name = result["installation_id"] + ".json"
            _, digest = store.read_record("installations", name)
            store.write_record("installations", name, result, digest)
            self.assertEqual(store.inventory()["installations"], [{"object": name, "status": "invalid"}])

    def test_nested_directories_symlinks_and_hardlinks_keep_topology(self):
        archive = self.fixture.source.archive
        members = []
        with tarfile.open(archive, "r:gz") as package:
            for member in package:
                members.append((member, package.extractfile(member).read() if member.isfile() else None))
        root = FIXTURE["CUSTOM"]["ROOT"]
        directory = tarfile.TarInfo(root + "/lib")
        directory.type, directory.mode = tarfile.DIRTYPE, 0o755
        data = tarfile.TarInfo(root + "/lib/data")
        data.size, data.mode = 7, 0o644
        hard = tarfile.TarInfo(root + "/lib/hard")
        hard.type, hard.linkname = tarfile.LNKTYPE, root + "/lib/data"
        link = tarfile.TarInfo(root + "/link")
        link.type, link.linkname = tarfile.SYMTYPE, "lib/data"
        with tarfile.open(archive, "w:gz") as package:
            for member, raw in members + [(directory, None), (data, b"fixture"), (hard, None), (link, None)]:
                package.addfile(member, io.BytesIO(raw) if raw is not None else None)
        self.fixture.options["sha512"] = hashlib.sha512(archive.read_bytes()).hexdigest()
        plan = self.plan()
        with self.store() as store:
            self.apply(store, plan)
        destination = Path(plan.summary()["destination"])
        self.assertTrue(verify_tree(destination, plan.inventory, plan.customization.overlays)["tree_matches"])
        self.assertEqual((destination / "lib/data").stat().st_ino, (destination / "lib/hard").stat().st_ino)
        self.assertEqual(os.readlink(destination / "link"), "lib/data")
        self.assertEqual((destination / "lib").stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
