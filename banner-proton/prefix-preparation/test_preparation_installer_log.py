#!/usr/bin/env python3
"""The diagnostic installer log: summary forms, writer count, shared copy and the bundle option."""

import io
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
# The trusted entry point has already inserted the distribution path under -I.
import preparation_installer_log as log
import preparation_store as storage
from preparation_common import Invalid

INSTALL_ID = "depinstall-" + "a" * 32


class SummaryTests(unittest.TestCase):
    def test_line_forms_of_the_pinned_wine(self):
        lines = [
            "0024:err:msi:ITERATE_Actions Execution halted, action L\"InstallFiles\" returned 1603",
            "00024:err:msi:ITERATE_Actions Execution halted, action L\"Other.Name\" returned 1627",   # five digits
            "  12.345:0024:0028:warn:msi:execute_script something",                                  # padded time
            "err:module:import_dll Library X.dll not found",                                         # no ID yet
            "0024:err:ole:CoGetClassObject class not registered",
            "0024:err:winediag:loader_init not a listed channel",
            "0024:fixme:msi:ignored fixme lines are not listed",
            "wine: Call from 7B000000 to unimplemented function a.dll.B, aborting",
            "wine: Unhandled exception 0xc0000005 in thread 24 at address 0, starting debugger...",
            "wine: something else",
        ]
        summary = log.summarize("\n".join(lines).encode())
        self.assertEqual(summary["channels"], {"err:module": 1, "err:msi": 2, "err:ole": 1, "warn:msi": 1})
        self.assertEqual(summary["functions"]["err:msi:ITERATE_Actions"], 2)
        self.assertEqual(summary["functions"]["err:ole:other"], 1)  # Not in the pinned list.
        self.assertEqual(summary["returned"], {"1603": 1, "1627": 1})
        self.assertEqual(summary["wine"], {"other": 1, "unhandled-exception": 1, "unimplemented-function": 1})
        actions = [entry.get("action") for entry in summary["entries"] if "action" in entry]
        self.assertEqual(actions, ["InstallFiles", "custom"])

    def test_no_path_or_name_reaches_the_summary(self):
        lines = ['0024:err:msi:ITERATE_Actions Execution halted, action L"Example_Game" returned 1603',
                 '0024:err:module:Example_Game L"Z:\\\\root\\\\Storage\\\\Example Game\\\\a.dll" /root/Storage/Example Game',
                 '0024:err:setupapi:do_file_copyW C:\\users\\steamuser\\Example', "wine: /root/Example Game failed"]
        text = json.dumps(log.summarize("\n".join(lines).encode()))
        for secret in ("Example", "root", "Storage", "steamuser", "Z:", "C:"):
            self.assertNotIn(secret, text)

    def test_deciding_lines_are_kept_and_the_size_is_bounded(self):
        noise = [f"0024:err:ole:CoGetClassObject noise {index}" for index in range(500)]
        last = '0024:err:msi:ITERATE_Actions Execution halted, action L"StartServices" returned 1920'
        summary = log.summarize("\n".join(noise + [last]).encode())
        self.assertLessEqual(len(summary["entries"]), log.MAX_ENTRIES)
        self.assertLessEqual(len(json.dumps(summary)), log.MAX_SUMMARY)
        self.assertIn({"class": "err:msi", "function": "ITERATE_Actions", "returned": 1920, "action": "StartServices"},
                      summary["entries"])
        self.assertEqual(summary["lines"], 501)

    def test_head_and_tail_of_a_large_file(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as root:
            path = Path(root) / "final.log"
            middle = b"x" * (log.HEAD + log.TAIL)
            path.write_bytes(b"0024:err:msi:ITERATE_Actions first\n" + middle +
                             b"\n0024:err:msi:ITERATE_Actions Execution halted, action L\"InstallFiles\" returned 1603\n")
            summary = log.summarize_file(path)
        self.assertEqual(summary["returned"], {"1603": 1})
        self.assertEqual(summary["channels"]["err:msi"], 2)


class OptionTests(unittest.TestCase):
    def test_the_bundle_option_is_a_strict_boolean(self):
        self.assertTrue(log.enabled({"diagnostics": {"installer_log": True}}))
        for value in ({}, {"diagnostics": {}}, {"diagnostics": {"installer_log": 1}}, {"diagnostics": {"installer_log": "true"}}):
            self.assertFalse(log.enabled(value))
        log.validate_diagnostics({"installer_log": False})
        for bad in ({"installer_log": 1}, {"installer_log": True, "other": True}):
            with self.assertRaises(Invalid):
                log.validate_diagnostics(bad)


class WriterTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "/proc is Linux only")
    def test_processes_holding_the_log_are_counted(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as root:
            path = Path(root) / "live.log"
            path.write_bytes(b"")
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            self.assertEqual(log._writers(identity, "/proc")[0], 0)
            with open(path, "ab") as stream:
                child = subprocess.Popen(["sleep", "30"], stderr=stream)
            try:
                remaining, _ = log._writers(identity, "/proc")
                self.assertEqual(remaining, 1)
            finally:
                child.terminate()  # Only the test's own child.
                child.wait()


class CopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        base = Path(self.temporary.name)
        self.home = base / "home"
        (self.home / "state").mkdir(parents=True, mode=0o700)
        self.store_root = self.home / "state/tool-store"
        self.shared = base / "shared"
        self.shared.mkdir(mode=0o700)
        folder = log.work_parent(self.home, "42")
        folder.mkdir(parents=True, mode=0o700)
        self.folder = log.log_folder(self.home, "42", INSTALL_ID)
        self.folder.mkdir(parents=True, mode=0o700)
        (self.folder / log.FINAL).write_bytes(b"0024:err:msi:x final\n")
        import hashlib
        final = {"bytes": 21, "sha256": hashlib.sha256(b"0024:err:msi:x final\n").hexdigest(), "writers_remaining": 0,
                 "writers_unreadable": 0, "summary": {}}
        with storage.PrivateStore(self.store_root, create=True) as store, store.locked("c" * 64):
            store.write_record(log.RECORDS, INSTALL_ID + ".json",
                               {**log._record(INSTALL_ID, "42", "open"), "state": "final", "final": final})

    def tearDown(self):
        self.temporary.cleanup()

    def offer(self, answer, saved=None, statuses=None):
        view = {"install_id": INSTALL_ID, "app_id": "42", "state": "final", "bytes": 21}
        output = io.StringIO()
        done = log.offer_shared_copies([view], statuses or {INSTALL_ID: "partial"},
                                       saved=self.shared / "plan-1.json" if saved is None else saved,
                                       shared_folder=self.shared, store_root=self.store_root, home=self.home,
                                       stream=io.StringIO(answer), output=output, text=str)
        return done, output.getvalue()

    def test_copied_only_after_the_operator_confirms(self):
        done, output = self.offer("q\n")
        self.assertEqual(done, [{"install_id": INSTALL_ID, "copied": False, "reason": "declined"}])
        self.assertEqual(list(self.shared.iterdir()), [])
        self.assertIn("回収できません", output)
        done, output = self.offer("1\n")
        name = "installer-" + INSTALL_ID + ".log"
        self.assertEqual(done[0]["name"], name)
        self.assertEqual((self.shared / name).read_bytes(), b"0024:err:msi:x final\n")
        self.assertEqual(sorted(p.name for p in self.shared.iterdir()), [name])  # No temporary file left.

    def test_never_replaced_and_never_for_a_verified_install_or_a_private_result(self):
        name = "installer-" + INSTALL_ID + ".log"
        (self.shared / name).write_bytes(b"existing")
        with storage.PrivateStore(self.store_root) as store, store.locked("c" * 64):
            self.assertEqual(log.copy_to_shared(store, INSTALL_ID, "42", self.home, self.shared),
                             (None, "not-copied:name-exists"))
        self.assertEqual((self.shared / name).read_bytes(), b"existing")
        self.assertEqual(self.offer("1\n", statuses={INSTALL_ID: "present-verified"})[0], [])
        self.assertEqual(self.offer("1\n", saved=self.home / "plan-1.json")[0], [])  # Result kept privately.

    def test_a_link_is_used_where_renameat2_is_missing_and_neither_leaves_a_partial_copy(self):
        from unittest import mock

        import preparation_publication as publication
        with mock.patch.object(publication, '_rename_function', side_effect=Invalid('libc renameat2 unavailable')):
            done, _ = self.offer("1\n")
        self.assertTrue(done[0]["copied"], done)
        (self.shared / done[0]["name"]).unlink()
        with storage.PrivateStore(self.store_root) as store, store.locked("c" * 64):
            record, digest = store.read_record(log.RECORDS, INSTALL_ID + ".json")
            store.write_record(log.RECORDS, INSTALL_ID + ".json", {**record, "shared_copy": None}, digest)
        with mock.patch.object(publication, '_rename_function', side_effect=Invalid('libc renameat2 unavailable')), \
                mock.patch.object(log.os, 'link', side_effect=PermissionError(1, 'not permitted')):
            done, _ = self.offer("1\n")
        self.assertEqual((done[0]["copied"], done[0]["reason"]), (False, "not-copied:PermissionError"))
        self.assertEqual(list(self.shared.iterdir()), [])

    def test_the_game_is_named_in_the_prompt(self):
        view = {"install_id": INSTALL_ID, "app_id": "42", "state": "final", "bytes": 21}
        output = io.StringIO()
        log.offer_shared_copies([view], {INSTALL_ID: "partial"}, saved=self.shared / "plan-1.json", shared_folder=self.shared,
                                store_root=self.store_root, home=self.home, stream=io.StringIO("q\n"), output=output,
                                text=str, labels={INSTALL_ID: "Example [ID 42]"})
        self.assertIn("ゲーム: Example [ID 42]", output.getvalue())

    def test_noting_the_copies_keeps_what_the_saved_result_holds(self):
        path = self.shared / "plan-1.json"
        path.write_text(json.dumps({"mode": "x", "writes": [{"scope": "report-only", "filename": "plan-1.json"}],
                                    "report_storage": {"authoritative": "private"}, "title": "日本語"}))
        self.assertTrue(log.rewrite_result(path, [{"install_id": INSTALL_ID, "copied": True}]))
        saved = json.loads(path.read_text())
        self.assertEqual(saved["writes"], [{"scope": "report-only", "filename": "plan-1.json"}])
        self.assertEqual(saved["report_storage"], {"authoritative": "private"})
        self.assertEqual((saved["title"], saved["installer_log_copies"][0]["copied"]), ("日本語", True))
        self.assertNotIn("日本語", path.read_text())  # The same ASCII form as the saved result.
        self.assertEqual(sorted(p.name for p in self.shared.iterdir()), ["plan-1.json"])

    def test_a_changed_log_is_not_copied(self):
        (self.folder / log.FINAL).write_bytes(b"changed after it was fixed\n")
        done, _ = self.offer("1\n")
        self.assertFalse(done[0]["copied"])
        self.assertEqual(list(self.shared.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
