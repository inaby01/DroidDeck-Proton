#!/usr/bin/env python3
"""The inherited VC++ runtime record: reading, deciding, releasing and resuming (synthetic registries only)."""

import hashlib
import os
import runpy
import tempfile
import unittest
from pathlib import Path

runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
# The trusted entry point has already inserted the distribution path under -I.
import preparation_vc_record as vc
from preparation_common import Invalid

HEADER = "WINE REGISTRY Version 2\n"
VERSION = "v14.51.36247.00"


def esc(path):
    return path.replace("\\", "\\\\")


def runtimes(ident, version=VERSION, extra=()):
    lines = [f"[{esc(vc.KEYS[ident])}] 1795176401", "#time=1dc5a4b2c3d4e5f",
             '"Bld"=dword:00008d8f', '"Installed"=dword:00000001', '"Major"=dword:0000000e',
             '"Minor"=dword:00000033', '"Rbld"=dword:00000000', f'"Version"="{version}"', *extra]
    return "\n".join(lines) + "\n"


def block(idents=tuple(vc.KEYS), version=VERSION):
    return "\n".join(runtimes(ident, version) for ident in idents)


def scan(text):
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / "system.reg"
        path.write_text(HEADER + text)
        return vc.scan_file(path)


def template(**changes):
    keys = {ident: {"Bld": ("dword", 0x8d8f), "Installed": ("dword", 1), "Major": ("dword", 14), "Minor": ("dword", 51),
                    "Rbld": ("dword", 0), "Version": ("sz", VERSION)} for ident in vc.KEYS}
    return {"keys": keys, "version": VERSION, "tail_sha256": "a" * 64, "archive_has_keys": False, **changes}


def initial(text):
    return {"state": "captured", "keys": vc.fingerprint(scan(text)), "template_tail_sha256": "a" * 64}


NO_MFC = {"syswow64": "absent", "system32": "absent"}


class ScanTests(unittest.TestCase):
    def test_reads_the_six_keys_and_keeps_other_values_as_hashes(self):
        found = scan(block() + '[Software\\\\Other] 1\n"Password"="DUMMY_SECRET_VALUE"\n')
        self.assertEqual(set(vc.fingerprint(found)), set(vc.KEYS))
        self.assertEqual(found["keys"]["native-x86"]["values"]["Version"], ("sz", VERSION))
        self.assertNotIn("DUMMY_SECRET_VALUE", repr(found))
        self.assertTrue(found["runtimes_present"]["native"] and found["runtimes_present"]["wow"])

    def test_links_duplicates_and_sub_keys(self):
        text = (runtimes("native-x86", extra=('"Version"="v1"',)) + "[" + esc(vc.KEYS["native-x64"]) + "] 1\n#link\n" +
                "[" + esc(vc.KEYS["wow-x86"]) + "\\\\Child] 1\n\"A\"=dword:00000001\n" +
                "[Software\\\\Microsoft\\\\VisualStudio\\\\14.0] 1\n#link\n")
        found = scan(text)
        self.assertTrue(found["keys"]["native-x86"]["duplicate"])
        self.assertTrue(found["keys"]["native-x64"]["link"])
        self.assertEqual(found["keys"]["wow-x86"]["subkeys"], ["child"])
        self.assertTrue(found["keys"]["wow-x86"]["exists"])  # Implied by the child header (Wine omits empty parents).
        self.assertEqual(found["ancestor_links"], ["software\\microsoft\\visualstudio\\14.0"])

    def test_a_key_named_like_a_prefix_is_not_a_sub_key(self):
        found = scan("[" + esc(vc.KEYS["native-x86"]) + "foo] 1\n\"A\"=dword:00000001\n")
        self.assertEqual(found["keys"]["native-x86"]["subkeys"], [])
        self.assertFalse(found["keys"]["native-x86"]["exists"])

    def test_vc14_registrations_are_found_by_display_name_only(self):
        root = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\"
        found = scan(f'[{root}{{A}}] 1\n"DisplayName"="Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127"\n'
                     f'[{root}{{B}}] 1\n"DisplayName"="Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664"\n'
                     f'[{root}{{C}}\\\\Sub] 1\n"DisplayName"="Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.51"\n')
        self.assertEqual(found["uninstall"], {"vc14": 1, "unreadable": 0})
        found = scan(f'[{root}{{A}}] 1\n"DisplayName"=dword:00000001\n')
        self.assertEqual(found["uninstall"]["unreadable"], 1)


class TemplateTests(unittest.TestCase):
    def write(self, archive, tail):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        path = Path(root.name) / "system.reg"
        data = (HEADER + archive).encode()
        path.write_bytes(data + tail.encode())
        return path, len(data), hashlib.sha256(tail.encode()).hexdigest()

    def test_the_verified_tail_is_interpreted(self):
        path, size, digest = self.write("[Software\\\\Wine] 1\n", "\n" + block())
        found = vc.read_template(path, size, digest)
        self.assertEqual(found["version"], VERSION)
        self.assertEqual(set(found["keys"]), set(vc.KEYS))
        self.assertFalse(found["archive_has_keys"])

    def test_a_changed_tail_or_mixed_versions_are_refused(self):
        path, size, digest = self.write("", "\n" + block())
        with self.assertRaises(Invalid):
            vc.read_template(path, size, "b" * 64)
        path, size, digest = self.write("", "\n" + runtimes("native-x86") + runtimes("wow-x86", "v14.50.1.00"))
        with self.assertRaisesRegex(Invalid, "versions differ"):
            vc.read_template(path, size, digest)
        path, size, digest = self.write("", "\n[" + esc(vc.KEYS["native-x86"]) + '] 1\n"Installed"=dword:00000001\n')
        with self.assertRaisesRegex(Invalid, "version missing"):
            vc.read_template(path, size, digest)

    def test_keys_already_in_the_archive_part_are_flagged(self):
        path, size, digest = self.write(runtimes("native-x86"), "\n" + block())
        self.assertTrue(vc.read_template(path, size, digest)["archive_has_keys"])


class DecisionTests(unittest.TestCase):
    def decide(self, text, *, mfc=NO_MFC, tmpl=None, init="same", tail="a" * 64):
        found = scan(text)
        start = initial(text) if init == "same" else init
        return vc.evaluate(found, mfc, template() if tmpl is None else tmpl, start, tail)

    def test_inherited_values_are_released_with_empty_keys(self):
        decision = self.decide(block())
        self.assertEqual((decision["state"], decision["values"], decision["version"]), ("release", 36, VERSION))
        self.assertTrue(all(item["delete_key"] for item in decision["keys"].values()))

    def test_a_key_with_other_data_keeps_the_key(self):
        text = block().replace('"Rbld"=dword:00000000\n', '"Rbld"=dword:00000000\n"Other"="x"\n', 1)
        decision = self.decide(text)
        self.assertFalse(decision["keys"]["native-x86"]["delete_key"])
        self.assertTrue(decision["keys"]["wow-x64"]["delete_key"])

    def test_every_guard(self):
        root = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\"
        cases = {
            "absent": self.decide("")["state"],
            "kept": self.decide(block(), mfc={"syswow64": "native", "system32": "absent"})["state"],
            "registered": self.decide(block() + f'[{root}{{A}}] 1\n"DisplayName"="Microsoft Visual C++ 2015-2019 '
                                      'Redistributable (x86) - 14.24.28127"\n')["reason"],
            "template": self.decide(block(), tmpl=Invalid("x"))["reason"],
            "archive": self.decide(block(), tmpl=template(archive_has_keys=True))["reason"],
            "legacy": self.decide(block(), init=None)["reason"],
            "unreadable": self.decide(block(), init={"state": "unreadable", "error_class": "OSError"})["reason"],
            "changed": self.decide(block(), tail="b" * 64)["reason"],
            "shape": self.decide(block() + "[" + esc(vc.KEYS["native-x86"]) + "] 2\n")["reason"],
            "values": self.decide(block(version="v14.40.1.00"))["reason"],
            "since-init": self.decide(block(), init=initial(block(("native-x86",))))["reason"],
        }
        self.assertEqual(cases, {"absent": "absent", "kept": "kept-vc-present", "registered": "vc-registered-without-mfc140",
                                 "template": "template-mismatch", "archive": "keys-in-archive",
                                 "legacy": "no-initial-fingerprint", "unreadable": "initial-fingerprint-unreadable",
                                 "changed": "template-changed", "shape": "registry-shape", "values": "values-differ",
                                 "since-init": "values-differ"})
        self.assertFalse(self.decide(block(), init=None)["retryable"])


class ReleaseTests(unittest.TestCase):
    def test_command_stops_a_key_at_its_first_failure_and_joins_keys(self):
        plan = {"native-x86": {"values": {"Version": "h", "Installed": "h"}, "delete_key": True, "kept": "k"},
                "wow-x64": {"values": {"Bld": "h"}, "delete_key": False, "kept": "k"}}
        key = "HKLM\\" + vc.KEYS["native-x86"]
        wow = "HKLM\\" + vc.KEYS["wow-x64"]
        self.assertEqual(vc.command(plan), (
            "cmd.exe", "/d", "/c", vc.REG, "delete", key, "/v", "Installed", "/reg:64", "/f", "&&",
            vc.REG, "delete", key, "/v", "Version", "/reg:64", "/f", "&&", vc.REG, "delete", key, "/reg:64", "/f", "&",
            vc.REG, "delete", wow, "/v", "Bld", "/reg:64", "/f"))

    def test_verify_requires_deleted_keys_gone_and_kept_data_unchanged(self):
        text = block().replace('"Rbld"=dword:00000000\n', '"Rbld"=dword:00000000\n"Other"="x"\n', 1)
        plan = vc.evaluate(scan(text), NO_MFC, template(), initial(text), "a" * 64)["keys"]
        runtimes_only = "[Software\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n" \
                        "[Software\\\\Wow6432Node\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n"
        kept = "[" + esc(vc.KEYS["native-x86"]) + '] 1\n"Other"="x"\n'
        self.assertIsNone(vc.verify(plan, scan(runtimes_only + kept)))
        self.assertEqual(vc.verify(plan, scan(runtimes_only + kept + runtimes("wow-x64"))), "values-remain")
        self.assertEqual(vc.verify(plan, scan(runtimes_only + kept + "[" + esc(vc.KEYS["wow-x64"]) + "] 1\n")), "keys-remain")
        self.assertEqual(vc.verify(plan, scan(runtimes_only)), "removed-too-much")
        self.assertEqual(vc.verify(plan, scan(kept)), "removed-too-much")

    def test_resume_continues_only_from_a_subset_of_the_original(self):
        text = block()
        original = vc.evaluate(scan(text), NO_MFC, template(), initial(text), "a" * 64)["keys"]
        partly = text.replace('"Installed"=dword:00000001\n', "", 1)
        decision = vc.resume(scan(partly), NO_MFC, original)
        self.assertEqual(decision["state"], "release")
        self.assertNotIn("Installed", decision["keys"]["native-x86"]["values"])
        runtimes_only = ("[Software\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n"
                         "[Software\\\\Wow6432Node\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n")
        self.assertEqual(vc.resume(scan(runtimes_only), NO_MFC, original)["state"], "absent-after-release")
        # An empty key left behind is not finished (design 4 resume).
        empty = runtimes_only + "[" + esc(vc.KEYS["native-x86"]) + "] 1\n"
        self.assertEqual(vc.resume(scan(empty), NO_MFC, original)["keys"], {"native-x86": {
            "values": {}, "delete_key": True, "kept": original["native-x86"]["kept"]}})
        self.assertEqual(vc.resume(scan(block(version="v14.24.28127.00")), NO_MFC, original)["reason"],
                         "investigation-required")
        self.assertEqual(vc.resume(scan(text), {"syswow64": "native", "system32": "absent"}, original)["state"],
                         "kept-vc-present")


class GuardDetailTests(unittest.TestCase):
    """Each guard on its own (Fable code review M2: a removed check must fail a test)."""

    def evaluate(self, text, init=None, tail="a" * 64):
        found = scan(text)
        return vc.evaluate(found, NO_MFC, template(), initial(block()) if init is None else init, tail)

    def test_link_and_value_duplicates_and_unreadable_names_stop(self):
        linked = block().replace(f"[{esc(vc.KEYS['wow-x64'])}] 1795176401\n", f"[{esc(vc.KEYS['wow-x64'])}] 1795176401\n#link\n")
        self.assertEqual(self.evaluate(linked)["reason"], "registry-shape")
        ancestor = block() + "[Software\\\\Wow6432Node\\\\Microsoft\\\\VisualStudio] 1\n#link\n"
        self.assertEqual(self.evaluate(ancestor)["reason"], "registry-shape")
        twice = block().replace('"Bld"=dword:00008d8f\n', '"Bld"=dword:00008d8f\n"bld"=dword:00008d8f\n', 1)
        self.assertEqual(self.evaluate(twice)["reason"], "registry-shape")
        root = "Software\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\"
        self.assertEqual(self.evaluate(block() + f'[{root}{{A}}] 1\n"DisplayName"=hex:00\n')["reason"], "uninstall-unreadable")
        self.assertEqual(self.evaluate(block() + f'[{root}{{A}}] 1\n"DisplayName"="Microsoft Visual C++ 2015-2019 '
                                       'Redistributable (x86) - 14.24.28127"\n')["reason"], "vc-registered-without-mfc140")

    def test_the_initial_template_hash_must_match(self):
        start = {**initial(block()), "template_tail_sha256": "b" * 64}
        self.assertEqual(self.evaluate(block(), init=start)["reason"], "template-changed")

    def test_mfc140_as_a_link_or_directory_counts_as_present(self):
        with tempfile.TemporaryDirectory() as root:
            wow = Path(root) / "pfx/drive_c/windows/syswow64"
            wow.mkdir(parents=True)
            (wow / "mfc140.dll").symlink_to("/nonexistent")
            self.assertEqual(vc.mfc140(Path(root))["syswow64"], "other")

    def test_a_template_read_error_can_be_retried_but_a_mismatch_cannot(self):
        found = vc.evaluate(scan(block()), NO_MFC, PermissionError(13, "denied"), initial(block()), "a" * 64)
        self.assertEqual((found["reason"], found["retryable"]), ("template-unreadable:PermissionError", True))
        found = vc.evaluate(scan(block()), NO_MFC, Invalid("template tail changed"), initial(block()), "a" * 64)
        self.assertEqual((found["reason"], found["retryable"]), ("template-mismatch", False))

    def test_same_state_notices_any_change_of_what_was_decided_on(self):
        before = scan(block())
        self.assertTrue(vc.same_state(before, scan(block())))
        self.assertFalse(vc.same_state(before, scan(block(version="v14.24.28127.00"))))
        self.assertFalse(vc.same_state(before, scan(block() + "[" + esc(vc.KEYS["native-x86"]) + "\\\\Child] 1\n")))

    def test_mfc140_duplicates_and_directories_count_as_present_without_leaking(self):
        with tempfile.TemporaryDirectory() as root:
            wow = Path(root) / "pfx/drive_c/windows/syswow64"
            (wow / "mfc140.dll").mkdir(parents=True)
            before = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
            self.assertEqual(vc.mfc140(Path(root))["syswow64"], "other")
            if before is not None:
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            (wow / "MFC140.DLL").write_bytes(b"MZ")
            self.assertEqual(vc.mfc140(Path(root))["syswow64"], "other")

    def test_resume_refuses_when_more_than_planned_is_gone_or_changed(self):
        text = block().replace('"Rbld"=dword:00000000\n', '"Rbld"=dword:00000000\n"Other"="x"\n', 1)
        original = vc.evaluate(scan(text), NO_MFC, template(), initial(text), "a" * 64)["keys"]
        parents = ("[Software\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n"
                   "[Software\\\\Wow6432Node\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n")
        kept = "[" + esc(vc.KEYS["native-x86"]) + '] 1\n"Other"="x"\n'
        self.assertEqual(vc.resume(scan(parents + kept), NO_MFC, original)["state"], "absent-after-release")
        self.assertEqual(vc.resume(scan(parents), NO_MFC, original)["reason"], "investigation-required")  # Kept key gone.
        self.assertEqual(vc.resume(scan(kept), NO_MFC, original)["reason"], "investigation-required")  # Parents gone.
        changed = "[" + esc(vc.KEYS["native-x86"]) + '] 1\n"Other"="y"\n'
        self.assertEqual(vc.resume(scan(parents + changed), NO_MFC, original)["reason"], "investigation-required")
        linked = parents + kept.replace("] 1\n", "] 1\n#link\n", 1)
        self.assertEqual(vc.resume(scan(linked), NO_MFC, original)["reason"], "investigation-required")


class FinalReviewTests(unittest.TestCase):
    """Codex final review: link marks with a note, sub-key links, resume checks, QWORD values."""

    def test_a_link_mark_with_anything_after_it_and_a_sub_key_link_stop(self):
        noted = block() + "[Software\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC] 1\n#link to elsewhere\n"
        found = scan(noted)
        self.assertEqual(found["ancestor_links"], ["software\\microsoft\\visualstudio\\14.0\\vc"])
        self.assertEqual(vc.evaluate(found, NO_MFC, template(), initial(block()), "a" * 64)["reason"], "registry-shape")
        child = block() + "[" + esc(vc.KEYS["wow-x86"]) + "\\\\Child] 1\n#link\n"
        found = scan(child)
        self.assertTrue(found["keys"]["wow-x86"]["link"])
        self.assertEqual(vc.evaluate(found, NO_MFC, template(), initial(block()), "a" * 64)["reason"], "registry-shape")

    def test_a_qword_beside_the_inherited_values_is_kept(self):
        qword = '"Other"=hex(b):01,00,00,00,00,00,00,00\n'
        self.assertEqual(vc.evaluate(scan(f"[{esc(vc.KEYS['native-x86'])}] 1\n" + qword), NO_MFC, Invalid("x"), None,
                                     None)["state"], "absent")
        text = block().replace('"Rbld"=dword:00000000\n', '"Rbld"=dword:00000000\n' + qword, 1)
        decision = vc.evaluate(scan(text), NO_MFC, template(), initial(text), "a" * 64)
        self.assertEqual((decision["state"], decision["keys"]["native-x86"]["delete_key"]), ("release", False))

    def test_resume_checks_vc_registrations_too(self):
        original = vc.evaluate(scan(block()), NO_MFC, template(), initial(block()), "a" * 64)["keys"]
        root = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\"
        added = block() + f'[{root}{{A}}] 1\n"DisplayName"="Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.24"\n'
        self.assertEqual(vc.resume(scan(added), NO_MFC, original)["reason"], "vc-registered-without-mfc140")

    def test_verify_looks_at_the_whole_original_plan(self):
        text = block().replace('"Rbld"=dword:00000000\n', '"Rbld"=dword:00000000\n"Other"="x"\n', 1)
        original = vc.evaluate(scan(text), NO_MFC, template(), initial(text), "a" * 64)["keys"]
        parents = ("[Software\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n"
                   "[Software\\\\Wow6432Node\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes] 1\n")
        self.assertEqual(vc.verify(original, scan(parents)), "removed-too-much")  # The kept key handled earlier is gone.

    def test_a_read_error_before_any_decision_does_not_hide_an_unfinished_release(self):
        keys = {"native-x86": {"values": {"Version": "a" * 64}, "delete_key": True, "kept": "b" * 64}}
        releasing = {"install_id": "depinstall-" + "1" * 32, "inherited_vc_record": {"state": "releasing", "keys": keys}}
        unreadable = {"install_id": "depinstall-" + "2" * 32,
                      "inherited_vc_record": vc.failed("registry-unreadable:OSError")}
        self.assertIs(vc.unfinished([releasing, unreadable]), releasing)


class RecordTests(unittest.TestCase):
    def test_unfinished_is_the_newest_evaluated_release_only(self):
        keys = {"native-x86": {"values": {"Version": "a" * 64}, "delete_key": True, "kept": "b" * 64}}
        releasing = {"install_id": "depinstall-" + "1" * 32, "inherited_vc_record": {"state": "releasing", "keys": keys}}
        winver_only = {"install_id": "depinstall-" + "2" * 32, "inherited_vc_record": {"state": "not-evaluated"}}
        done = {"install_id": "depinstall-" + "3" * 32, "inherited_vc_record": {"state": "released", "keys": keys}}
        self.assertIs(vc.unfinished([releasing, winver_only]), releasing)
        self.assertIsNone(vc.unfinished([releasing, done, winver_only]))
        stopped = {"inherited_vc_record": vc.failed("no-initial-fingerprint")}
        retry = {"inherited_vc_record": vc.failed("wait-timeout")}
        self.assertEqual(vc.final_stop([retry, stopped, winver_only]), "no-initial-fingerprint")
        self.assertIsNone(vc.final_stop([stopped, retry]))

    def test_record_shapes(self):
        vc.validate_record({"state": "not-evaluated"})
        vc.validate_record({**vc.failed("registry-unreadable:OSError"), "values": 6})
        vc.validate_record({"state": "released", "values": 36, "version": VERSION, "exit_code": 0, "resumed_from": None,
                            "keys": {"wow-arm64": {"values": {"Bld": "a" * 64}, "delete_key": True, "kept": "b" * 64}},
                            "wineserver_observed": True, "wineserver_gone_before_read": True})
        for bad in ({"state": "released", "reason": "x"}, {"state": "failed"}, {"state": "absent", "secret": 1},
                    {"state": "released", "keys": {"elsewhere": {}}}):
            with self.assertRaises(Invalid):
                vc.validate_record(bad)
        with self.assertRaises(Invalid):
            vc.failed("not-a-known-reason")
        vc.validate_initial({"state": "none", "template_tail_sha256": None})
        with self.assertRaises(Invalid):
            vc.validate_initial({"state": "captured", "keys": {}, "template_tail_sha256": None})

    def test_capture_never_raises(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(vc.capture_initial(Path(root) / "missing", None)["state"], "unreadable")
            (Path(root) / "pfx").mkdir()
            (Path(root) / "pfx/system.reg").write_text(HEADER + block(("native-x86",)))
            found = vc.capture_initial(Path(root), "c" * 64)
            self.assertEqual((found["state"], set(found["keys"]), found["template_tail_sha256"]),
                             ("captured", {"native-x86"}, "c" * 64))

    def test_mfc140_kinds(self):
        with tempfile.TemporaryDirectory() as root:
            windows = Path(root) / "pfx/drive_c/windows"
            (windows / "syswow64").mkdir(parents=True)
            self.assertEqual(vc.mfc140(Path(root)), {"syswow64": "absent", "system32": "absent"})
            (windows / "syswow64/MFC140.dll").write_bytes(b"MZ" + b"\0" * 0x3e + b"Wine builtin DLL" + b"\0" * 48)
            self.assertEqual(vc.mfc140(Path(root))["syswow64"], "wine-builtin")
            (windows / "syswow64/MFC140.dll").write_bytes(b"MZ" + b"\0" * 0x7e)
            self.assertEqual(vc.mfc140(Path(root))["syswow64"], "native")


if __name__ == "__main__":
    unittest.main()
