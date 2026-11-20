#!/usr/bin/env python3
"""Payload identity with generated archives only; no real runtime is executed."""

import gzip
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURES = runpy.run_path(str(Path(__file__).with_name("test_prepare_game.py")))
import preparation_payload as payload
from preparation_common import Invalid

ROOT = "Example Proton 日本語"
MEMBERS = [("files", "directory", None, 0o755), ("files/bin-arm64", "directory", None, 0o755),
           ("proton", "file", b"#!/bin/sh\nexit 0\n", 0o755),
           ("files/bin-arm64/wine", "file", b"dummy-wine-not-executed", 0o755),
           ("wine", "symlink", "files/bin-arm64/wine", 0o777)]


class PayloadTests(unittest.TestCase):
    write_json = FIXTURES["InspectionTests"].write_json
    snapshot = FIXTURES["InspectionTests"].snapshot

    def setUp(self):
        FIXTURES["InspectionTests"].setUp(self)
        self.archive = self.root / "Example Proton.tar.gz"
        self.installed = self.root / "installed"
        self.installed.mkdir()
        for name, kind, data, mode in MEMBERS:
            path = self.installed / name
            if kind == "directory":
                path.mkdir()
            elif kind == "symlink":
                path.symlink_to(data)
            else:
                path.write_bytes(data)
                path.chmod(mode)
        self.make_archive()

    def make_archive(self, entries=None):
        entries = MEMBERS if entries is None else entries
        with tarfile.open(self.archive, "w:gz") as package:
            root = tarfile.TarInfo(ROOT)
            root.type, root.mode = tarfile.DIRTYPE, 0o755
            package.addfile(root)
            for name, kind, data, mode in entries:
                info = tarfile.TarInfo(name if name.startswith("/") else ROOT + "/" + name)
                info.mode = mode
                info.type = {"file":tarfile.REGTYPE, "directory":tarfile.DIRTYPE, "symlink":tarfile.SYMTYPE,
                             "hardlink":tarfile.LNKTYPE, "fifo":tarfile.FIFOTYPE}[kind]
                if kind == "file":
                    info.size = len(data)
                    package.addfile(info, io.BytesIO(data))
                else:
                    if data is not None:
                        info.linkname = data
                    package.addfile(info)
        self.sha = hashlib.sha512(self.archive.read_bytes()).hexdigest()

    def inspect(self, **kwargs):
        return payload.inspect_archive(kwargs.get("path",self.archive),kwargs.get("sha",self.sha),kwargs.get("root",ROOT))

    def cli(self, *extra):
        script = Path(__file__).with_name("prepare_game.py")
        return subprocess.run([sys.executable,"-I","-B",str(script),"--inspect-payload",
                               "--payload-archive",str(self.archive),"--payload-sha512",self.sha,
                               "--payload-root",ROOT,*extra],capture_output=True,text=True,check=False)

    def fex_fixture(self):
        self.installed.chmod(0o755)
        (self.installed / 'files/share/fex-emu').mkdir(parents=True)
        self.make_archive(MEMBERS + [('files/share', 'directory', None, 0o755),
                                    ('files/share/fex-emu', 'directory', None, 0o755)])
        directory = self.installed / payload.FEX_RUNTIME_DIRECTORY
        directory.mkdir(mode=0o700)
        return directory, self.inspect()

    def test_fex_contract_accepts_only_the_empty_runtime_directory_without_weakening_strict_verifier(self):
        directory, inventory = self.fex_fixture()
        before = self.snapshot()
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed, inventory)
        result = payload.verify_fex_runtime_tree(self.installed, inventory)
        self.assertEqual(result['runtime_contract'], payload.FEX_RUNTIME_CONTRACT)
        self.assertTrue(result['runtime_directory_empty'])
        self.assertFalse(result['execution_authorized'])
        self.assertEqual(before, self.snapshot())
        self.assertTrue(directory.exists())

    def test_fex_contract_refuses_nonempty_directory_without_reading_configuration(self):
        directory, inventory = self.fex_fixture()
        file = directory / 'DUMMY_PRIVATE.json'
        file.write_text('{"DUMMY_SECRET": true}')
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        self.assertIn('DUMMY_SECRET', file.read_text())

    def test_fex_contract_refuses_wrong_modes_and_symlink(self):
        directory, inventory = self.fex_fixture()
        directory.chmod(0o755)
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        directory.chmod(0o700)
        directory.rmdir()
        directory.symlink_to(self.root)
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)

    def test_fex_contract_does_not_ignore_other_extras_or_unprivate_parent(self):
        _directory, inventory = self.fex_fixture()
        extra = self.installed / 'unexpected'
        extra.write_bytes(b'x')
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        extra.unlink()
        self.root.chmod(0o755)
        self.addCleanup(self.root.chmod, 0o700)
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)

    def test_fex_contract_refuses_source_owned_directory_collision(self):
        _directory, _ = self.fex_fixture()
        self.make_archive(MEMBERS + [('files/share', 'directory', None, 0o755),
            ('files/share/fex-emu', 'directory', None, 0o755),
            (payload.FEX_RUNTIME_DIRECTORY, 'directory', None, 0o700)])
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, self.inspect())

    REG = b'WINE REGISTRY Version 2\n;; All keys relative to \\\\Machine\n\n[Software\\\\Wine] 1\n"Version"="synthetic"\n'
    TAIL = (b'\n[Software\\\\Valve\\\\Steam\\\\Apps\\\\CommonRedist\\\\vcredist\\\\2019] 1795176401\n'
            b'"x86 14.28.29334.0"=dword:00000001\n'
            b'\n[Software\\\\Wow6432Node\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes\\\\x86] 1795176401\n'
            b'"Installed"=dword:00000001\n"Version"="v14.51.36247.00"\n')

    def redist_fixture(self):
        """FEX contract tree plus a default prefix template, as DroidDeck sees the preparation slot."""
        self.installed.chmod(0o755)
        template = self.installed / payload.REDIST_TEMPLATE
        template.mkdir(parents=True)
        (template / 'system.reg').write_bytes(self.REG)
        (template / 'system.reg').chmod(0o644)
        (self.installed / 'files/share/fex-emu').mkdir()
        self.make_archive(MEMBERS + [('files/share', 'directory', None, 0o755),
                                    ('files/share/fex-emu', 'directory', None, 0o755),
                                    ('files/share/default_pfx_arm64', 'directory', None, 0o755),
                                    (payload.REDIST_REGISTRY, 'file', self.REG, 0o644)])
        (self.installed / payload.FEX_RUNTIME_DIRECTORY).mkdir(mode=0o700)
        return template, self.inspect()

    def droiddeck_redist_step(self, template, tail=None):
        with open(template / 'system.reg', 'ab') as handle:
            handle.write(self.TAIL if tail is None else tail)
        (template / '.droiddeck-redists').write_bytes(b'synthetic marker list\n')
        (template / '.droiddeck-redists').chmod(0o644)
        (template / '.droiddeck-redists-checked').write_bytes(b'')
        (template / '.droiddeck-redists-checked').chmod(0o644)

    def test_runtime_contract_accepts_only_droiddeck_redist_markers_and_strict_verifier_stays_strict(self):
        template, inventory = self.redist_fixture()
        self.assertIsNone(payload.verify_fex_runtime_tree(self.installed, inventory)['droiddeck_redist'])
        self.droiddeck_redist_step(template)
        before = self.snapshot()
        result = payload.verify_fex_runtime_tree(self.installed, inventory)['droiddeck_redist']
        self.assertEqual(result['contract'], payload.DROIDDECK_REDIST_CONTRACT)
        self.assertEqual((result['registry_sections'], result['registry_appended_bytes']), (2, len(self.TAIL)))
        self.assertEqual(sorted(result['markers']), ['.droiddeck-redists', '.droiddeck-redists-checked'])
        self.assertEqual(before, self.snapshot())
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed, inventory)
        # The checked marker may still be missing right after the step.
        (template / '.droiddeck-redists-checked').unlink()
        payload.verify_fex_runtime_tree(self.installed, inventory)

    def test_runtime_contract_refuses_other_registry_changes_and_unsafe_markers(self):
        cases = {
            'other key': b'\n[Software\\\\Wine\\\\DllOverrides] 1\n"mfc42"="native"\n',
            'other value type': b'\n[Software\\\\Valve\\\\Steam\\\\Apps\\\\CommonRedist\\\\DirectX] 1\n"x"=hex:01\n',
            'value before any section': b'\n"Version"="v1"\n',
            'no trailing newline': self.TAIL[:-1],
        }
        for label, tail in cases.items():
            with self.subTest(label=label):
                template, inventory = self.redist_fixture()
                self.droiddeck_redist_step(template, tail)
                with self.assertRaises(Invalid):
                    payload.verify_fex_runtime_tree(self.installed, inventory)
                self.tearDown()
                self.setUp()
        template, inventory = self.redist_fixture()
        # Archive bytes changed in place, with an allowed tail appended.
        (template / 'system.reg').write_bytes(self.REG.replace(b'synthetic', b'Synthetic') + self.TAIL)
        (template / '.droiddeck-redists').write_bytes(b'x')
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        # An allowed tail without DroidDeck's marker file.
        (template / 'system.reg').write_bytes(self.REG + self.TAIL)
        (template / '.droiddeck-redists').unlink()
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        # Unsafe markers: executable, symlink, another name.
        (template / '.droiddeck-redists').write_bytes(b'x')
        (template / '.droiddeck-redists').chmod(0o755)
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        (template / '.droiddeck-redists').unlink()
        (template / '.droiddeck-redists').symlink_to(self.root)
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)
        (template / '.droiddeck-redists').unlink()
        (template / '.droiddeck-other').write_bytes(b'x')
        with self.assertRaises(Invalid):
            payload.verify_fex_runtime_tree(self.installed, inventory)

    def test_difference_audit_aggregates_changes_extras_and_missing_without_adoption(self):
        self.installed.chmod(0o755)
        (self.installed / "proton").write_bytes(b"changed-content")
        (self.installed / "proton").chmod(0o600)
        (self.installed / "files/bin-arm64/wine").unlink()
        extra = self.installed / "DUMMY_PRIVATE_NAME"
        extra.write_bytes(b"DUMMY_PRIVATE_CONTENT")
        result = payload.inspect_tree_differences(self.installed, self.inspect())
        checks = [item["check"] for item in result["differences"]]
        self.assertIn("entry-differs", checks)
        self.assertIn("missing-object", checks)
        self.assertIn("unexpected-object", checks)
        self.assertFalse(result["observed_tree_matches"])
        self.assertFalse(result["unknown_contents_read"])
        self.assertFalse(result["execution_authorized"])
        self.assertNotIn("DUMMY_PRIVATE", json.dumps(result))
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed, self.inspect())
        self.assertEqual(extra.read_bytes(), b"DUMMY_PRIVATE_CONTENT")

    def test_difference_audit_does_not_traverse_unknown_directories_or_links(self):
        self.installed.chmod(0o755)
        cache = self.installed / "__pycache__"
        cache.mkdir()
        (cache / "DUMMY_PRIVATE_FILE").write_bytes(b"DUMMY_PRIVATE_BYTES")
        (self.installed / "DUMMY_PRIVATE_LINK").symlink_to(cache)
        result = payload.inspect_tree_differences(self.installed, self.inspect())
        self.assertFalse(result["unexpected_subtrees_traversed"])
        self.assertEqual(result["difference_count"], 2)
        self.assertIn("python-bytecode-cache", json.dumps(result))
        self.assertNotIn("DUMMY_PRIVATE", json.dumps(result))

    def test_difference_audit_marks_bounded_output_truncation(self):
        self.installed.chmod(0o755)
        for index in range(4):
            (self.installed / f"DUMMY_UNKNOWN_{index}").write_bytes(b"x")
        result = payload.inspect_tree_differences(self.installed, self.inspect(), limit=2)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["differences"]), 2)
        self.assertEqual(result["difference_count"], 4)
        self.assertFalse(result["observed_tree_matches"])

    def test_difference_audit_matching_tree_remains_diagnostic_only(self):
        self.installed.chmod(0o755)
        result = payload.inspect_tree_differences(self.installed, self.inspect())
        self.assertEqual(result["difference_count"], 0)
        self.assertTrue(result["observed_tree_matches"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["writes"], [])

    def test_difference_audit_dist_lock_is_identified_without_reading_contents(self):
        self.installed.chmod(0o755)
        (self.installed / "dist.lock").write_bytes(b"DUMMY_PRIVATE_CONTENT")
        result = payload.inspect_tree_differences(self.installed, self.inspect())
        self.assertEqual(result["differences"][0]["category"], "distribution-lock")
        self.assertNotIn("DUMMY_PRIVATE_CONTENT", json.dumps(result))

    def test_inspection_no_write_extract_or_process(self):
        before = self.snapshot()
        with patch("subprocess.Popen",side_effect=AssertionError("no process")), patch("tarfile.TarFile.extractall",side_effect=AssertionError("no extraction")):
            inventory = self.inspect()
        self.assertEqual(before,self.snapshot())
        self.assertEqual(inventory.entries["files/bin-arm64/wine"]["sha256"],hashlib.sha256(MEMBERS[3][2]).hexdigest())
        self.assertEqual(inventory.summary()["writes"],[])
        self.assertEqual(inventory.summary()["checksum_source"],"operator-declared")
        self.assertIn("payload-provenance-unreviewed",inventory.summary()["blockers"])

    def test_complete_installed_tree_matches_without_writes(self):
        inventory = self.inspect()
        before = self.snapshot()
        result = payload.verify_tree(self.installed,inventory)
        self.assertTrue(result["tree_matches"])
        self.assertFalse(result["preparation_complete"])
        self.assertFalse(result["external_link_targets_checked"])
        self.assertEqual(before,self.snapshot())

    def test_wrong_checksum_or_root_rejected(self):
        for options in ({"sha":"0"*128},{"sha":"x"*128},{"root":"Wrong Root"},{"root":"../Root"}):
            with self.subTest(options=options), self.assertRaises(Invalid):
                self.inspect(**options)

    def test_absolute_and_parent_paths_and_duplicate_members_rejected(self):
        for name in ("/escape","../escape","files/../escape","files//escape",".env","files/.env.local","proton"):
            with self.subTest(name=name):
                self.make_archive(MEMBERS+[(name,"file",b"never-written",0o644)])
                with self.assertRaises(Invalid):
                    self.inspect()
        self.assertFalse((self.root / "escape").exists())

    def test_special_or_privileged_members_rejected(self):
        for member in (("pipe","fifo",None,0o600),("special","file",b"x",0o4755)):
            self.make_archive(MEMBERS+[member])
            with self.assertRaises(Invalid):
                self.inspect()

    def test_file_cannot_be_parent_of_another_member(self):
        self.make_archive(MEMBERS+[("proton/child","file",b"x",0o644)])
        with self.assertRaises(Invalid):
            self.inspect()

    def test_link_cannot_be_parent_of_another_member(self):
        self.make_archive(MEMBERS+[("wine/child","file",b"x",0o644)])
        with self.assertRaises(Invalid):
            self.inspect()

    def test_missing_explicit_parent_rejected(self):
        self.make_archive([("missing/child","file",b"x",0o644)])
        with self.assertRaises(Invalid):
            self.inspect()

    def test_compressed_member_and_expanded_limits(self):
        for key, limit in (("MAX_ARCHIVE",10),("MAX_MEMBER",2),("MAX_EXPANDED",2),("MAX_MEMBERS",2)):
            with self.subTest(key=key), patch.object(payload,key,limit), self.assertRaises(Invalid):
                self.inspect()

    def test_parser_allocation_request_is_bounded(self):
        reader = payload._Reader(io.BytesIO(b"data"),4)
        for size in (-1,payload.CHUNK+1):
            with self.assertRaises(Invalid):
                reader.read(size)
        self.assertEqual(reader.read(4),b"data")

    def test_truncated_gzip_and_invalid_tar_rejected(self):
        original = self.archive.read_bytes()
        for raw in (original[:-12],gzip.compress(b"not a tar"),b"not gzip",
                    b"\x1f\x8b\x08\0\0\0\0\0\0\x03\x07" + b"\0"*8):
            self.archive.write_bytes(raw)
            self.sha = hashlib.sha512(raw).hexdigest()
            with self.assertRaises((Invalid,OSError)):
                self.inspect()

    def test_unexpected_installed_file_or_python_cache_rejected(self):
        inventory = self.inspect()
        extra = self.installed / "__pycache__"
        extra.mkdir()
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_missing_or_modified_installed_binary_rejected(self):
        inventory = self.inspect()
        path = self.installed / "files/bin-arm64/wine"
        path.write_bytes(b"modified")
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)
        path.unlink()
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_changed_executable_mode_rejected(self):
        inventory = self.inspect()
        (self.installed / "proton").chmod(0o644)
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_changed_link_or_linked_regular_file_rejected(self):
        inventory = self.inspect()
        link = self.installed / "wine"
        link.unlink()
        link.symlink_to(self.exe)
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)
        link.unlink()
        link.symlink_to("files/bin-arm64/wine")
        regular = self.installed / "proton"
        regular.unlink()
        regular.symlink_to(self.exe)
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_external_symlink_is_not_followed_or_declared_verified(self):
        self.make_archive(MEMBERS+[("outside","symlink",str(self.exe),0o777)])
        (self.installed / "outside").symlink_to(self.exe)
        inventory = self.inspect()
        self.assertEqual(inventory.external_links,1)
        self.assertIn("external-link-targets-unverified",inventory.summary()["blockers"])
        self.assertTrue(payload.verify_tree(self.installed,inventory)["tree_matches"])

    def test_hardlink_identity_and_link_count_checked(self):
        self.make_archive(MEMBERS+[("wine-hard","hardlink",ROOT+"/files/bin-arm64/wine",0o755)])
        os.link(self.installed / "files/bin-arm64/wine",self.installed / "wine-hard")
        inventory = self.inspect()
        self.assertTrue(payload.verify_tree(self.installed,inventory)["tree_matches"])
        os.link(self.installed / "wine-hard",self.root / "external-hardlink")
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_independent_copy_cannot_replace_hardlink(self):
        self.make_archive(MEMBERS+[("wine-hard","hardlink",ROOT+"/files/bin-arm64/wine",0o755)])
        copy_path = self.installed / "wine-hard"
        copy_path.write_bytes(MEMBERS[3][2])
        copy_path.chmod(0o755)
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,self.inspect())

    def test_external_hardlink_on_regular_member_rejected(self):
        inventory = self.inspect()
        os.link(self.installed / "proton",self.root / "outside")
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_hardlinks_outside_or_missing_target_rejected(self):
        for target in ("/outside",ROOT+"/missing",ROOT+"/wine"):
            self.make_archive(MEMBERS+[("hard","hardlink",target,0o755)])
            with self.assertRaises(Invalid):
                self.inspect()

    def test_only_explicit_generated_registration_overlays_allowed(self):
        inventory = self.inspect()
        raw = b"generated wrapper, not executed"
        path = self.installed / "droiddeck-proton-wrap"
        path.write_bytes(raw)
        path.chmod(0o755)
        overlay = {path.name:{"kind":"file","mode":0o755,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}}
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)
        self.assertTrue(payload.verify_tree(self.installed,inventory,overlay)["tree_matches"])
        overlay[path.name]["sha256"] = "0"*64
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory,overlay)

    def test_binary_overlay_cannot_override_archive_integrity(self):
        entry = {"kind":"file","mode":0o755,"size":0,"sha256":"0"*64}
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,self.inspect(),{"proton":entry})

    def test_malformed_overlay_rejected(self):
        for entry in ({"kind":"symlink","mode":0o777,"size":0,"sha256":"0"*64},
                      {"kind":"file","mode":0o755,"size":0,"sha256":"x"*64}):
            with self.assertRaises(Invalid):
                payload.verify_tree(self.installed,self.inspect(),{"user_settings.py":entry})

    def test_archive_or_installed_root_symlink_rejected(self):
        link = self.root / "linked.tar.gz"
        link.symlink_to(self.archive)
        with self.assertRaises(Invalid):
            self.inspect(path=link)
        link = self.root / "linked-root"
        link.symlink_to(self.installed,target_is_directory=True)
        with self.assertRaises(Invalid):
            payload.verify_tree(link,self.inspect())

    def test_cli_inspection_reports_identity_and_remains_read_only(self):
        before = self.snapshot()
        result = self.cli("--payload-directory",str(self.installed))
        self.assertEqual(result.returncode,0,result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["installed_payload"]["tree_matches"])
        self.assertFalse(report["preparation_complete"])
        self.assertEqual(before,self.snapshot())

    def test_cli_does_not_mix_payload_and_preparation_modes(self):
        result = self.cli("--registrations",str(self.added))
        self.assertEqual(result.returncode,1)
        self.assertNotIn(str(self.added),result.stderr)
        self.assertEqual(self.cli("--stage-local").returncode,2)

    def test_cli_incorrect_checksum_never_reports_match(self):
        self.sha = "0"*128
        result = self.cli()
        self.assertEqual(result.returncode,1)
        self.assertNotIn('"checksum_matches": true',result.stdout)

    def test_oversized_extended_header_rejected_before_metadata_read(self):
        info = tarfile.TarInfo(ROOT)
        info.type = tarfile.DIRTYPE
        header = tarfile.TarInfo("pax")
        header.type, header.size = tarfile.XHDTYPE, payload.CHUNK * 2
        raw = gzip.compress(info.tobuf(format=tarfile.USTAR_FORMAT) + header.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024)
        self.archive.write_bytes(raw)
        self.sha = hashlib.sha512(raw).hexdigest()
        with self.assertRaisesRegex(Invalid,"extended payload header"):
            self.inspect()

    def test_root_permissions_are_part_of_identity(self):
        inventory = self.inspect()
        self.installed.chmod(0o700)
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_parent_directory_replaced_by_link_during_hash_is_detected(self):
        inventory = self.inspect()
        original_hash = payload._hash
        old = self.installed / "files/bin-arm64"
        moved = self.installed / "files/moved"
        def mutate(stream, size):
            result = original_hash(stream,size)
            if old.is_dir() and not old.is_symlink():
                old.rename(moved)
                old.symlink_to(self.exe.parent,target_is_directory=True)
            return result
        with patch.object(payload,"_hash",side_effect=mutate), self.assertRaises((Invalid,OSError)):
            payload.verify_tree(self.installed,inventory)

    def test_file_modified_after_hash_is_detected(self):
        inventory = self.inspect()
        original_hash = payload._hash
        def mutate(stream, size):
            result = original_hash(stream,size)
            path = self.installed / "files/bin-arm64/wine"
            path.write_bytes(path.read_bytes()+b"changed")
            return result
        with patch.object(payload,"_hash",side_effect=mutate), self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_mutated_inventory_cannot_approve_modified_binary(self):
        inventory = self.inspect()
        raw = b"tampered"
        (self.installed / "proton").write_bytes(raw)
        inventory.entries["proton"].update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(Invalid):
            payload.verify_tree(self.installed,inventory)

    def test_selected_metadata_capture_remains_private_and_hash_bound(self):
        inventory = payload.inspect_archive(self.archive,self.sha,ROOT,capture=("proton",))
        self.assertEqual(inventory.captured["proton"],MEMBERS[2][2])
        self.assertEqual(inventory.digest,self.inspect().digest)
        self.assertNotIn("#!/bin/sh",repr(inventory))
        self.assertNotIn("#!/bin/sh",json.dumps(inventory.summary()))

    def test_metadata_capture_has_fixed_memory_limit(self):
        self.make_archive(MEMBERS+[("large","file",b"x"*(payload.CHUNK+1),0o644)])
        with self.assertRaises(Invalid):
            payload.inspect_archive(self.archive,self.sha,ROOT,capture=("large",))

    def test_invalid_capture_selector_is_refused(self):
        for capture in (("../outside",),("proton","proton")):
            with self.assertRaises(Invalid):
                payload.inspect_archive(self.archive,self.sha,ROOT,capture=capture)

    def test_inventory_repr_omits_full_member_contents(self):
        inventory = self.inspect()
        self.assertNotIn("files/bin-arm64/wine",repr(inventory))
        self.assertNotIn("files/bin-arm64/wine",json.dumps(inventory.summary()))


if __name__ == "__main__":
    unittest.main()
