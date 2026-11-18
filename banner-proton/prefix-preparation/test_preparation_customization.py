#!/usr/bin/env python3
"""Expected installation/adoption metadata using synthetic archives and sources."""

import hashlib
import io
import json
import os
import runpy
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
import preparation_customization as customization
from preparation_common import Invalid
from preparation_payload import inspect_archive, verify_tree
from preparation_vdf import Document

PARENT = Path(__file__).resolve().parent.parent
INSTALLER = runpy.run_path(str(next(p for p in (PARENT/"install-softdenchi.py",PARENT/"banner-proton/install-softdenchi.py") if p.exists())))
VERSION = "11-12.8-softdenchi3-fixture"
ARCHIVE_NAME = "DroidDeck-Proton-"+VERSION+"-aarch64.tar.gz"
ROOT = "DroidDeck-Proton "+VERSION


class CustomizationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.archive = self.root / ARCHIVE_NAME
        self.helper = self.root / "runtime-helper.py"
        values = {name:"\\n"+name+"\\n" for name in customization.SETUPS}
        values.update(EXTRA_WRAPPER="droiddeck-proton-wrap",
                      EXTRA_WRAPPER_SH='#!/bin/bash\nhere=$(dirname "$0")\nentry=%s\n',
                      EXTRA_COMPAT_TOOL_VDF='"compatibilitytools" {"compat_tools" {"%s" {"install_path" "." "display_name" "%s" "from_oslist" "windows" "to_oslist" "linux"}}}')
        source = "\n".join(name+" = "+repr(value) for name,value in values.items())
        source += '\nEXTRA_MANIFEST_VDF = '+repr('"manifest" {"commandline" "/%s %%verb%%"}')+' % EXTRA_WRAPPER\n'
        source += 'raise RuntimeError("source must never execute")\n'
        self.helper.write_text(source)
        self.helper_hash = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        self.make_archive()

    def make_archive(self, settings=b'user_settings={"PROTON_LOG":"1"}\n', command="/proton %verb%"):
        contents = {"version":("123 DroidDeck-Proton-"+VERSION+"\n").encode(),
                    "proton":b"#!/bin/sh\nexit 0\n", "compatibilitytool.vdf":b'"original" {}\n',
                    "toolmanifest.vdf":('"manifest" {"commandline" "'+command+'"}\n').encode()}
        if settings is not None:
            contents["user_settings.py"] = settings
        with tarfile.open(self.archive,"w:gz") as package:
            root = tarfile.TarInfo(ROOT)
            root.type,root.mode = tarfile.DIRTYPE,0o755
            package.addfile(root)
            for name,raw in contents.items():
                info = tarfile.TarInfo(ROOT+"/"+name)
                info.size,info.mode = len(raw),0o755 if name=="proton" else 0o644
                package.addfile(info,io.BytesIO(raw))
        self.sha = hashlib.sha512(self.archive.read_bytes()).hexdigest()
        self.archive.with_name(self.archive.name.removesuffix(".tar.gz")+".sha512sum").write_text(self.sha+"  "+self.archive.name+"\n")
        self.inventory = inspect_archive(self.archive,self.sha,ROOT,capture=("version","toolmanifest.vdf","user_settings.py"))

    def plan(self, **options):
        with patch.object(customization,"HELPER_SHA256",self.helper_hash):
            return customization.plan_customizations(self.inventory,self.archive.name,"cleanup",self.helper,
                                                     INSTALLER["render_installation"],**options)

    def test_render_is_read_only_and_never_executes_helper_or_process(self):
        before = {p.name:p.read_bytes() for p in self.root.iterdir()}
        with patch("subprocess.run",side_effect=AssertionError("no process")), patch("runpy.run_path",side_effect=AssertionError("no helper import")):
            plan = self.plan()
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})
        self.assertEqual(plan.summary()["writes"],[])
        self.assertFalse(plan.summary()["preparation_complete"])
        self.assertNotIn("user_settings=",repr(plan))
        self.assertNotIn("user_settings=",json.dumps(plan.summary()))

    def test_expected_installer_outputs_match_real_fixture_installation(self):
        plan = self.plan()
        previous = os.umask(0o022)
        try:
            directory = INSTALLER["install"](self.archive,self.root/"tools","cleanup")
        finally:
            os.umask(previous)
        for name in ("user_settings.py","softdenchi-install.json"):
            self.assertEqual((directory/name).read_bytes(),plan.files[name])
        # Simulate adoption using exactly the precomputed outputs, not measured expectations.
        for name,raw in plan.files.items():
            (directory/name).write_bytes(raw)
            (directory/name).chmod(plan.overlays[name]["mode"])
        self.assertTrue(verify_tree(directory,self.inventory,plan.overlays)["tree_matches"])
        (directory/"proton").write_text("changed")
        with self.assertRaises(Invalid):
            verify_tree(directory,self.inventory,plan.overlays)

    def test_wrapper_template_insertion_order_and_manifest_are_fixed(self):
        plan = self.plan()
        wrapper = plan.files["droiddeck-proton-wrap"].decode()
        positions = [wrapper.index(name) for name in customization.SETUPS]
        self.assertEqual(positions,sorted(positions))
        self.assertIn("entry=proton",wrapper)
        command = Document(plan.files["toolmanifest.vdf"]).node(("manifest","commandline")).value
        self.assertEqual(command,"/droiddeck-proton-wrap %verb%")
        self.assertEqual(plan.files["toolmanifest.vdf.droiddeck-orig"],self.inventory.captured["toolmanifest.vdf"])

    def test_label_is_sanitized_like_runtime_and_bound_in_digest(self):
        base = self.plan()
        labelled = self.plan(label=b' My "label" \\ test \n')
        entry = Document(labelled.files["compatibilitytool.vdf"]).node(("compatibilitytools","compat_tools","SoftDenchi-Proton-"+VERSION,"display_name")).value
        self.assertEqual(entry,"SoftDenchi-Proton "+VERSION+" (My 'label'  test)")
        self.assertNotEqual(base.digest,labelled.digest)
        self.assertNotEqual(self.plan(label=b"").digest,base.digest)

    def test_label_control_or_oversize_is_refused(self):
        for label in (b"a\nb",b"x"*4097):
            with self.subTest(label_length=len(label)), self.assertRaises(Invalid):
                self.plan(label=label)

    def test_unknown_or_changed_runtime_source_is_refused(self):
        self.helper.write_text(self.helper.read_text()+"# changed\n")
        with self.assertRaises(Invalid):
            self.plan()

    def test_missing_capture_cannot_be_replaced_with_installed_file(self):
        self.inventory.captured.pop("version")
        with self.assertRaises(Invalid):
            self.plan()

    def test_changed_captured_settings_is_refused(self):
        self.inventory.captured["user_settings.py"] = b"user_settings={}\n"
        with self.assertRaises(Invalid):
            self.plan()

    def test_absent_source_settings_uses_installer_default(self):
        self.make_archive(settings=None)
        self.assertTrue(self.plan().files["user_settings.py"].startswith(b"user_settings = {}\n"))

    def test_unexpected_original_launcher_is_refused(self):
        self.make_archive(command="/other %verb%")
        with self.assertRaises(Invalid):
            self.plan()

    def test_supported_umasks_affect_only_created_metadata_modes(self):
        public = self.plan()
        private = self.plan(umask=0o077)
        self.assertEqual(private.overlays["toolmanifest.vdf"]["mode"],0o600)
        self.assertEqual(public.overlays["toolmanifest.vdf"]["mode"],0o644)
        self.assertEqual(private.overlays["user_settings.py"]["mode"],0o644)
        self.assertEqual(private.overlays["droiddeck-proton-wrap"]["mode"],0o755)
        with self.assertRaises(Invalid):
            self.plan(umask=0)

    def test_renderer_rejects_wrong_archive_version_checksum_and_mode(self):
        version = self.inventory.captured["version"]
        for args in (("wrong.tar.gz",self.sha,"cleanup",version),
                     (self.archive.name,"x"*128,"cleanup",version),
                     (self.archive.name,self.sha,"unknown",version),
                     (self.archive.name,self.sha,"cleanup",b"123 Wrong\n")):
            with self.assertRaises(ValueError):
                INSTALLER["render_installation"](*args)

    def test_renderer_preserves_legacy_newline_and_custom_settings_behavior(self):
        files = INSTALLER["render_installation"](self.archive.name,self.sha,"off",self.inventory.captured["version"],
                                                  b'user_settings={"CUSTOM":"preserve"}\r\n')
        self.assertNotIn(b"\r",files["user_settings.py"])
        self.assertIn(b'"CUSTOM":"preserve"',files["user_settings.py"])
        self.assertIn(b"'PROTON_SOFTDENCHI_CLEANUP': '0'",files["user_settings.py"])


if __name__ == "__main__":
    unittest.main()
