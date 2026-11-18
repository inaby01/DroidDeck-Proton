#!/usr/bin/env python3
"""Runtime inventory with synthetic source files, ELF headers and Unix sockets."""

import hashlib
import json
import runpy
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
import preparation_runtime as runtime
from preparation_common import Invalid


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
        self.hashes = {}
        for index,name in enumerate(runtime.SOURCES):
            path = self.root / name
            path.parent.mkdir(parents=True,exist_ok=True)
            raw = ("raise RuntimeError('never execute runtime fixture "+str(index)+"')\n").encode()
            path.write_bytes(raw)
            path.chmod(0o755)
            self.hashes[name] = hashlib.sha256(raw).hexdigest()
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (183).to_bytes(2,"little")
        for name in runtime.LIBRARIES:
            path = self.root / name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(header)

    def inspect(self, env=None):
        with patch.dict(runtime.SOURCES,self.hashes,clear=True):
            return runtime.inspect_runtime(self.root,{} if env is None else env)

    def snapshot(self):
        return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob("*") if p.is_file()}

    def test_inventory_is_read_only_and_keeps_execution_blocked(self):
        before = self.snapshot()
        with patch("subprocess.Popen",side_effect=AssertionError("no launch")),patch("runpy.run_path",side_effect=AssertionError("no import")):
            result = self.inspect()
        self.assertEqual(before,self.snapshot())
        self.assertTrue(result["sources_match_pinned_version"])
        self.assertEqual(result["view"],"root-snapshot")
        self.assertEqual(result["writes"],[])
        self.assertFalse(result["preparation_complete"])
        self.assertFalse(result["helpers_executed"])
        self.assertIn("runtime-execution-unverified",result["blockers"])

    def test_changed_or_missing_source_is_reported(self):
        name = next(iter(self.hashes))
        path = self.root / name
        path.write_text("changed")
        self.assertEqual(self.inspect()["runtime_sources"][name]["status"],"different")
        path.unlink()
        self.assertEqual(self.inspect()["runtime_sources"][name]["status"],"missing")

    def test_same_bytes_without_execute_permission_are_not_sufficient(self):
        (self.root / next(iter(self.hashes))).chmod(0o644)
        self.assertFalse(self.inspect()["sources_match_pinned_version"])

    def test_linked_source_is_not_followed(self):
        path = self.root / next(iter(self.hashes))
        path.unlink()
        path.symlink_to(self.root / "etc/os-release")
        self.assertEqual(next(iter(self.inspect()["runtime_sources"].values()))["status"],"unreadable-or-linked")

    def test_library_elf_architecture_is_measured_without_trust_claim(self):
        result = self.inspect()
        self.assertTrue(all(v["elf_arm64"] for v in result["libraries"].values()))
        self.assertTrue(all(v["basis"]=="local-measurement" for v in result["libraries"].values()))
        (self.root / runtime.LIBRARIES[0]).write_bytes(b"not-ELF")
        self.assertFalse(self.inspect()["libraries"][runtime.LIBRARIES[0]]["elf_arm64"])

    def test_missing_library_is_reported(self):
        (self.root / runtime.LIBRARIES[0]).unlink()
        self.assertEqual(self.inspect()["libraries"][runtime.LIBRARIES[0]]["status"],"missing")

    def test_environment_values_and_private_root_are_omitted(self):
        result = self.inspect({"PROOT_FP_KEY":"DUMMY_SECRET","LD_PRELOAD":"/private/sensitive-library.so","DISPLAY":":7"})
        raw = json.dumps(result)
        self.assertTrue(result["environment_presence"]["PROOT_FP_KEY"])
        for value in ("DUMMY_SECRET","/private/sensitive-library.so",str(self.root)):
            self.assertNotIn(value,raw)

    @unittest.skipUnless(sys.platform=="linux","native Unix socket fixture requires Linux")
    def test_existing_display_socket_is_not_connected(self):
        path = self.root / "tmp/.X11-unix/X7"
        path.parent.mkdir(parents=True)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.bind(str(path))
            result = self.inspect({"DISPLAY":":7"})
            self.assertEqual(result["display_socket"],"present-unconnected")
            self.assertFalse(result["connections_attempted"])

    def test_label_hash_is_recorded_without_label_contents(self):
        (self.root / "etc/steam-compatibility-label").write_text("DUMMY_PRIVATE_LABEL")
        result = self.inspect()
        self.assertEqual(result["label"]["status"],"measured")
        self.assertNotIn("DUMMY_PRIVATE_LABEL",json.dumps(result))

    def test_wrong_os_and_invalid_root_are_not_accepted_as_matching_runtime(self):
        (self.root / "etc/os-release").write_text('ID=other\nVERSION_ID="1"\n')
        self.assertIn("runtime-os-unconfirmed",self.inspect()["blockers"])
        with self.assertRaises(Invalid):
            runtime.inspect_runtime(self.root / "absent",{})

    def test_known_os_release_link_is_read_within_snapshot(self):
        path = self.root / "etc/os-release"
        raw = path.read_bytes()
        path.unlink()
        target = self.root / "usr/lib/os-release"
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
        path.symlink_to("../usr/lib/os-release")
        self.assertEqual(self.inspect()["os_release"],{"ID":"ubuntu","VERSION_ID":"26.04"})

    @unittest.skipUnless(sys.platform=="linux","native root inventory requires Linux")
    def test_native_container_os_release_is_recognized(self):
        result = runtime.inspect_runtime(Path("/"),{})
        self.assertEqual(result["os_release"],{"ID":"ubuntu","VERSION_ID":"26.04"})
        self.assertFalse(result["helpers_executed"])
        self.assertTrue(result["process_observation_basis"]["self_proc_readable"])
        self.assertRegex(result["process_observation_basis"]["umask"],r"[0-7]{4}")

    def test_standalone_audit_runs_without_installing_modules_or_writing(self):
        command = runtime.runtime_audit_command()
        self.assertTrue(command.startswith("/usr/bin/python3 -I -B - <<"))
        result = subprocess.run(["/bin/bash"],input=command,capture_output=True,text=True,check=False,
                                env={"PATH":"/usr/bin:/bin","PROOT_FP_KEY":"DUMMY_COMMAND_SECRET"})
        self.assertEqual(result.returncode,0,result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["view"],"current-root")
        self.assertEqual(report["writes"],[])
        self.assertFalse(report["helpers_executed"])
        self.assertNotIn("DUMMY_COMMAND_SECRET",result.stdout)

    def test_runtime_cli_is_separate_read_only_mode(self):
        before = self.snapshot()
        script = Path(__file__).with_name("prepare_game.py")
        result = subprocess.run([sys.executable,"-I","-B",str(script),"--inspect-runtime","--runtime-root",str(self.root)],
                                capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(json.loads(result.stdout)["preparation_complete"])
        self.assertEqual(before,self.snapshot())
        rejected = subprocess.run([sys.executable,"-I","-B",str(script),"--inspect-runtime","--runtime-root",str(self.root),"--app-id","42"],
                                  capture_output=True,text=True,check=False)
        self.assertEqual(rejected.returncode,1)


if __name__ == "__main__":
    unittest.main()
