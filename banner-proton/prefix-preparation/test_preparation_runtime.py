#!/usr/bin/env python3
"""Runtime inventory with synthetic source files, ELF headers and Unix sockets."""

import hashlib
import json
import os
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
        self.assertTrue(command.startswith("DROIDDECK_AUDIT_SHELL_UMASK=$(umask) /usr/bin/python3 -I -B - <<"))
        result = subprocess.run(["/bin/bash"],input=command,capture_output=True,text=True,check=False,
                                env={"PATH":"/usr/bin:/bin","PROOT_FP_KEY":"DUMMY_COMMAND_SECRET"})
        self.assertEqual(result.returncode,0,result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["view"],"current-root")
        self.assertRegex(report["process_observation_basis"]["shell_umask"],r"[0-7]{4}")
        self.assertEqual(report["writes"],[])
        self.assertFalse(report["helpers_executed"])
        self.assertNotIn("DUMMY_COMMAND_SECRET",result.stdout)

    def proc_fixture(self, *, links=1, raw=None):
        proc = self.root / "proc"
        pid = str(os.getpid())
        folder = proc / pid
        folder.mkdir(parents=True)
        status = folder / "status"
        status.write_bytes(raw if raw is not None else ("Name:\tfixture\nUid:\t"+str(os.getuid())+" 0 0 0\nUmask:\t0022\n").encode())
        (proc / "self").symlink_to(pid)
        if links==2:
            os.link(status,self.root / "status-alias")
        return proc

    def test_proc_diagnostics_preserve_reader_failures_without_promoting_namespace(self):
        proc = self.proc_fixture(links=2)
        result = runtime.inspect_process_basis(proc,{"DROIDDECK_AUDIT_SHELL_UMASK":"0077"})
        self.assertTrue(result["self_proc_readable"])
        self.assertEqual(result["status_read_basis"],"proc-self-directory-fd")
        self.assertEqual(result["shared_reader"]["validation"],"single-link regular file required")
        self.assertEqual(result["numeric_pid_fd_reader"]["status"],"read")
        self.assertEqual(result["numeric_pid_fd_reader"]["link_count"],2)
        self.assertEqual(result["shell_umask"],"0077")
        self.assertFalse(result["device_namespace_verified"])

    def test_proc_self_and_python_pid_difference_is_visible_without_pid_values(self):
        proc = self.proc_fixture()
        other = 2147483000
        with patch.object(runtime.os,"getpid",return_value=other):
            result = runtime.inspect_process_basis(proc,{})
        self.assertEqual(result["numeric_pid_fd_reader"]["status"],"failed")
        self.assertFalse(result["proc_self_link"]["matches_python_pid"])
        self.assertEqual(result["proc_self_fd_reader"]["status"],"read")
        self.assertNotIn(str(other),json.dumps(result))

    def test_proc_status_symlink_is_never_followed(self):
        proc = self.proc_fixture()
        status = proc / str(os.getpid()) / "status"
        status.unlink()
        target = self.root / "private-status"
        target.write_text("DUMMY_PRIVATE_STATUS")
        status.symlink_to(target)
        result = runtime.inspect_process_basis(proc,{})
        self.assertEqual(result["numeric_pid_fd_reader"]["stage"],"open-status-no-follow")
        self.assertEqual(result["numeric_pid_fd_reader"]["status"],"failed")
        self.assertNotIn("DUMMY_PRIVATE_STATUS",json.dumps(result))
        self.assertNotIn(str(self.root),json.dumps(result))

    def test_proc_permission_error_exposes_only_errno_and_stage(self):
        proc = self.proc_fixture()
        with patch.object(runtime,"read_bytes",side_effect=PermissionError(13,"DUMMY_PRIVATE_ERROR")):
            result = runtime.inspect_process_basis(proc,{})
        self.assertEqual(result["shared_reader"]["errno"],13)
        self.assertEqual(result["shared_reader"]["stage"],"shared-reader")
        self.assertNotIn("DUMMY_PRIVATE_ERROR",json.dumps(result))

    def test_invalid_status_encoding_never_echoes_status_bytes(self):
        proc = self.proc_fixture(raw=b"DUMMY_PRIVATE_STATUS\xff")
        result = runtime.inspect_process_basis(proc,{})
        self.assertEqual(result["shared_reader"]["error_type"],"UnicodeDecodeError")
        self.assertNotIn("DUMMY_PRIVATE_STATUS",json.dumps(result))

    def test_proc_status_reads_are_bounded(self):
        proc = self.proc_fixture(raw=b"x"*65537)
        result = runtime.inspect_process_basis(proc,{})
        self.assertEqual(result["numeric_pid_fd_reader"]["status"],"failed")
        self.assertFalse(result["self_proc_readable"])

    def test_non_numeric_proc_self_target_is_not_followed_or_echoed(self):
        proc = self.proc_fixture()
        (proc / "self").unlink()
        (proc / "self").symlink_to("../private-target")
        result = runtime.inspect_process_basis(proc,{})
        self.assertEqual(result["proc_self_link"]["status"],"unsupported-target")
        self.assertNotIn("proc_self_fd_reader",result)
        self.assertNotIn("private-target",json.dumps(result))

    def test_proc_diagnostics_return_only_selected_fields_and_validated_shell_umask(self):
        proc = self.proc_fixture()
        result = runtime.inspect_process_basis(proc,{"DROIDDECK_AUDIT_SHELL_UMASK":"private-not-a-mask"})
        self.assertTrue(result["proc_self_link"]["matches_python_pid"])
        self.assertEqual(result["umask"],"0022")
        self.assertIsNone(result["shell_umask"])
        self.assertNotIn("private-not-a-mask",json.dumps(result))
        self.assertNotIn("Name",json.dumps(result))

    def test_runtime_cli_is_separate_read_only_mode(self):
        before = self.snapshot()
        script = Path(__file__).with_name("prepare_game.py")
        result = subprocess.run([sys.executable,"-I","-B",str(script),"--inspect-runtime","--runtime-root",str(self.root)],
                                capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(json.loads(result.stdout)["preparation_complete"])
        self.assertEqual(before,self.snapshot())
        rejected = subprocess.run([sys.executable,"-I","-B",str(script),"--inspect-runtime","--runtime-root",str(self.root),"--script-entry","status"],
                                  capture_output=True,text=True,check=False)
        self.assertEqual(rejected.returncode,1)


if __name__ == "__main__":
    unittest.main()
