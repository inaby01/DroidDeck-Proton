#!/usr/bin/env python3
"""Synthetic proc records; one harmless Linux child tests native proc observation."""

import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
import preparation_processes as processes
from preparation_common import Invalid


class ProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.proc = self.root / "proc"
        (self.proc / str(os.getpid())).mkdir(parents=True)
        self.target = self.root / "compatdata/42"
        self.pid = str(os.getpid()+100000)

    def record(self, env=b"", state="S", pid=None):
        pid = self.pid if pid is None else str(pid)
        folder = self.proc / pid
        folder.mkdir()
        tail = [state,"1"]+["0"]*17+["123"]
        (folder / "stat").write_text(pid+" (test ) name) "+" ".join(tail))
        (folder / "environ").write_bytes(env)
        return folder

    def observe(self):
        return processes.observe_processes(self.target,self.proc)

    def test_empty_view_is_reported_with_explicit_scope(self):
        result = self.observe()
        self.assertTrue(result["clear_in_view"])
        self.assertEqual(result["scope"],"same-proc-directory-owner-as-self")
        self.assertFalse(result["device_namespace_verified"])

    def test_matching_wineprefix_or_compatdata_counts_as_active(self):
        for key,path in (("WINEPREFIX",self.target / "pfx"),("STEAM_COMPAT_DATA_PATH",self.target)):
            with self.subTest(key=key):
                folder = self.record((key+"="+str(path)+"/\0").encode())
                self.assertEqual(self.observe()["active_count"],1)
                self.assertFalse(self.observe()["clear_in_view"])
                shutil.rmtree(folder)

    def test_other_prefix_does_not_block_or_disclose_environment(self):
        self.record(b"WINEPREFIX=/other/pfx\0DUMMY_SECRET=never-log-this\0")
        result = self.observe()
        self.assertTrue(result["clear_in_view"])
        self.assertNotIn("never-log-this",json.dumps(result))
        self.assertNotIn("/other",json.dumps(result))

    def test_missing_environment_on_existing_pid_is_unknown(self):
        folder = self.record()
        (folder / "environ").unlink()
        result = self.observe()
        self.assertEqual(result["unknown_count"],1)
        self.assertFalse(result["clear_in_view"])

    def test_unreadable_environment_is_unknown(self):
        self.record()
        original = processes._read
        def denied(fd,name,limit):
            if name=="environ":
                raise PermissionError("fixture")
            return original(fd,name,limit)
        with patch.object(processes,"_read",side_effect=denied):
            self.assertEqual(self.observe()["unknown_count"],1)

    def test_truncated_duplicate_or_oversized_prefix_fields_are_unknown(self):
        for env in (b"WINEPREFIX=/x",b"WINEPREFIX=/x\0WINEPREFIX=/y\0",b"X="+b"x"*(1024*1024)+b"\0"):
            folder = self.record(env)
            self.assertEqual(self.observe()["unknown_count"],1)
            shutil.rmtree(folder)

    def test_zombies_are_not_treated_as_running(self):
        self.record(("WINEPREFIX="+str(self.target / "pfx")+"\0").encode(),state="Z")
        self.assertTrue(self.observe()["clear_in_view"])

    def test_process_identity_change_is_unknown(self):
        self.record()
        original = processes._read
        calls = []
        def replaced(fd,name,limit):
            raw = original(fd,name,limit)
            if name=="stat":
                calls.append(True)
                if len(calls)==2:
                    return raw.replace(b"123",b"124")
            return raw
        with patch.object(processes,"_read",side_effect=replaced):
            self.assertEqual(self.observe()["unknown_count"],1)

    def test_disappeared_pid_is_not_counted_as_unknown(self):
        folder = self.record()
        original = processes._read
        def exited(fd,name,limit):
            if name=="environ":
                shutil.rmtree(folder)
                raise FileNotFoundError("fixture")
            return original(fd,name,limit)
        with patch.object(processes,"_read",side_effect=exited):
            self.assertTrue(self.observe()["clear_in_view"])

    def test_pid_symlink_is_not_followed(self):
        (self.proc / self.pid).symlink_to(self.root,target_is_directory=True)
        self.assertEqual(self.observe()["unknown_count"],1)

    def test_process_entry_limit_blocks_observation(self):
        with patch.object(processes,"MAX_PROCESSES",0), self.assertRaises(Invalid):
            self.observe()

    def test_stop_check_requires_both_observations_to_be_clear(self):
        clear = {"scope":"fixture","clear_in_view":True,"active_count":0,"unknown_count":0}
        active = {**clear,"clear_in_view":False,"active_count":1}
        for pair in ((clear,active),(active,clear)):
            with patch.object(processes,"observe_processes",side_effect=pair):
                result = processes.ProcessStopCheck(self.target,self.proc).check()
                self.assertFalse(result["clear_in_view"])
                self.assertFalse(result["device_namespace_verified"])

    @unittest.skipUnless(sys.platform=="linux" and Path("/proc/self/stat").exists(),"native proc test requires Linux")
    def test_native_child_is_seen_then_clears_after_normal_exit(self):
        env = {"PATH":"/usr/bin:/bin","WINEPREFIX":str(self.target / "pfx"),"DUMMY_SECRET":"never-log-native"}
        child = subprocess.Popen([sys.executable,"-I","-B","-c","import sys; sys.stdin.buffer.read(1)"],
                                 env=env,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            result = processes.ProcessStopCheck(self.target).check()
            self.assertGreaterEqual(result["active_count"],1)
            self.assertFalse(result["clear_in_view"])
            self.assertNotIn("never-log-native",json.dumps(result))
        finally:
            child.communicate(b"x",timeout=10)
        self.assertEqual(child.returncode,0)
        self.assertTrue(processes.ProcessStopCheck(self.target).check()["clear_in_view"])


if __name__ == "__main__":
    unittest.main()
