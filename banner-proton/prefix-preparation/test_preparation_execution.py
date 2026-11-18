#!/usr/bin/env python3
"""Disposable launch contracts. No Wine, Windows binary or real prefix is used."""

import copy
import hashlib
import json
import os
import runpy
import subprocess
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURES = runpy.run_path(str(Path(__file__).with_name("test_prepare_game.py")))
import preparation_execution as execution
from preparation_common import Invalid
from preparation_payload import inspect_archive
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore
from preparation_target import pin_registration

FAKE = '''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
import launch_fixture_support
assert launch_fixture_support.MARKER == "sibling-imported"
root = Path(os.environ["STEAM_COMPAT_DATA_PATH"])
work = Path.cwd()
(work / "seen.json").write_text(json.dumps({"argv":sys.argv,"env":dict(os.environ)}))
print("DUMMY_PRIVATE_CHILD_OUTPUT", flush=True)
if (work / "fail").exists():
    sys.exit(7)
if (work / "incomplete").exists():
    sys.exit(0)
(root / "pfx/drive_c/windows").mkdir(parents=True, exist_ok=True)
for name in ("system.reg", "user.reg"):
    (root / "pfx" / name).write_text("WINE REGISTRY Version 2\\n")
(root / "version").write_text("fixture-prefix-1\\n")
'''


class ExecutionTests(unittest.TestCase):
    write_json = FIXTURES["InspectionTests"].write_json
    snapshot = FIXTURES["InspectionTests"].snapshot

    def setUp(self):
        FIXTURES["InspectionTests"].setUp(self)
        self.key = "4294967295"
        self.base = self.steam / "steamapps/compatdata"
        self.base.mkdir(parents=True)
        self.compatdata = self.base / self.key
        self.tool = self.steam / "compatibilitytools.d/Example Proton"
        self.tool.mkdir(parents=True)
        (self.tool / "launch_fixture_support.py").write_text('MARKER = "sibling-imported"\n')
        (self.tool / "proton").write_text(FAKE)
        (self.tool / "proton").chmod(0o755)
        (self.tool / "version").write_text("fixture-build-1\n")
        (self.tool / "user_settings.py").write_text('user_settings = {"PROTON_LOG":"1"}\nuser_settings.update({"PROTON_SOFTDENCHI_CLEANUP":"1"})\n')
        self.work = self.root / "private work 日本語 ; $(touch injected)"
        self.home = self.root / "private-home"
        self.work.mkdir()
        self.home.mkdir()
        self.proc = self.root / "fixture-proc"
        (self.proc / str(os.getpid())).mkdir(parents=True)
        self.stop_check = ProcessStopCheck(self.compatdata,self.proc)
        self.store_root = self.root / "launch-store"
        self.checks = {"target": True, "payload": True, "runtime": True, "stopped": True}
        self.options = {"tool": self.tool, "steam": self.steam, "registration_id": self.key, "install": self.exe.parent,
                        "work": self.work, "home": self.home, "runtime_environment": {"DISPLAY": ":7"},
                        "expected_hashes": self.hashes(), "payload_inventory": self.inventory(),
                        "target_pin": pin_registration(self.added,self.key,self.exe_root,self.steam)}
        self.lock_key = hashlib.sha256(str(self.compatdata).encode()).hexdigest()

    def hashes(self):
        return {name: hashlib.sha256((self.tool / name).read_bytes()).hexdigest() if (self.tool / name).exists() else None
                for name in ("proton", "version", "user_settings.py")}

    def inventory(self):
        archive = self.root / "fixture-payload.tar.gz"
        with tarfile.open(archive,"w:gz") as package:
            package.add(self.tool,arcname="Fixture Payload")
        return inspect_archive(archive,hashlib.sha512(archive.read_bytes()).hexdigest(),"Fixture Payload")

    def plan(self, **options):
        if "expected_hashes" in options and "payload_inventory" not in options:
            options["payload_inventory"] = self.inventory()
        return execution.plan_launch(**(self.options | options))

    def session(self, store, plan=None):
        return execution.LaunchSession(plan or self.plan(), store, lambda: dict(self.checks), self.stop_check)

    def launch(self, **options):
        plan = self.plan(**options)
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
            return self.session(store, plan).start().wait(10)

    def test_plan_read_only_no_process_no_environment_leak(self):
        before = self.snapshot()
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")), patch.dict(os.environ, {"DUMMY_SECRET":"private"}):
            plan = self.plan()
        self.assertEqual(before, self.snapshot())
        self.assertNotIn("DUMMY_SECRET", plan.environment)
        self.assertNotIn(str(self.home), repr(plan))
        self.assertNotIn(":7", json.dumps(plan.summary()))
        self.assertEqual(plan.summary()["writes"], [])

    def test_real_child_gets_exact_prefix_arguments_and_safeguards(self):
        result = self.launch()
        seen = json.loads((self.work / "seen.json").read_text())
        self.assertEqual(seen["argv"], [str(self.tool / "proton"), "run", "cmd.exe", "/d", "/c", "exit", "0"])
        self.assertEqual(seen["env"]["STEAM_COMPAT_DATA_PATH"], str(self.compatdata))
        self.assertEqual(seen["env"]["WINEPREFIX"], str(self.compatdata / "pfx"))
        self.assertEqual(seen["env"]["DISPLAY"], ":7")
        self.assertEqual(seen["env"]["SteamAppId"], "0")
        self.assertEqual(seen["env"]["SteamGameId"], str(int(self.key) << 32 | 0x02000000))
        for key, value in execution.DISABLED.items():
            self.assertEqual(seen["env"][key], value)
        self.assertEqual(result["status"], "initialized-unverified")
        self.assertFalse(result["preparation_complete"])
        self.assertFalse((self.root / "injected").exists())
        self.assertFalse((self.work / "injected").exists())
        self.assertEqual(self.exe.read_bytes(), FIXTURES["pe"]())

    def test_low_app_id_environment_matches_steam_identity(self):
        self.write_json(self.added,[{"appid":42,"exe":str(self.exe)}])
        pin = pin_registration(self.added,"42",self.exe_root,self.steam)
        env = self.plan(registration_id="42",target_pin=pin).environment
        for key in ("SteamAppId", "STEAM_COMPAT_APP_ID", "SteamGameId", "SteamOverlayGameId"):
            self.assertEqual(env[key], "42")

    def test_existing_prefix_even_empty_is_never_initialized(self):
        self.compatdata.mkdir()
        with self.assertRaises(Invalid):
            self.plan()
        self.assertEqual(list(self.compatdata.iterdir()), [])

    def test_signed_and_noncanonical_aliases_refused(self):
        for name in ("-1", "04294967295"):
            with self.subTest(name=name):
                path = self.base / name
                path.mkdir()
                with self.assertRaises(Invalid):
                    self.plan()
                path.rmdir()

    def test_symlink_launch_path_refused(self):
        link = self.root / "linked-work"
        link.symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(Invalid):
            self.plan(work=link)

    def test_private_work_must_not_overlap_game_or_steam(self):
        for name in ("work", "home"):
            for folder in (self.exe.parent, self.steam, self.tool):
                with self.subTest(name=name, folder=folder), self.assertRaises(Invalid):
                    self.plan(**{name:folder})

    def test_parent_copyprefix_refused(self):
        with patch.dict(os.environ, {"COPYPREFIX":"1"}), self.assertRaises(Invalid):
            self.plan()

    def test_runtime_injection_and_unknown_environment_refused(self):
        for env in ({"LD_PRELOAD":"evil"}, {"PYTHONPATH":"evil"}, {"COPYPREFIX":"1"}, {"DISPLAY":":0\nBAD=1"}):
            with self.subTest(env=env), self.assertRaises(Invalid):
                self.plan(runtime_environment=env)

    def test_executable_user_settings_rejected_without_execution(self):
        path = self.tool / "user_settings.py"
        for text in ('raise Exception("executed")', 'import os\nuser_settings={}',
                     'user_settings={"WINEPREFIX":"/wrong"}', 'user_settings = dict()',
                     'user_settings={}\nuser_settings.update(__import__("os").environ)',
                     'user_settings={}\nuser_settings={}'):
            with self.subTest(text=text):
                path.write_text(text)
                with self.assertRaises(Invalid):
                    self.plan(expected_hashes=self.hashes())

    def test_absent_settings_allowed_but_new_file_invalidates_plan(self):
        path = self.tool / "user_settings.py"
        path.unlink()
        plan = self.plan(expected_hashes=self.hashes())
        path.write_text('user_settings={}\n')
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store, plan).start()
        self.assertFalse(self.compatdata.exists())

    def test_changed_launcher_or_settings_or_version_rejected_before_start(self):
        for name in ("proton", "user_settings.py", "version"):
            with self.subTest(name=name):
                plan = self.plan()
                path = self.tool / name
                raw = path.read_bytes()
                path.write_bytes(raw+b"\n")
                with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
                    self.session(store, plan).start()
                self.assertFalse(self.compatdata.exists())
                path.write_bytes(raw)

    def test_global_and_correct_target_locks_required(self):
        with PrivateStore(self.store_root, create=True) as store:
            with self.assertRaises(Invalid):
                self.session(store).start()
            with store.locked("0"*64), self.assertRaises(Invalid):
                self.session(store).start()
        self.assertFalse(self.compatdata.exists())

    def test_missing_or_nonboolean_readiness_refuses_launch(self):
        for checks in ({"target":True,"payload":True}, {"target":True,"payload":1,"stopped":True},
                       {"target":False,"payload":True,"stopped":True}, {"target":True,"payload":False,"stopped":True},
                       {"target":True,"payload":True,"stopped":False}):
            with self.subTest(checks=checks), PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
                self.checks = {**checks,"runtime":True}
                with self.assertRaises(Invalid):
                    self.session(store).start()
        self.checks = {"target":True,"payload":True,"runtime":False,"stopped":True}
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store).start()
        self.assertFalse(self.compatdata.exists())

    def test_nonzero_exit_preserves_partial_prefix_and_blocks_reinitialize(self):
        (self.work / "fail").touch()
        result = self.launch()
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(self.compatdata.is_dir())
        with self.assertRaises(Invalid):
            self.plan()

    def test_exit_zero_without_registry_and_version_is_failed(self):
        (self.work / "incomplete").touch()
        result = self.launch()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["status"], "failed")

    def test_timeout_does_not_kill_and_later_wait_rechecks(self):
        child = unittest.mock.Mock()
        child.wait.side_effect = [subprocess.TimeoutExpired("fixture", 1), 7]
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key), patch("subprocess.Popen", return_value=child):
            session = self.session(store).start()
            self.assertEqual(session.wait(1)["status"], "needs-user")
            child.kill.assert_not_called()
            child.terminate.assert_not_called()
            self.assertEqual(session.wait(1)["status"], "failed")

    def test_live_child_not_stopped_when_parent_exits(self):
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
            session = self.session(store).start()
            self.checks["stopped"] = False
            result = session.wait(10)
            self.assertEqual(result["status"], "needs-user")
            self.assertEqual(result["exit_code"], 0)
            self.checks["stopped"] = True
            self.assertEqual(session.wait(1)["status"], "initialized-unverified")

    def test_payload_change_during_launch_cannot_finish_successfully(self):
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
            session = self.session(store).start()
            session.process.wait(10)
            (self.tool / "version").write_text("changed")
            self.assertEqual(session.wait(1)["status"], "failed")

    def test_probe_requires_explicit_matching_initialized_version(self):
        result = self.launch()
        with self.assertRaises(Invalid):
            self.plan(operation="probe")
        result = self.launch(operation="probe", prefix_version_sha256=result["prefix_version_sha256"], origin_launch_id=result["launch_id"])
        self.assertEqual(result["status"], "probe-exited")
        seen = json.loads((self.work / "seen.json").read_text())
        self.assertEqual(seen["argv"][1], "runinprefix")
        with self.assertRaises(Invalid):
            self.plan(operation="probe", prefix_version_sha256="0"*64, origin_launch_id=result["launch_id"])

    def test_probe_cannot_adopt_unknown_or_differently_initialized_prefix(self):
        result = self.launch()
        with self.assertRaises(Invalid):
            self.plan(operation="probe", prefix_version_sha256=result["prefix_version_sha256"])
        plan = self.plan(operation="probe", prefix_version_sha256=result["prefix_version_sha256"],
                         origin_launch_id="launch-" + "0"*32)
        with PrivateStore(self.store_root) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store, plan).start()
        (self.tool / "version").write_text("other-build")
        plan = self.plan(operation="probe", prefix_version_sha256=result["prefix_version_sha256"],
                         origin_launch_id=result["launch_id"], expected_hashes=self.hashes())
        with PrivateStore(self.store_root) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store, plan).start()

    def test_probe_refuses_missing_or_linked_registry(self):
        result = self.launch()
        path = self.compatdata / "pfx/system.reg"
        path.unlink()
        with self.assertRaises((OSError, Invalid)):
            self.plan(operation="probe", prefix_version_sha256=result["prefix_version_sha256"], origin_launch_id=result["launch_id"])
        path.symlink_to(self.exe)
        with self.assertRaises(Invalid):
            self.plan(operation="probe", prefix_version_sha256=result["prefix_version_sha256"], origin_launch_id=result["launch_id"])

    def test_spawn_failure_recorded_without_deleting_new_directory(self):
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key), patch("subprocess.Popen", side_effect=OSError("spawn")):
            with self.assertRaises(OSError):
                self.session(store).start()
            self.assertEqual(store.inventory()["launches"][0]["status"], "failed")
        self.assertTrue(self.compatdata.exists())

    def test_inventory_marks_abandoned_running_record_for_reinspection(self):
        child = unittest.mock.Mock()
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key), patch("subprocess.Popen", return_value=child):
            self.session(store).start()
        with PrivateStore(self.store_root) as store:
            item = store.inventory()["launches"][0]
            self.assertEqual(item["status"], "running")
            self.assertTrue(item["reinspection_required"])
            self.assertFalse(item["preparation_complete"])

    def test_private_records_have_no_child_output_or_environment(self):
        self.launch()
        record = next((self.store_root / "launches").iterdir())
        raw = record.read_text()
        self.assertNotIn("DUMMY_PRIVATE_CHILD_OUTPUT", raw)
        self.assertNotIn(str(self.home), raw)
        self.assertNotIn(":7", raw)
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record.parent.stat().st_mode & 0o777, 0o700)

    def test_inventory_does_not_accept_broken_launch_record(self):
        self.launch()
        path = next((self.store_root / "launches").iterdir())
        data = json.loads(path.read_text())
        data["preparation_complete"] = True
        path.write_text(json.dumps(data))
        with PrivateStore(self.store_root) as store:
            self.assertEqual(store.inventory()["launches"][0]["status"], "invalid")

    def test_unknown_operations_and_unbounded_wait_refused(self):
        with self.assertRaises(Invalid):
            self.plan(operation="destroyprefix")
        with PrivateStore(self.store_root, create=True) as store, store.locked(self.lock_key):
            session = self.session(store)
            for timeout in (0, 121, True, None):
                with self.subTest(timeout=timeout), self.assertRaises(Invalid):
                    session.wait(timeout)

    def test_full_payload_and_matching_registration_are_mandatory(self):
        for values in ({"payload_inventory":None},{"target_pin":None},{"install":self.home}):
            with self.subTest(values=list(values)), self.assertRaises(Invalid):
                self.plan(**values)
        self.assertFalse(self.compatdata.exists())

    def test_extra_python_module_blocks_launch_even_when_callback_returns_true(self):
        plan = self.plan()
        (self.tool / "unexpected.py").write_text("raise RuntimeError('must not execute')")
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key):
            with patch("subprocess.Popen") as child, self.assertRaises(Invalid):
                self.session(store,plan).start()
            child.assert_not_called()
        self.assertFalse(self.compatdata.exists())

    def test_missing_payload_member_blocks_launch(self):
        plan = self.plan()
        (self.tool / "launch_fixture_support.py").unlink()
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store,plan).start()
        self.assertFalse(self.compatdata.exists())

    def test_nonlauncher_payload_change_after_zero_exit_is_failed(self):
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key):
            session = self.session(store).start()
            self.assertEqual(session.process.wait(10),0)
            (self.tool / "launch_fixture_support.py").write_text("MARKER = 'changed'\n")
            result = session.wait(1)
            self.assertEqual(result["exit_code"],0)
            self.assertEqual(result["status"],"failed")
            self.assertTrue(self.compatdata.exists())

    def test_launcher_reference_cannot_disagree_with_inventory(self):
        hashes = self.hashes()
        hashes["proton"] = "0"*64
        with self.assertRaises(Invalid):
            self.plan(expected_hashes=hashes)

    def test_external_payload_link_cannot_be_launched(self):
        (self.tool / "outside").symlink_to(self.exe)
        with self.assertRaises(Invalid):
            self.plan(payload_inventory=self.inventory())

    def test_generated_settings_overlay_is_copied_and_verified(self):
        original = self.options["payload_inventory"]
        raw = b'user_settings = {"PROTON_LOG":"0"}\n'
        settings = self.tool / "user_settings.py"
        settings.write_bytes(raw)
        overlays = {"user_settings.py":{"kind":"file","mode":settings.stat().st_mode & 0o777,
                                        "size":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}}
        plan = self.plan(payload_inventory=original,payload_overlays=overlays,expected_hashes=self.hashes())
        overlays["user_settings.py"]["sha256"] = "0"*64
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key):
            self.assertEqual(self.session(store,plan).start().wait(10)["status"],"initialized-unverified")

    def test_overlay_inside_plan_cannot_be_changed_after_pinning(self):
        plan = self.plan()
        plan.spec["payload_overlays"]["user_settings.py"] = {"kind":"file","mode":0o644,"size":0,"sha256":"0"*64}
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store,plan).start()
        self.assertFalse(self.compatdata.exists())

    def test_changed_registration_blocks_launch_with_true_callback(self):
        plan = self.plan()
        self.write_json(self.added,[])
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store,plan).start()
        self.assertFalse(self.compatdata.exists())

    def test_changed_game_executable_blocks_launch(self):
        plan = self.plan()
        self.exe.write_bytes(self.exe.read_bytes()+b"changed")
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store,plan).start()
        self.assertFalse(self.compatdata.exists())

    def test_target_pin_from_other_registration_is_refused(self):
        self.write_json(self.added,[{"appid":42,"exe":str(self.exe)}])
        other = pin_registration(self.added,"42",self.exe_root,self.steam)
        with self.assertRaises(Invalid):
            self.plan(target_pin=other)

    def test_changed_executable_after_child_exit_is_failed(self):
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key):
            session = self.session(store).start()
            self.assertEqual(session.process.wait(10),0)
            self.exe.write_bytes(self.exe.read_bytes()+b"changed")
            self.assertEqual(session.wait(1)["status"],"failed")

    def test_registration_removed_after_child_exit_is_failed(self):
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key):
            session = self.session(store).start()
            self.assertEqual(session.process.wait(10),0)
            self.added.unlink()
            self.assertEqual(session.wait(1)["status"],"failed")

    def test_registration_change_between_checks_prevents_spawn(self):
        plan = self.plan()
        calls = []
        def ready():
            calls.append(True)
            if len(calls)==2:
                self.write_json(self.added,[])
            return dict(self.checks)
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), patch("subprocess.Popen") as child:
            session = execution.LaunchSession(plan,store,ready,self.stop_check)
            with self.assertRaises(Invalid):
                session.start()
            child.assert_not_called()
            self.assertEqual(store.inventory()["launches"][0]["status"],"failed")
        self.assertTrue(self.compatdata.exists())

    def test_payload_change_between_checks_prevents_spawn(self):
        plan = self.plan()
        calls = []
        def ready():
            calls.append(True)
            if len(calls)==2:
                (self.tool / "launch_fixture_support.py").write_text("MARKER='changed'")
            return dict(self.checks)
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), patch("subprocess.Popen") as child:
            with self.assertRaises(Invalid):
                execution.LaunchSession(plan,store,ready,self.stop_check).start()
            child.assert_not_called()

    def test_registration_pinning_never_accepts_executable_outside_root(self):
        with self.assertRaises(Invalid):
            pin_registration(self.added,self.key,self.home,self.steam)

    def test_visible_target_process_blocks_true_readiness_callback(self):
        pid = str(os.getpid()+100000)
        folder = self.proc / pid
        folder.mkdir()
        (folder / "stat").write_text(pid+" (fixture) "+" ".join(["S","1"]+["0"]*17+["123"]))
        (folder / "environ").write_bytes(("WINEPREFIX="+str(self.compatdata / "pfx")+"\0").encode())
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store).start()
        self.assertFalse(self.compatdata.exists())

    def test_process_observation_does_not_mutate_readiness_callback_state(self):
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key):
            session = execution.LaunchSession(self.plan(),store,lambda:self.checks,self.stop_check).start()
            self.assertEqual(session.process.wait(10),0)
            pid = str(os.getpid()+100000)
            folder = self.proc / pid
            folder.mkdir()
            (folder / "stat").write_text(pid+" (fixture) "+" ".join(["S","1"]+["0"]*17+["123"]))
            (folder / "environ").write_bytes(("WINEPREFIX="+str(self.compatdata / "pfx")+"\0").encode())
            self.assertEqual(session.wait(1)["status"],"needs-user")
            self.assertTrue(self.checks["stopped"])
            (folder / "stat").unlink()
            (folder / "environ").unlink()
            folder.rmdir()
            self.assertEqual(session.wait(1)["status"],"initialized-unverified")

    def test_stop_observer_for_another_prefix_is_refused(self):
        self.stop_check = ProcessStopCheck(self.base / "42",self.proc)
        with PrivateStore(self.store_root,create=True) as store, store.locked(self.lock_key), self.assertRaises(Invalid):
            self.session(store).start()
        self.assertFalse(self.compatdata.exists())

    def test_launch_record_validation_rejects_invalid_identifiers(self):
        result = self.launch()
        for key, value in (("schema_version", 1), ("launch_id", "launch-../"), ("input_digest", "x"), ("app_id", "-1"),
                           ("operation", "run"), ("exit_code", True), ("prefix_version_sha256", "x")):
            record = copy.deepcopy(result)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(Invalid):
                execution.validate_launch_record(record)


if __name__ == "__main__":
    unittest.main()
