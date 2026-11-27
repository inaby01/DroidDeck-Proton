#!/usr/bin/env python3
"""Disposable launch contracts. No Wine, Windows binary or real prefix is used."""

import hashlib
import json
import os
import runpy
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURES = runpy.run_path(str(Path(__file__).with_name("test_prepare_game.py")))
import preparation_execution as execution
from preparation_common import Invalid
from preparation_payload import inspect_archive
from preparation_processes import ProcessStopCheck
from preparation_runtime_context import RuntimeEnvironmentPlan
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
    write_json = FIXTURES["SettingsFixture"].write_json
    snapshot = FIXTURES["SettingsFixture"].snapshot

    def setUp(self):
        FIXTURES["SettingsFixture"].setUp(self)
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

    def test_plan_read_only_no_process_no_environment_leak(self):
        before = self.snapshot()
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")), patch.dict(os.environ, {"DUMMY_SECRET":"private"}):
            plan = self.plan()
        self.assertEqual(before, self.snapshot())
        self.assertNotIn("DUMMY_SECRET", plan.environment)
        self.assertNotIn(str(self.home), repr(plan))
        self.assertNotIn(":7", json.dumps(plan.summary()))
        self.assertEqual(plan.summary()["writes"], [])

    def test_tool_launches_never_read_bytecode_caches_from_the_tool(self):
        prefix = self.work / execution.BYTECODE_PREFIX
        prefix.mkdir()
        with self.assertRaisesRegex(Invalid, "bytecode cache prefix present"):
            self.plan()
        prefix.rmdir()
        plan = self.plan()
        self.assertEqual(plan.environment["PYTHONPYCACHEPREFIX"], str(prefix))
        self.assertEqual(plan.environment["PYTHONDONTWRITEBYTECODE"], "1")
        execution.require_no_bytecode_cache(plan)
        self.assertFalse(os.path.lexists(prefix))

    def test_bytecode_prefix_appearing_after_planning_blocks_the_spawn(self):
        plan = self.plan()
        (self.work / execution.BYTECODE_PREFIX).mkdir()
        with self.assertRaisesRegex(Invalid, "bytecode cache prefix present"):
            execution.require_no_bytecode_cache(plan)

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

    def test_full_payload_and_matching_registration_are_mandatory(self):
        for values in ({"payload_inventory":None},{"target_pin":None},{"install":self.home}):
            with self.subTest(values=list(values)), self.assertRaises(Invalid):
                self.plan(**values)
        self.assertFalse(self.compatdata.exists())

    def test_launcher_reference_cannot_disagree_with_inventory(self):
        hashes = self.hashes()
        hashes["proton"] = "0"*64
        with self.assertRaises(Invalid):
            self.plan(expected_hashes=hashes)

    def test_external_payload_link_cannot_be_launched(self):
        (self.tool / "outside").symlink_to(self.exe)
        with self.assertRaises(Invalid):
            self.plan(payload_inventory=self.inventory())

    def test_target_pin_from_other_registration_is_refused(self):
        self.write_json(self.added,[{"appid":42,"exe":str(self.exe)}])
        other = pin_registration(self.added,"42",self.exe_root,self.steam)
        with self.assertRaises(Invalid):
            self.plan(target_pin=other)

    def test_registration_pinning_never_accepts_executable_outside_root(self):
        with self.assertRaises(Invalid):
            pin_registration(self.added,self.key,self.home,self.steam)

    def test_runtime_snapshot_cannot_be_used_as_live_launch_environment(self):
        context = RuntimeEnvironmentPlan("0"*64,"0077","root-snapshot",self.root,{},None,{},())
        with self.assertRaisesRegex(Invalid,"live runtime environment plan required"):
            self.plan(runtime_plan=context)

if __name__ == "__main__":
    unittest.main()
