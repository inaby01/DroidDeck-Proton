#!/usr/bin/env python3
"""Minimum hook environments from generated, nonexecuted runtime fixtures."""

import copy
import json
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURES = runpy.run_path(str(Path(__file__).with_name("test_preparation_runtime.py")))
import preparation_runtime as runtime
from preparation_common import Invalid
from preparation_runtime_context import plan_runtime_environment


class RuntimeContextTests(unittest.TestCase):
    def setUp(self):
        FIXTURES["RuntimeTests"].setUp(self)
        source_patch = patch.dict(runtime.SOURCES,self.hashes,clear=True)
        source_patch.start()
        self.addCleanup(source_patch.stop)
        self.environment = {"DISPLAY":":7","WAYLAND_DISPLAY":"wayland-0","XDG_RUNTIME_DIR":str(self.root/"private-run"),
                            "PULSE_SERVER":"unix:"+str(self.root/"private-pulse"),"PROOT_FP_KEY":"DUMMY_PROTOCOL_SECRET"}
        self.reference = runtime.inspect_runtime(self.root,self.environment)
        self.reference.update(view="current-root",auditor_architecture="aarch64")
        self.reference["process_observation_basis"]["umask"] = "0077"

    def plan(self, environment=None, reference=None):
        return plan_runtime_environment(self.root,self.reference if reference is None else reference,
                                        self.environment if environment is None else environment)

    def test_known_hook_order_and_private_values_without_execution(self):
        with patch("subprocess.Popen",side_effect=AssertionError("no execution")):
            plan = self.plan()
        self.assertEqual(plan.environment["LD_PRELOAD"],str(self.root/runtime.LIBRARIES[1])+":"+str(self.root/runtime.LIBRARIES[0]))
        self.assertEqual(plan.environment["LD_AUDIT"],str(self.root/runtime.LIBRARIES[2]))
        self.assertEqual(plan.environment["PROTON_USE_PIPEWIRE"],"0")
        self.assertEqual(plan.umask,"0077")
        for rendered in (repr(plan),json.dumps(plan.summary())):
            self.assertNotIn("DUMMY_PROTOCOL_SECRET",rendered)
            self.assertNotIn(str(self.root),rendered)
        self.assertFalse(plan.summary()["runtime_execution_verified"])
        self.assertFalse(plan.summary()["device_namespace_verified"])

    def test_runtime_library_or_source_change_invalidates_reference(self):
        plan = self.plan()
        path = self.root/runtime.LIBRARIES[0]
        raw = path.read_bytes()
        path.write_bytes(raw+b"changed")
        with self.assertRaises(Invalid):
            plan.verify(self.environment)
        path.write_bytes(raw)
        (self.root/next(iter(self.hashes))).write_text("changed")
        with self.assertRaises(Invalid):
            self.plan()

    def test_unknown_inherited_loader_values_are_refused(self):
        for values in ({"LD_PRELOAD":"/unknown/private.so"},{"LD_AUDIT":"/unknown/private.so"}):
            with self.assertRaises(Invalid):
                self.plan({**self.environment,**values})

    def test_absent_protocol_key_does_not_select_audit_hook(self):
        environment = {k:v for k,v in self.environment.items() if k!="PROOT_FP_KEY"}
        reference = copy.deepcopy(self.reference)
        reference["environment_presence"]["PROOT_FP_KEY"] = False
        self.assertNotIn("LD_AUDIT",self.plan(environment,reference).environment)
        with self.assertRaises(Invalid):
            self.plan(environment)

    def test_label_is_private_and_checked_live(self):
        path = self.root/"etc/steam-compatibility-label"
        path.write_bytes(b"DUMMY_PRIVATE_LABEL")
        reference = copy.deepcopy(self.reference)
        reference["label"] = runtime.inspect_runtime(self.root,self.environment)["label"]
        plan = self.plan(reference=reference)
        self.assertEqual(plan.label,b"DUMMY_PRIVATE_LABEL")
        self.assertNotIn("DUMMY_PRIVATE_LABEL",repr(plan)+json.dumps(plan.summary()))
        path.write_bytes(b"changed")
        with self.assertRaises(Invalid):
            plan.verify(self.environment)

    def test_umask_must_have_one_supported_consistent_value(self):
        reference = copy.deepcopy(self.reference)
        reference["process_observation_basis"]["shell_umask"] = "0022"
        with self.assertRaises(Invalid):
            self.plan(reference=reference)
        reference["process_observation_basis"] = {"umask":"0000"}
        with self.assertRaises(Invalid):
            self.plan(reference=reference)

    def test_protocol_secret_changes_are_rechecked_without_public_fingerprint(self):
        plan = self.plan()
        changed = {**self.environment,"PROOT_FP_KEY":"ANOTHER_PROTOCOL_SECRET"}
        other = self.plan(changed)
        self.assertEqual(other.identity_digest,plan.identity_digest)
        with self.assertRaises(Invalid):
            plan.verify(changed)
        self.assertNotIn("ANOTHER_PROTOCOL_SECRET",json.dumps(other.summary()))

    def test_mutated_plan_environment_cannot_supply_unknown_loader(self):
        plan = self.plan()
        plan.environment["LD_PRELOAD"] = "/unknown/private.so"
        with self.assertRaises(Invalid):
            plan.verify(self.environment)

    def test_only_supported_arm64_live_audit_reference_is_accepted(self):
        for values in ({"view":"root-snapshot"},{"auditor_architecture":"x86_64"}):
            with self.assertRaises(Invalid):
                self.plan(reference={**self.reference,**values})

    def test_private_gui_auth_path_forwarding_and_pipewire_selection(self):
        plan = self.plan({**self.environment,"XAUTHORITY":"/private/gui-cookie","PROTON_USE_PIPEWIRE":"1"})
        self.assertEqual(plan.environment["XAUTHORITY"],"/private/gui-cookie")
        self.assertEqual(plan.environment["PROTON_USE_PIPEWIRE"],"1")
        self.assertNotIn("/private/gui-cookie",repr(plan)+json.dumps(plan.summary()))
        with self.assertRaises(Invalid):
            self.plan({**self.environment,"PROTON_USE_PIPEWIRE":"unknown"})


if __name__ == "__main__":
    unittest.main()
