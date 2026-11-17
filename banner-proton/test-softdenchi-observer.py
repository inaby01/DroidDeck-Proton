#!/usr/bin/env python3
"""Host-side behavioral tests; no Wine, games or credentials required."""

import ast
import errno
import io
import json
import os
import signal
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent.parent
DIST = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else SOURCE
sys.dont_write_bytecode = True
sys.path.insert(0, str(DIST))
from softdenchi_observer import (
    SOFTDENCHI_PROXY,
    Observer,
    Process,
    ProxyCleanup,
    Tracker,
    image_path,
    pidfd_preflight,
    read_stat,
    snapshot,
)


def process(pid, image, parent=1, started=10, game_id="test-game", native_program="", executable_id=None):
    return Process(pid, started, parent, "S", image_path(image), game_id,
                   native_program=native_program,
                   executable_id=("1:200" if native_program else "") if executable_id is None else executable_id)


def sample(tracker, processes, now, unreadable=0):
    tracker.update({p.identity: p for p in processes}, unreadable, now)
    return tracker.last_decision


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.tracker = Tracker("/games/Another Title/launch.exe", "test-game")
        sample(self.tracker, [], 0)
        self.launcher = process(10, r"Z:\games\Another Title\launch.exe")
        self.payload = process(11, r"Z:\games\Another Title\payload.log", parent=10)
        self.proxy = process(20, SOFTDENCHI_PROXY, parent=30)

    def test_game_handoff_service_proxy_and_grace(self):
        service = process(30, r"C:\Program Files (x86)\SoftDenchi\UCManSvc.exe")
        sample(self.tracker, [self.launcher, service, self.proxy], 1)
        result = sample(self.tracker, [self.payload, service, self.proxy], 2)
        self.assertEqual(result["phase"], "game_processes_present")
        self.assertEqual(sample(self.tracker, [service, self.proxy], 3)["phase"], "game_absence_grace")
        result = sample(self.tracker, [service, self.proxy], 8)
        self.assertEqual(result["phase"], "helpers_remaining_candidate")
        self.assertEqual(result["proxy_candidates"], [[20, 10]])
        self.assertTrue(result["cleanup_requires_revalidation"])

    def test_proxy_alone_never_arms_before_game_observation(self):
        result = sample(self.tracker, [self.proxy], 1000)
        self.assertEqual(result["phase"], "awaiting_game_observation")

    def test_game_reappearing_cancels_grace(self):
        sample(self.tracker, [self.launcher, self.proxy], 1)
        sample(self.tracker, [self.proxy], 2)
        sample(self.tracker, [self.payload, self.proxy], 6)
        self.assertEqual(sample(self.tracker, [self.proxy], 7)["phase"], "game_absence_grace")
        self.assertEqual(sample(self.tracker, [self.proxy], 11)["phase"], "game_absence_grace")

    def test_new_proxy_restarts_absence_grace(self):
        sample(self.tracker, [self.launcher, self.proxy], 1)
        sample(self.tracker, [self.proxy], 2)
        new = process(22, SOFTDENCHI_PROXY)
        self.assertEqual(sample(self.tracker, [self.proxy, new], 6)["phase"], "game_absence_grace")
        self.assertEqual(sample(self.tracker, [self.proxy, new], 10)["phase"], "game_absence_grace")
        self.assertEqual(sample(self.tracker, [self.proxy, new], 11)["phase"], "helpers_remaining_candidate")

    def test_descendant_outside_game_directory_survives_launcher(self):
        child = process(12, r"C:\other\engine.exe", parent=10)
        sample(self.tracker, [self.launcher, child, self.proxy], 1)
        self.assertEqual(sample(self.tracker, [child, self.proxy], 20)["phase"], "game_processes_present")

    def test_reused_pid_is_not_old_game_descendant(self):
        child = process(12, r"C:\other\engine.exe", parent=10)
        sample(self.tracker, [self.launcher, child], 1)
        reused = process(12, r"C:\unrelated.exe", started=99)
        result = sample(self.tracker, [reused, self.proxy], 2)
        self.assertEqual(result["phase"], "indeterminate")
        self.assertIn("unclassified_prefix_process", result["blockers"])

    def test_unknown_cross_game_and_incomplete_snapshots_block(self):
        for extra, unreadable, reason in [
            ([process(40, r"C:\unknown.exe")], 0, "unclassified_prefix_process"),
            ([process(40, r"C:\windows\system32\explorer.exe", game_id="other")],
             0, "different_game_id_in_prefix"),
            ([], 1, "incomplete_proc_snapshot"),
        ]:
            with self.subTest(reason=reason):
                sample(self.tracker, [self.launcher, self.proxy], 1)
                result = sample(self.tracker, [self.proxy] + extra, 100, unreadable)
                self.assertEqual(result["phase"], "indeterminate")
                self.assertIn(reason, result["blockers"])

    def test_baseline_proxy_does_not_become_session_owned(self):
        tracker = Tracker("/games/Another Title/launch.exe", "test-game")
        sample(tracker, [self.proxy], 0)
        sample(tracker, [self.launcher, self.proxy], 1)
        result = sample(tracker, [self.proxy], 100)
        self.assertIn("preexisting_proxy", result["blockers"])

    def test_proxy_basename_elsewhere_is_not_allowlisted(self):
        spoof = process(40, r"C:\another\sdproxy.exe")
        self.assertEqual(self.tracker.role(spoof), "unclassified")

    def test_known_system_helpers_do_not_hide_game_exit(self):
        helpers = [process(40, r"C:\windows\system32\lsass.exe"),
                   process(41, r"C:\windows\syswow64\tabtip.exe")]
        sample(self.tracker, [self.launcher, self.proxy] + helpers, 1)
        sample(self.tracker, [self.proxy] + helpers, 2)
        result = sample(self.tracker, [self.proxy] + helpers, 7)
        self.assertEqual(result["phase"], "helpers_remaining_candidate")
        self.assertTrue(result["cleanup_requires_revalidation"])

    def test_system_helper_name_outside_system_directory_blocks(self):
        for image in [r"C:\other\lsass.exe", r"Z:\other\tabtip.exe"]:
            with self.subTest(image=image):
                extra = process(40, image)
                sample(self.tracker, [self.launcher, self.proxy, extra], 1)
                result = sample(self.tracker, [self.proxy, extra], 100)
                self.assertEqual(result["phase"], "indeterminate")
                self.assertEqual(result["unclassified_processes"],
                                 [self.tracker.process_record(extra, "unclassified")])

    def test_decision_is_self_contained_when_process_events_are_truncated(self):
        unknown = process(40, r"C:\unknown.exe")
        sample(self.tracker, [self.launcher, self.proxy, unknown], 1)
        result = sample(self.tracker, [self.proxy, unknown], 100)
        self.assertEqual(result["game_processes"], [])
        self.assertEqual(result["proxy_processes"],
                         [self.tracker.process_record(self.proxy, "softdenchi_proxy")])
        self.assertEqual(result["unclassified_processes"][0]["image"], unknown.image)

    def test_unsupported_launch_does_not_arm(self):
        tracker = Tracker("relative.exe", "test-game")
        self.assertIn("unsupported_target_path", sample(tracker, [self.proxy], 0)["blockers"])

    def test_verified_native_helpers_from_wine_device_are_separate(self):
        device = process(40, r"C:\windows\system32\winedevice.exe")
        launch = process(41, "dbus-launch", parent=40, native_program="/usr/bin/dbus-launch")
        daemon = process(42, "/usr/bin/dbus-daemon", parent=40, native_program="/usr/bin/dbus-daemon")
        others = [device, launch, daemon, self.proxy]
        sample(self.tracker, [self.launcher] + others, 1)
        sample(self.tracker, others, 2)
        result = sample(self.tracker, others, 7)
        self.assertEqual(result["phase"], "helpers_remaining_candidate")
        self.assertEqual(len(result["native_auxiliary_processes"]), 2)
        self.assertEqual(result["proxy_candidates"], [[20, 10]])
        self.assertTrue(result["cleanup_requires_revalidation"])
        self.assertFalse(result["session_exit_verified"])

    def test_native_binary_alone_without_parent_proof_still_blocks(self):
        daemon = process(42, "/usr/bin/dbus-daemon", native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, daemon, self.proxy], 1)
        result = sample(self.tracker, [daemon, self.proxy], 20)
        self.assertEqual(result["phase"], "indeterminate")
        self.assertEqual(result["native_auxiliary_processes"], [])

    def test_native_name_alone_even_with_wine_parent_still_blocks(self):
        device = process(40, r"C:\windows\system32\winedevice.exe")
        daemon = process(42, "/usr/bin/dbus-daemon", parent=40)
        others = [device, daemon, self.proxy]
        sample(self.tracker, [self.launcher] + others, 1)
        self.assertEqual(sample(self.tracker, others, 20)["phase"], "indeterminate")

    def test_native_game_child_remains_game_after_reparenting(self):
        daemon = process(42, "/usr/bin/dbus-daemon", parent=10, native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, daemon, self.proxy], 1)
        orphan = process(42, "/usr/bin/dbus-daemon", parent=1, native_program="/usr/bin/dbus-daemon")
        result = sample(self.tracker, [orphan, self.proxy], 20)
        self.assertEqual(result["phase"], "game_processes_present")
        self.assertEqual(result["native_auxiliary_processes"], [])

    def test_native_origin_survives_parent_exit_but_not_pid_reuse(self):
        device = process(40, r"C:\windows\system32\winedevice.exe")
        daemon = process(42, "/usr/bin/dbus-daemon", parent=40, native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, device, daemon, self.proxy], 1)
        orphan = process(42, "/usr/bin/dbus-daemon", parent=1, native_program="/usr/bin/dbus-daemon")
        result = sample(self.tracker, [orphan, self.proxy], 2)
        self.assertEqual(result["native_auxiliary_processes"][0]["native_origin"]["wine_anchor"], [40, 10])
        reused = process(42, "/usr/bin/dbus-daemon", started=99, native_program="/usr/bin/dbus-daemon")
        result = sample(self.tracker, [reused, self.proxy], 20)
        self.assertEqual(result["phase"], "indeterminate")
        self.assertEqual(result["native_auxiliary_processes"], [])

    def test_transitive_native_origin(self):
        device = process(40, r"C:\windows\system32\winedevice.exe")
        launch = process(42, "dbus-launch", parent=40, native_program="/usr/bin/dbus-launch")
        daemon = process(41, "/usr/bin/dbus-daemon", parent=42, native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, device, daemon, launch, self.proxy], 1)
        result = self.tracker.last_decision
        self.assertEqual(len(result["native_auxiliary_processes"]), 2)
        self.assertEqual(result["native_auxiliary_processes"][0]["native_origin"]["wine_anchor"], [40, 10])

    def test_lost_native_executable_proof_returns_to_unknown(self):
        device = process(40, r"C:\windows\system32\winedevice.exe")
        daemon = process(42, "/usr/bin/dbus-daemon", parent=40, native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, device, daemon, self.proxy], 1)
        unverified = process(42, "/usr/bin/dbus-daemon", parent=40)
        result = sample(self.tracker, [device, unverified, self.proxy], 20)
        self.assertEqual(result["phase"], "indeterminate")

    def test_parent_starting_after_child_is_not_origin_proof(self):
        device = process(40, r"C:\windows\system32\winedevice.exe", started=99)
        daemon = process(42, "/usr/bin/dbus-daemon", parent=40, native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, device, daemon, self.proxy], 1)
        result = sample(self.tracker, [device, daemon, self.proxy], 20)
        self.assertEqual(result["phase"], "indeterminate")

    def test_native_executable_change_does_not_reuse_old_origin(self):
        device = process(40, r"C:\windows\system32\winedevice.exe")
        daemon = process(42, "/usr/bin/dbus-daemon", parent=40, native_program="/usr/bin/dbus-daemon")
        sample(self.tracker, [self.launcher, device, daemon, self.proxy], 1)
        changed = process(42, "/usr/bin/dbus-daemon", parent=1,
                          native_program="/usr/bin/dbus-daemon", executable_id="1:201")
        result = sample(self.tracker, [changed, self.proxy], 20)
        self.assertEqual(result["phase"], "indeterminate")
        self.assertEqual(result["native_auxiliary_processes"], [])


class SnapshotTests(unittest.TestCase):
    def make_process(self, root, pid, prefix, state="S", argv0=SOFTDENCHI_PROXY):
        directory = root / str(pid)
        directory.mkdir()
        # stat field 22 is starttime; comm intentionally has ')' and spaces.
        fields = [state, "1"] + ["0"] * 17 + ["123"]
        (directory / "stat").write_text(f"{pid} (name ) with spaces) " + " ".join(fields))
        (directory / "environ").write_bytes(
            os.fsencode(f"WINEPREFIX={prefix}\0SteamGameId=test-game\0SECRET=do-not-log\0"))
        (directory / "cmdline").write_bytes(os.fsencode(argv0 + "\0/m\0do-not-log\0"))
        return directory

    def test_prefix_isolation_zombies_and_sensitive_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_process(root, 100001, "/test/pfx")
            self.make_process(root, 100002, "/other/pfx")
            self.make_process(root, 100003, "/test/pfx", state="Z")
            found, unreadable = snapshot("/test/pfx", root)
            self.assertEqual(set(found), {(100001, 123)})
            self.assertEqual(unreadable, 0)
            tracker = Tracker("/games/launch.exe", "test-game")
            output = json.dumps(tracker.update(found, unreadable, 0))
            self.assertNotIn("do-not-log", output)
            self.assertNotIn("SECRET", output)

    def test_missing_environment_is_not_silently_treated_as_matching(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entry = self.make_process(root, 100001, "/test/pfx")
            (entry / "environ").write_bytes(b"OTHER=value\0")
            self.assertEqual(snapshot("/test/pfx", root), ({}, 0))

    def test_permission_failure_marks_snapshot_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_process(root, 100001, "/test/pfx")
            with patch.object(Path, "read_bytes", side_effect=PermissionError):
                self.assertEqual(snapshot("/test/pfx", root), ({}, 1))

    def test_stat_parser(self):
        fields = ["S", "42"] + ["0"] * 17 + ["456"]
        self.assertEqual(read_stat("10 (name ) spaces) " + " ".join(fields)), ("S", 42, 456))

    def test_native_executable_identity_uses_inode_not_command_name(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reference = root / "reference"
            reference.write_bytes(b"native executable fixture")
            other = root / "other"
            other.write_bytes(b"another executable")
            valid = self.make_process(root, 100001, "/test/pfx", argv0="dbus-launch")
            (valid / "exe").symlink_to(reference)
            spoof = self.make_process(root, 100002, "/test/pfx", argv0="/usr/bin/dbus-launch")
            (spoof / "exe").symlink_to(other)
            found, unreadable = snapshot("/test/pfx", root, {"/usr/bin/dbus-launch": reference})
            self.assertEqual(unreadable, 0)
            self.assertEqual(found[(100001, 123)].native_program, "/usr/bin/dbus-launch")
            identity = reference.stat()
            self.assertEqual(found[(100001, 123)].executable_id, f"{identity.st_dev}:{identity.st_ino}")
            self.assertEqual(found[(100002, 123)].native_program, "")

    def test_missing_executable_proof_is_recorded_not_assumed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_process(root, 100001, "/test/pfx", argv0="dbus-launch")
            found, _ = snapshot("/test/pfx", root)
            self.assertEqual(found[(100001, 123)].native_program, "")
            self.assertEqual(found[(100001, 123)].executable_error, "FileNotFoundError")

    def test_observer_lifecycle_never_sends_signal(self):
        output = io.StringIO()
        with patch("softdenchi_observer.snapshot", return_value=({}, 0)), \
                patch("os.kill", side_effect=AssertionError("must not signal")):
            observer = Observer({"WINEPREFIX": "/test/pfx"}, "/games/launch.exe", output)
            observer.start()
            observer.stop()
        events = [json.loads(line.split(" ", 1)[1]) for line in output.getvalue().splitlines()]
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[-1]["event"], "stop")
        self.assertTrue(events[-1]["observe_only"])

    def test_output_failure_does_not_raise_into_launcher(self):
        output = io.StringIO()
        output.close()
        Observer({"WINEPREFIX": "/test/pfx"}, "/games/launch.exe", output).stop()

    def test_mirror_receives_records_even_when_proton_log_is_closed(self):
        output = io.StringIO()
        output.close()
        mirror = io.StringIO()
        Observer({"WINEPREFIX": "/test/pfx"}, "/games/launch.exe", output, mirror=mirror).stop()
        event = json.loads(mirror.getvalue().split(" ", 1)[1])
        self.assertEqual(event["schema"], 4)
        self.assertEqual(event["event"], "stop")

    def test_same_output_is_not_duplicated(self):
        output = io.StringIO()
        Observer({"WINEPREFIX": "/test/pfx"}, "/games/launch.exe", output, mirror=output).stop()
        self.assertEqual(len(output.getvalue().splitlines()), 1)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.tracker = Tracker("/games/Another Title/launch.exe", "test-game")
        def wine(p):
            return replace(p, executable="/test/wine-preloader", executable_id="1:300")
        self.root = wine(process(70, r"C:\windows\system32\steam.exe", parent=1, started=1))
        self.services = wine(process(71, r"C:\windows\system32\services.exe", parent=70, started=2))
        self.service = wine(process(30, r"C:\Program Files (x86)\SoftDenchi\UCManSvc.exe", parent=71, started=3))
        self.parent = wine(process(20, SOFTDENCHI_PROXY, parent=30))
        self.child = wine(process(21, SOFTDENCHI_PROXY, parent=20, started=11))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        server_file = Path(temp.name) / "wineserver"
        server_file.write_bytes(b"wineserver fixture")
        identity = server_file.stat()
        self.server = replace(process(72, str(server_file), parent=70, started=3),
                              executable=str(server_file), executable_id=f"{identity.st_dev}:{identity.st_ino}")
        self.game = process(10, r"Z:\games\Another Title\launch.exe")
        self.payload = process(11, r"Z:\games\Another Title\payload.log", parent=10)
        self.current = {p.identity: p for p in [self.root, self.services, self.service, self.parent,
                                              self.child, self.server]}
        sample(self.tracker, [], 0)
        sample(self.tracker, [self.game, self.payload] + list(self.current.values()), 1)
        self.tracker.update(self.current, 0, 2)
        self.tracker.update(self.current, 0, 7)
        self.events = []
        self.reader = unittest.mock.Mock(return_value=(self.current, 0))
        self.stopped = unittest.mock.Mock(return_value=False)
        self.cleaner = ProxyCleanup("/test/pfx", self.tracker, self.events.append, self.stopped,
                                    reader=self.reader, launcher_pid=1, wineserver_path=str(server_file))

    def attempt(self, open_error=None, send_error=None):
        with patch.object(os, "pidfd_open", create=True, side_effect=open_error or (lambda pid, flags: pid + 1000)) as opened, \
                patch.object(signal, "pidfd_send_signal", create=True, side_effect=send_error) as sent, \
                patch.object(os, "close") as closed, \
                patch.object(os, "kill", side_effect=AssertionError("PID fallback forbidden")):
            self.cleaner.attempt(self.current, 7)
        return opened, sent, closed

    def test_only_revalidated_proxies_receive_one_sigterm_batch(self):
        opened, sent, closed = self.attempt()
        self.assertEqual(opened.call_args_list, [unittest.mock.call(20, 0), unittest.mock.call(21, 0)])
        self.assertEqual(sent.call_args_list, [unittest.mock.call(1020, signal.SIGTERM, None, 0),
                                              unittest.mock.call(1021, signal.SIGTERM, None, 0)])
        self.assertEqual(closed.call_count, 2)
        self.assertEqual(len(self.cleaner.signalled), 2)
        self.assertEqual(self.attempt()[0].call_count, 0)

    def observe_game_proxies(self, unreadable=0, game_changes=None):
        self.tracker = Tracker("/games/Another Title/launch.exe", "test-game")
        self.cleaner.tracker = self.tracker
        self.game = replace(self.game, parent=self.root.pid, started=4,
                            executable=self.root.executable, executable_id=self.root.executable_id)
        if game_changes:
            self.game = replace(self.game, **game_changes)
        self.payload = replace(self.payload, started=5, executable=self.root.executable,
                               executable_id=self.root.executable_id)
        original_parent = replace(self.parent, parent=self.game.pid)
        live = {p.identity: p for p in [self.root, self.services, self.service, self.server,
                                       self.game, self.payload, original_parent, self.child]}
        sample(self.tracker, [], 0)
        self.tracker.update(live, unreadable, 1)
        self.cleaner.observe_origins(live, unreadable)
        self.current = {p.identity: p for p in [self.root, self.services, self.service, self.server,
                                              replace(self.parent, parent=self.root.pid), self.child]}
        self.tracker.update(self.current, 0, 2)
        self.cleaner.observe_origins(self.current, 0)
        self.tracker.update(self.current, 0, 7)
        self.reader.return_value = (self.current, 0)

    def test_observed_game_proxy_survives_game_exit_and_reparenting(self):
        self.observe_game_proxies()
        self.assertEqual(set(self.cleaner.game_origins), {self.parent.identity, self.child.identity})
        _, sent, _ = self.attempt()
        self.assertEqual(sent.call_count, 2)
        self.assertEqual([e["origin"] for e in self.events if e["event"] == "cleanup_sigterm_sent"],
                         ["observed_game_ancestry", "observed_game_ancestry"])

    def test_unobserved_proxy_under_launcher_is_not_accepted(self):
        self.current[self.parent.identity] = replace(self.parent, parent=self.root.pid)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_incomplete_observation_does_not_establish_game_origin(self):
        self.observe_game_proxies(unreadable=1)
        self.assertEqual(self.cleaner.game_origins, {})
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_game_origin_requires_current_launcher_and_same_wine(self):
        for change in [{"parent": 900}, {"game_id": "other"}, {"executable_id": "1:999"},
                       {"executable": "/other/wine"}, {"executable_error": "PermissionError"},
                       {"started": 99}]:
            with self.subTest(change=change):
                self.cleaner.game_origins.clear()
                self.observe_game_proxies(game_changes=change)
                self.assertEqual(self.cleaner.game_origins, {})
                self.assertEqual(self.attempt()[1].call_count, 0)

    def test_game_proof_does_not_survive_proxy_pid_or_executable_change(self):
        for changes in [{"started": 99}, {"executable_id": "1:999"},
                        {"image": r"c:\other\sdproxy.exe"}, {"game_id": "other"}]:
            with self.subTest(changes=changes):
                self.cleaner.game_origins.clear()
                self.observe_game_proxies()
                fresh = dict(self.current)
                fresh.pop(self.parent.identity)
                changed = replace(self.current[self.parent.identity], **changes)
                fresh[changed.identity] = changed
                self.reader.return_value = (fresh, 0)
                self.assertEqual(self.attempt()[1].call_count, 0)

    def test_reused_launcher_invalidates_game_origin(self):
        self.observe_game_proxies()
        fresh = dict(self.current)
        fresh.pop(self.root.identity)
        root = replace(self.root, started=99)
        fresh[root.identity] = root
        self.reader.return_value = (fresh, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_unexpected_parent_after_game_exit_blocks_cleanup(self):
        self.observe_game_proxies()
        unknown_parent = replace(self.services, pid=90)
        fresh = {**self.current, unknown_parent.identity: unknown_parent,
                 self.parent.identity: replace(self.parent, parent=unknown_parent.pid)}
        self.reader.return_value = (fresh, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_missing_child_origin_blocks_entire_batch(self):
        self.observe_game_proxies()
        self.cleaner.game_origins.pop(self.child.identity)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_new_child_after_game_exit_does_not_acquire_origin(self):
        self.observe_game_proxies()
        extra = replace(self.child, pid=25, started=12)
        self.current[extra.identity] = extra
        self.cleaner.observe_origins(self.current, 0)
        self.assertNotIn(extra.identity, self.cleaner.game_origins)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_preexisting_game_proxy_does_not_acquire_origin(self):
        self.observe_game_proxies()
        self.tracker.baseline.add(self.parent.identity)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_missing_launcher_clears_game_origins(self):
        self.observe_game_proxies()
        fresh = dict(self.current)
        fresh.pop(self.root.identity)
        self.reader.return_value = (fresh, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)
        self.assertEqual(self.cleaner.game_origins, {})

    def test_game_reappearing_prevents_signals(self):
        fresh = {**self.current, self.game.identity: self.game}
        self.reader.return_value = (fresh, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_unknown_process_or_read_failure_prevents_signals(self):
        unknown = process(88, r"C:\unknown.exe")
        self.reader.return_value = ({**self.current, unknown.identity: unknown}, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)
        self.reader.return_value = (self.current, 1)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_proxy_pid_reuse_prevents_signals(self):
        fresh = dict(self.current)
        fresh.pop(self.parent.identity)
        reused = replace(self.parent, started=99)
        fresh[reused.identity] = reused
        self.reader.return_value = (fresh, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_executable_path_change_prevents_signal(self):
        changed = replace(self.parent, executable="/other/wine-preloader")
        self.reader.return_value = ({**self.current, changed.identity: changed}, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_handoff_not_observed_prevents_authentication_only_cleanup(self):
        self.tracker.seen_handoff = False
        opened, sent, _ = self.attempt()
        self.assertEqual(opened.call_count, 0)
        self.assertEqual(sent.call_count, 0)
        self.assertEqual(self.events[-1]["reason"], "game_handoff_not_observed")

    def test_missing_game_id_prevents_cleanup(self):
        self.tracker.game_id = ""
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_preexisting_proxy_prevents_cleanup(self):
        self.tracker.baseline.add(self.parent.identity)
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_foreign_game_or_wrong_wine_loader_prevents_cleanup(self):
        self.current[self.parent.identity] = replace(self.parent, game_id="another-game")
        self.assertEqual(self.attempt()[0].call_count, 0)
        self.current[self.parent.identity] = replace(self.parent, executable_id="1:999")
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_service_must_belong_to_current_launcher(self):
        self.current[self.services.identity] = replace(self.services, parent=900)
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_service_origin_is_rechecked_after_pidfd_open(self):
        changed = replace(self.services, parent=900)
        self.reader.return_value = ({**self.current, changed.identity: changed}, 0)
        self.assertEqual(self.attempt()[1].call_count, 0)

    def test_launcher_must_be_direct_child_of_this_proton(self):
        self.current[self.root.identity] = replace(self.root, parent=900)
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_native_wineserver_must_match_installed_binary(self):
        self.current[self.server.identity] = replace(self.server, executable_id="1:999")
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_infrastructure_basename_in_other_directory_is_not_enough(self):
        unknown = process(80, r"C:\other\services.exe")
        self.current[unknown.identity] = unknown
        self.assertEqual(self.attempt()[0].call_count, 0)

    def test_no_pidfd_api_has_no_pid_fallback(self):
        with patch.object(os, "pidfd_open", None, create=True), \
                patch.object(os, "kill", side_effect=AssertionError("forbidden")):
            self.cleaner.attempt(self.current, 7)
        self.assertTrue(self.cleaner.unavailable)
        self.assertEqual(self.events[-1]["reason"], "pidfd_api_unavailable")

    def test_partial_pidfd_open_failure_closes_pinned_handle(self):
        _, sent, closed = self.attempt(open_error=[1020, PermissionError(errno.EPERM, "denied")])
        self.assertEqual(sent.call_count, 0)
        closed.assert_called_once_with(1020)
        self.assertTrue(self.cleaner.unavailable)

    def test_signal_failure_has_no_escalation(self):
        _, sent, closed = self.attempt(send_error=PermissionError(errno.EPERM, "denied"))
        self.assertEqual(sent.call_count, 1)
        self.assertEqual(closed.call_count, 2)
        self.assertTrue(self.cleaner.unavailable)
        self.assertEqual(self.cleaner.signalled, [])

    def test_child_already_exited_after_parent_signal_is_skipped(self):
        gone = {k: p for k, p in self.current.items() if p.image != SOFTDENCHI_PROXY}
        self.reader.side_effect = [(self.current, 0), (gone, 0)]
        _, sent, closed = self.attempt()
        self.assertEqual(sent.call_count, 1)
        self.assertEqual(closed.call_count, 2)

    def test_child_is_still_signalled_after_parent_exit_and_reparenting(self):
        fresh = dict(self.current)
        fresh.pop(self.parent.identity)
        fresh[self.child.identity] = replace(self.child, parent=1)
        self.reader.side_effect = [(self.current, 0), (fresh, 0)]
        _, sent, closed = self.attempt()
        self.assertEqual(sent.call_count, 2)
        self.assertEqual(closed.call_count, 2)

    def test_new_proxy_during_parent_exit_is_not_added_to_batch(self):
        extra = replace(self.child, pid=25, started=99)
        fresh = {**self.current, extra.identity: extra}
        self.reader.side_effect = [(self.current, 0), (fresh, 0)]
        self.assertEqual(self.attempt()[1].call_count, 1)

    def test_game_reappearing_between_signals_stops_batch(self):
        fresh = {**self.current, self.game.identity: self.game}
        self.reader.side_effect = [(self.current, 0), (fresh, 0)]
        self.assertEqual(self.attempt()[1].call_count, 1)

    def test_stop_request_before_send_cancels_cleanup(self):
        self.stopped.side_effect = [False, False, True]
        opened, sent, closed = self.attempt()
        self.assertEqual(opened.call_count, 2)
        self.assertEqual(sent.call_count, 0)
        self.assertEqual(closed.call_count, 2)

    def test_native_auxiliaries_are_never_targets(self):
        device = process(80, r"C:\windows\system32\winedevice.exe")
        daemon = process(81, "/usr/bin/dbus-daemon", parent=80, native_program="/usr/bin/dbus-daemon")
        self.current.update({p.identity: p for p in [device, daemon]})
        self.tracker.update(self.current, 0, 8)
        opened, sent, _ = self.attempt()
        self.assertEqual(opened.call_count, 2)
        self.assertEqual(sent.call_count, 2)
        self.assertEqual(len(self.tracker.last_decision["native_auxiliary_processes"]), 1)

    def test_followup_reports_remaining_without_retry(self):
        self.attempt()
        self.cleaner.report(self.current, 12)
        self.assertEqual(self.events[-1]["event"], "cleanup_followup")
        self.assertEqual(len(self.events[-1]["remaining_signalled"]), 2)

    def test_preflight_failure_is_reported_without_entering_cleanup(self):
        output = io.StringIO()
        with patch("softdenchi_observer.pidfd_preflight", return_value={"available": False, "returncode": -31}), \
                patch("softdenchi_observer.snapshot", return_value=({}, 0)), \
                patch.object(os, "kill", side_effect=AssertionError("forbidden")):
            observer = Observer({"WINEPREFIX": "/test/pfx", "PROTON_SOFTDENCHI_CLEANUP": "1"},
                                "/games/launch.exe", output)
            observer.start()
            observer.stop()
        self.assertTrue(observer.cleaner.unavailable)
        self.assertIn('"reason": "pidfd_preflight_failed"', output.getvalue())

    def test_preflight_uses_only_signal_zero_in_isolated_helper(self):
        with patch.object(os, "pidfd_open", create=True), \
                patch.object(signal, "pidfd_send_signal", create=True), \
                patch("softdenchi_observer.subprocess.run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertTrue(pidfd_preflight()["available"])
        self.assertIn("pidfd_send_signal(fd,0,None,0)", run.call_args.args[0][2])
        self.assertEqual(run.call_args.kwargs["timeout"], 5)


class LauncherTests(unittest.TestCase):
    def run_launcher(self, enabled, run_proc, cleanup="0"):
        tree = ast.parse((DIST / "proton").read_text())
        session = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Session")
        method = next(node for node in session.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        scope = {"os": os, "shutil": SimpleNamespace(which=lambda _: None), "sys": sys,
                 "g_proton": SimpleNamespace(host_pe_arch="aarch64-windows", wine_bin="wine", wineserver_bin="wineserver"),
                 "log": lambda _: None}
        # Execute only Session.run from the checked-out (or packaged) trusted source.
        exec(compile(ast.Module(body=[method], type_ignores=[]), "proton", "exec"), scope)  # noqa: S102
        session = SimpleNamespace(env={"PROTON_SOFTDENCHI_OBSERVE": enabled, "WINEPREFIX": "/test/pfx",
                                       "PROTON_SOFTDENCHI_CLEANUP": cleanup},
                                  remote_debug_cmd=None, log_file=io.StringIO(), cmdlineappend=[], run_proc=run_proc)
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(sys, "argv", ["proton", "run", "/games/launch.exe"]), \
                patch.object(sys, "stderr", session.log_file):
            return scope["run"](session)

    def test_disabled_observer_is_not_constructed(self):
        with patch("softdenchi_observer.Observer", side_effect=AssertionError("must stay disabled")):
            self.assertEqual(self.run_launcher("0", lambda _: 7), 7)

    def test_cleanup_flag_alone_starts_monitor_and_records_returncode(self):
        observer = unittest.mock.MagicMock()
        with patch("softdenchi_observer.Observer", return_value=observer):
            self.assertEqual(self.run_launcher("0", lambda _: 7, cleanup="1"), 7)
        observer.start.assert_called_once()
        observer.stop.assert_called_once_with(returncode=7)

    def test_observer_start_failure_preserves_game_launch_and_status(self):
        with patch("softdenchi_observer.Observer.start", side_effect=OSError):
            self.assertEqual(self.run_launcher("1", lambda _: 7), 7)

    def test_thread_start_failure_preserves_game_launch_and_status(self):
        with patch("softdenchi_observer.snapshot", return_value=({}, 0)), \
                patch("threading.Thread.start", side_effect=RuntimeError):
            self.assertEqual(self.run_launcher("1", lambda _: 7), 7)

    def test_observer_stops_on_game_launch_exception(self):
        observer = unittest.mock.MagicMock()
        with patch("softdenchi_observer.Observer", return_value=observer):
            def fail(_):
                raise OSError("launch failed")
            with self.assertRaises(OSError):
                self.run_launcher("1", fail)
        observer.stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
