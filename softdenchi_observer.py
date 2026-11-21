"""Process observations, with separately enabled experimental SdProxy cleanup."""

import errno
import json
import ntpath
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SOFTDENCHI_PROXY = r"c:\program files (x86)\softdenchi\sdproxy.exe"
SOFTDENCHI_SERVICE = r"c:\program files (x86)\softdenchi\ucmansvc.exe"
INFRASTRUCTURE = {
    "steam.exe", "umu.exe", "services.exe", "winedevice.exe", "explorer.exe",
    "plugplay.exe", "svchost.exe", "rpcss.exe", "conhost.exe", "wineserver",
}
# Classification by a system directory and known implementation, not basename alone.
# lsass: patches/game-patches/ace-lsass-samss-service-stub.patch uses the service
# dispatcher, which calls ProcessWineMakeProcessSystem. tabtip does so directly.
SYSTEM_HELPERS = {"lsass.exe", "tabtip.exe"}
SYSTEM_DIRECTORIES = {r"c:\windows\system32", r"c:\windows\syswow64"}
NATIVE_AUXILIARIES = {
    "/usr/bin/dbus-launch": "/usr/bin/dbus-launch",
    "/usr/bin/dbus-daemon": "/usr/bin/dbus-daemon",
}


def image_path(value):
    """Normalize an absolute DOS image or Proton's Z: mapping, without arguments."""
    value = value.replace("/", "\\")
    value = value.removeprefix("\\??\\")
    value = value.removeprefix("\\\\?\\")
    return ntpath.normpath(value).casefold()


def target_path(value):
    if os.path.isabs(value):
        return image_path("z:" + os.path.realpath(value))
    if ntpath.isabs(value) and ntpath.splitdrive(value)[0]:
        return image_path(value)
    return None


@dataclass(frozen=True)
class Process:
    pid: int
    started: int
    parent: int
    state: str
    image: str
    game_id: str
    executable: str = ""
    native_program: str = ""
    executable_error: str = ""
    executable_id: str = ""

    @property
    def identity(self):
        return self.pid, self.started


def read_stat(text):
    # comm can contain spaces and ')' characters. Fields after the final ')' are fixed.
    fields = text[text.rindex(")") + 2:].split()
    return fields[0], int(fields[1]), int(fields[19])


def stat_of(path):
    """Read /proc stat as bytes: comm is a truncated executable name and may not be valid UTF-8."""
    return path.read_bytes().decode("utf-8", "replace")


def read_threads(text):
    """num_threads (field 20): the thread group size, which keeps counting a zombie leader
    while other threads of the group still run."""
    return int(text[text.rindex(")") + 2:].split()[17])


LINGERING_LIMIT = 64


class Found(dict):
    """Snapshot result: prefix processes by identity, plus thread groups whose leader has
    exited (or is exiting) while other threads remain (``lingering``)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lingering = []


def environment_prefix(data, expected):
    """Classify an environment block: "prefix", "other" or None (empty block)."""
    if not data:
        return None
    for item in data.split(b"\0"):
        key, sep, value = item.partition(b"=")
        if sep and key == b"WINEPREFIX":
            return "prefix" if os.path.realpath(os.fsdecode(value)) == expected else "other"
    return "other"


def lingering_group(entry, started, expected):
    """Attribute a thread group whose leader cannot attribute it, through its other threads.

    Returns (attribution, reason): attribution is "prefix", "other", "ambiguous" or None when
    the group has ended. Threads share the address space, so a live thread's environ is the
    environment the process started with.
    """
    pid = entry.name
    try:
        tids = sorted(name for name in os.listdir(entry / "task") if name.isdecimal())
    except (FileNotFoundError, ProcessLookupError):
        tids = None
        reason = "task_unlisted"
    except OSError:
        return "ambiguous", "task_unlisted"
    unreadable = False
    empty = False
    for tid in tids or ():
        if tid == pid:
            continue
        task = entry / "task" / tid
        try:
            if read_stat(stat_of(task / "stat"))[0] in {"Z", "X"}:
                continue
            data = (task / "environ").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError):
            unreadable = True
            continue
        try:
            leader = read_stat(stat_of(entry / "stat"))
        except (FileNotFoundError, ProcessLookupError):
            return None, "group_ended"
        except (OSError, ValueError, IndexError):
            return "ambiguous", "leader_unreadable"
        if leader[2] != started:
            return "ambiguous", "identity_changed"
        found = environment_prefix(data, expected)
        if found is None:
            # An exiting thread's environ also reads empty: try the other threads first.
            empty = True
            continue
        return found, "task_environ"
    try:
        text = stat_of(entry / "stat")
        leader = read_stat(text)
        threads = read_threads(text)
    except (FileNotFoundError, ProcessLookupError):
        return None, "group_ended"
    except (OSError, ValueError, IndexError):
        return "ambiguous", "leader_unreadable"
    if leader[2] != started:
        return "ambiguous", "identity_changed"
    if threads <= 1:
        return None, "group_ended"
    if tids is None:
        return "ambiguous", reason
    if unreadable:
        return "ambiguous", "thread_unreadable"
    # Every readable thread had an empty environment: the process has none (Wine always sets WINEPREFIX).
    return ("other", "empty_environment") if empty else ("ambiguous", "no_readable_thread")


def executable_identity(entry, references):
    """Verify a native helper by executable inode, never by argv[0] alone."""
    executable = entry / "exe"
    try:
        path = os.readlink(executable)
        identity = executable.stat()
    except OSError as exc:
        return "", "", type(exc).__name__, ""
    executable_id = f"{identity.st_dev}:{identity.st_ino}"
    for program, reference in references.items():
        try:
            if os.path.samestat(identity, Path(reference).stat()):
                return path, program, "", executable_id
        except OSError:
            continue
    return path, "", "", executable_id


def native_reference_status():
    result = {}
    for program, reference in NATIVE_AUXILIARIES.items():
        try:
            identity = Path(reference).stat()
            result[program] = {"executable_id": f"{identity.st_dev}:{identity.st_ino}"}
        except OSError as exc:
            result[program] = {"error": type(exc).__name__}
    return result


def pidfd_preflight():
    # Isolate unsupported/blocked syscalls (including a possible SIGSYS) from
    # Proton. The helper probes only itself with signal 0, then exits.
    if not callable(getattr(os, "pidfd_open", None)) or not callable(getattr(signal, "pidfd_send_signal", None)):
        return {"available": False, "reason": "pidfd_api_unavailable"}
    code = ("import os,signal; fd=os.pidfd_open(os.getpid(),0); "
            "signal.pidfd_send_signal(fd,0,None,0); os.close(fd)")
    try:
        result = subprocess.run([sys.executable, "-c", code], timeout=5,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": type(exc).__name__}
    return {"available": result.returncode == 0, "returncode": result.returncode}


def snapshot(prefix, proc=Path("/proc"), native_references=None):
    """Read only selected env keys and argv[0]; never log full env or arguments."""
    found = Found()
    unreadable = 0
    expected = os.path.realpath(prefix)
    references = NATIVE_AUXILIARIES if native_references is None else native_references
    for entry in proc.iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            text = stat_of(entry / "stat")
            before = read_stat(text)
            if before[0] in {"Z", "X"}:
                if read_threads(text) >= 2:
                    linger(found, entry, before[2], expected, read_threads(text))
                continue
            try:
                raw_env = (entry / "environ").read_bytes()
            except (FileNotFoundError, ProcessLookupError):
                raw_env = None
            if not raw_env:
                # The leader may be exiting: its address space (and so environ) goes before
                # it becomes a zombie. Other threads can still run the process.
                try:
                    text = stat_of(entry / "stat")
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if read_threads(text) < 2:
                    continue
                if read_stat(text)[2] != before[2]:
                    found.lingering.append({"pid": int(entry.name), "started": before[2], "threads": read_threads(text),
                                            "attribution": "ambiguous", "reason": "identity_changed"})
                else:
                    linger(found, entry, before[2], expected, read_threads(text))
                continue
            env = {}
            for item in raw_env.split(b"\0"):
                key, sep, value = item.partition(b"=")
                if sep and key in {b"WINEPREFIX", b"SteamGameId"}:
                    env[key] = os.fsdecode(value)
            if b"WINEPREFIX" not in env or os.path.realpath(env[b"WINEPREFIX"]) != expected:
                continue
            raw = (entry / "cmdline").read_bytes().split(b"\0", 1)[0]
            executable, native_program, executable_error, executable_id = executable_identity(entry, references)
            after = read_stat(stat_of(entry / "stat"))
            if after[2] != before[2] or after[0] in {"Z", "X"} or not raw:
                unreadable += 1
                continue
            process = Process(int(entry.name), after[2], after[1], after[0],
                              image_path(os.fsdecode(raw)), env.get(b"SteamGameId", ""),
                              executable, native_program, executable_error, executable_id)
            found[process.identity] = process
        except (FileNotFoundError, ProcessLookupError):
            # A process disappearing during observation is normal.
            continue
        except (OSError, ValueError, IndexError):
            unreadable += 1
    return found, unreadable


def linger(found, entry, started, expected, threads):
    attribution, reason = lingering_group(entry, started, expected)
    if attribution is not None:
        found.lingering.append({"pid": int(entry.name), "started": started, "threads": threads,
                                "attribution": attribution, "reason": reason})


class Tracker:
    def __init__(self, target, game_id, grace=5):
        self.target = target_path(target)
        self.directory = ntpath.dirname(self.target) if self.target else None
        self.game_id = game_id
        self.grace = grace
        self.previous = {}
        self.baseline = None
        self.seen_game = False
        self.seen_handoff = False
        self.gone_since = None
        self.last_decision = None
        self.tracked_game = set()
        self.native_origins = {}
        self.last_proxy_state = None
        self.known = set()
        # Identities this launch sent SIGTERM to: their own exit is expected, not a live game.
        self.signalled = set()

    def role(self, process):
        image = process.image
        if image == SOFTDENCHI_PROXY:
            return "softdenchi_proxy"
        if image == SOFTDENCHI_SERVICE:
            return "softdenchi_service"
        # The launcher's first image is not necessarily the game's lasting image.
        # Treat executable payloads in the launch directory as game-side evidence.
        if self.target and (image == self.target or (
                ntpath.dirname(image) == self.directory
                and ntpath.splitext(image)[1] in {".exe", ".log"})):
            return "game_image"
        if ntpath.basename(image) in INFRASTRUCTURE:
            return "infrastructure_name_only"
        if (ntpath.dirname(image) in SYSTEM_DIRECTORIES
                and ntpath.basename(image) in SYSTEM_HELPERS):
            return "infrastructure_name_only"
        return "unclassified"

    def update(self, processes, unreadable, now):
        events = []
        if self.baseline is None:
            self.baseline = set(processes)
        roles = {key: self.role(p) for key, p in processes.items()}
        # Propagate game lineage to other directories too. Never use an old PID
        # alone: inheritance is established while both parent and child are live.
        self.tracked_game.intersection_update(processes)
        for key, role in roles.items():
            if role == "game_image" and key not in self.baseline:
                self.tracked_game.add(key)
        changed = True
        while changed:
            changed = False
            parents = {processes[key].pid: processes[key] for key in self.tracked_game}
            for key, p in processes.items():
                if (p.parent in parents and parents[p.parent].started <= p.started
                        and key not in self.tracked_game
                        and key not in self.baseline
                        and roles[key] not in {"softdenchi_proxy", "softdenchi_service"}):
                    self.tracked_game.add(key)
                    changed = True
        for key in self.tracked_game:
            if roles[key] != "game_image":
                roles[key] = "game_descendant"
            p = processes[key]
            if (p.image != self.target and ntpath.splitdrive(p.image)[0]
                    and ntpath.splitext(p.image)[1] in {".exe", ".log"}):
                self.seen_handoff = True

        # A verified native binary is not sufficient: establish its origin while
        # its parent is visible. Game descendants continue to block game exit.
        self.native_origins = {
            key: origin for key, origin in self.native_origins.items()
            if key in processes and roles[key] == "unclassified"
            and processes[key].native_program == origin["native_program"]
            and processes[key].executable_id == origin["executable_id"]
        }
        for key in self.native_origins:
            roles[key] = "native_session_auxiliary"
        by_pid = {p.pid: p for p in processes.values()}
        changed = True
        while changed:
            changed = False
            for key, p in processes.items():
                if (roles[key] != "unclassified" or p.native_program not in NATIVE_AUXILIARIES
                        or not p.executable_id):
                    continue
                parent = by_pid.get(p.parent)
                if parent is None or parent.started > p.started:
                    continue
                parent_role = roles[parent.identity]
                windows_parent = (parent_role == "infrastructure_name_only"
                                  and ntpath.dirname(parent.image) in SYSTEM_DIRECTORIES)
                if not windows_parent and parent_role != "native_session_auxiliary":
                    continue
                anchor = ([parent.pid, parent.started] if windows_parent
                          else self.native_origins[parent.identity]["wine_anchor"])
                self.native_origins[key] = {
                    "proof": "proc_exe_samefile", "native_program": p.native_program,
                    "executable_id": p.executable_id,
                    "parent_identity": [parent.pid, parent.started], "parent_image": parent.image,
                    "wine_anchor": anchor,
                }
                roles[key] = "native_session_auxiliary"
                changed = True

        for key, p in processes.items():
            previous = self.previous.get(key)
            record = {**self.process_record(p, roles[key]),
                      "preexisting": key in self.baseline,
                      "game_id_match": bool(self.game_id) and p.game_id == self.game_id}
            if record != previous:
                events.append({"event": "process", **record})
        for key, record in self.previous.items():
            if key not in processes:
                events.append({"event": "no_longer_observed", "pid": record["pid"],
                               "started": record["started"], "role": record["role"]})

        game = [p for key, p in processes.items() if key in self.tracked_game]
        proxies = [p for key, p in processes.items() if roles[key] == "softdenchi_proxy"]
        proxy_state = frozenset((p.identity, p.executable_id, p.game_id) for p in proxies)
        if self.last_proxy_state is not None and proxy_state != self.last_proxy_state:
            self.gone_since = None
        self.last_proxy_state = proxy_state
        blockers = []
        if not self.target:
            blockers.append("unsupported_target_path")
        if unreadable:
            blockers.append("incomplete_proc_snapshot")
        if any(key in self.baseline and role == "game_image" for key, role in roles.items()):
            blockers.append("preexisting_game_image")
        if any(p.game_id and self.game_id and p.game_id != self.game_id for p in processes.values()):
            blockers.append("different_game_id_in_prefix")
        if any(role == "unclassified" for role in roles.values()):
            blockers.append("unclassified_prefix_process")
        if any(p.identity in self.baseline for p in proxies):
            blockers.append("preexisting_proxy")
        lingering = []
        for item in getattr(processes, "lingering", ()):
            identity = (item["pid"], item["started"])
            if identity in self.signalled:
                continue
            if identity in self.known:
                lingering.append({**item, "attribution": "observed"})
            elif item["attribution"] in {"prefix", "ambiguous"}:
                lingering.append(item)
        if lingering:
            blockers.append("zombie_leader_with_live_threads")
        self.known.update(processes)
        if game:
            self.seen_game = True
            self.gone_since = None
            phase = "game_processes_present"
        elif not self.seen_game:
            phase = "awaiting_game_observation"
        elif blockers:
            self.gone_since = None
            phase = "indeterminate"
        else:
            if self.gone_since is None:
                self.gone_since = now
            phase = "game_absence_grace"
            if now - self.gone_since >= self.grace:
                phase = "helpers_remaining_candidate" if proxies else "no_proxy_observed"
        decision = {"phase": phase, "blockers": sorted(blockers),
                    "proxy_candidates": [[p.pid, p.started] for p in sorted(proxies, key=lambda p: p.pid)],
                    "unclassified_processes": [self.process_record(p, roles[p.identity])
                                               for p in sorted(processes.values(), key=lambda p: p.pid)
                                               if roles[p.identity] == "unclassified"],
                    "game_processes": [self.process_record(p, roles[p.identity])
                                       for p in sorted(game, key=lambda p: p.pid)],
                    "proxy_processes": [self.process_record(p, "softdenchi_proxy")
                                        for p in sorted(proxies, key=lambda p: p.pid)],
                    "native_auxiliary_processes": [self.process_record(p, roles[p.identity])
                                                   for p in sorted(processes.values(), key=lambda p: p.pid)
                                                   if roles[p.identity] == "native_session_auxiliary"],
                    "session_exit_verified": False,
                    "game_handoff_observed": self.seen_handoff,
                    "unreadable_processes": unreadable, "cleanup_requires_revalidation": True}
        if lingering:
            decision["lingering_processes"] = sorted(lingering, key=lambda item: item["pid"])[:LINGERING_LIMIT]
        if decision != self.last_decision:
            events.append({"event": "decision", **decision})
        self.last_decision = decision
        self.previous = {
            key: {**self.process_record(p, roles[key]), "preexisting": key in self.baseline,
                  "game_id_match": bool(self.game_id) and p.game_id == self.game_id}
            for key, p in processes.items()
        }
        return events

    def process_record(self, process, role):
        return {"pid": process.pid, "started": process.started, "parent": process.parent,
                "image": process.image, "role": role, "executable": process.executable,
                "native_program": process.native_program, "executable_error": process.executable_error,
                "executable_id": process.executable_id,
                "native_origin": self.native_origins.get(process.identity)}


class ProxyCleanup:
    """One SIGTERM batch per launch; no PID-based fallback or auxiliary cleanup."""

    def __init__(self, prefix, tracker, emit, stopped, reader=None, launcher_pid=None, wineserver_path=None):
        self.prefix = prefix
        self.tracker = tracker
        self.emit = emit
        self.stopped = stopped
        self.reader = snapshot if reader is None else reader
        self.launcher_pid = os.getpid() if launcher_pid is None else launcher_pid
        self.wineserver_path = wineserver_path
        self.attempted = False
        self.unavailable = False
        self.last_rejection = None
        self.signalled = []
        self.sent_at = None
        self.reported = False
        self.game_origins = {}

    @staticmethod
    def fingerprint(process):
        return (process.identity, process.image, process.game_id, process.executable,
                process.executable_id, process.executable_error, process.native_program)

    def launcher(self, processes):
        found = [p for p in processes.values()
                 if ntpath.dirname(p.image) in SYSTEM_DIRECTORIES
                 and ntpath.basename(p.image) in {"steam.exe", "umu.exe"}
                 and p.parent == self.launcher_pid and p.game_id == self.tracker.game_id
                 and p.executable_id and p.executable and not p.executable_error and not p.native_program]
        return found[0] if len(found) == 1 else None

    @staticmethod
    def same_wine(process, launcher):
        return (process.game_id == launcher.game_id and process.executable_id == launcher.executable_id
                and process.executable == launcher.executable
                and not process.executable_error and not process.native_program)

    def observe_origins(self, processes, unreadable):
        """Remember only concurrently observed game ancestry under this Wine launcher."""
        launcher = self.launcher(processes)
        if launcher is None:
            self.game_origins.clear()
            return
        signature = self.fingerprint(launcher)
        self.game_origins = {
            key: proof for key, proof in self.game_origins.items()
            if key in processes and self.fingerprint(processes[key]) == proof["fingerprint"]
            and proof["launcher"] == signature
        }
        if unreadable or not self.tracker.game_id:
            return
        by_pid = {p.pid: p for p in processes.values()}
        games = {p.pid: p for p in processes.values()
                 if p.identity in self.tracker.tracked_game and p.identity not in self.tracker.baseline
                 and self.same_wine(p, launcher)}
        anchors = {}
        for game in games.values():
            cursor = game
            visited = set()
            while cursor.pid in games and cursor.identity not in visited:
                visited.add(cursor.identity)
                parent = by_pid.get(cursor.parent)
                if parent is None or parent.started > cursor.started:
                    break
                if parent.identity == launcher.identity:
                    anchors[game.pid] = game
                    break
                cursor = parent
        # New proof is acquired only while a verified game process is still live.
        if not anchors:
            return
        changed = True
        while changed:
            changed = False
            for p in processes.values():
                if (p.image != SOFTDENCHI_PROXY or p.identity in self.game_origins
                        or p.identity in self.tracker.baseline or not self.same_wine(p, launcher)):
                    continue
                parent = by_pid.get(p.parent)
                if parent is None or parent.started > p.started:
                    continue
                inherited = self.game_origins.get(parent.identity)
                if parent.pid in anchors:
                    anchor = anchors[parent.pid]
                    game_anchor = {"pid": anchor.pid, "started": anchor.started,
                                   "image": anchor.image, "executable_id": anchor.executable_id}
                elif inherited is not None:
                    game_anchor = inherited["game_anchor"]
                else:
                    continue
                proof = {"fingerprint": self.fingerprint(p), "launcher": signature,
                         "game_anchor": game_anchor, "parent_identity": list(parent.identity)}
                self.game_origins[p.identity] = proof
                self.emit({"event": "proxy_game_origin_observed", "pid": p.pid, "started": p.started,
                           "parent_identity": proof["parent_identity"], "game_anchor": game_anchor,
                           "executable_id": p.executable_id})
                changed = True

    def game_origin_confirmed(self, process, processes, launcher):
        by_pid = {p.pid: p for p in processes.values()}
        cursor = process
        visited = set()
        while cursor.image == SOFTDENCHI_PROXY:
            proof = self.game_origins.get(cursor.identity)
            if (cursor.identity in visited or proof is None
                    or proof["fingerprint"] != self.fingerprint(cursor)
                    or proof["launcher"] != self.fingerprint(launcher)):
                return False
            visited.add(cursor.identity)
            parent = by_pid.get(cursor.parent)
            if parent is None or parent.started > cursor.started:
                return False
            if parent.identity == launcher.identity:
                return True
            cursor = parent
        return False

    def reject(self, reason):
        if reason != self.last_rejection:
            self.emit({"event": "cleanup_skipped", "reason": reason})
            self.last_rejection = reason

    def readiness(self, continuing=False):
        if self.stopped():
            return "observer_stopping"
        decision = self.tracker.last_decision or {}
        allowed = {"helpers_remaining_candidate"}
        if continuing and self.signalled:
            # Removing a parent ourselves changes the candidate set and resets
            # the tracker grace. Finish only the already pinned, rechecked batch.
            allowed.add("game_absence_grace")
        if decision.get("phase") not in allowed or decision.get("blockers") or decision.get("game_processes"):
            return "candidate_conditions_changed"
        if not self.tracker.seen_handoff:
            return "game_handoff_not_observed"
        if not self.tracker.game_id:
            return "missing_game_id"
        return None

    def targets(self, processes):
        launcher = self.launcher(processes)
        if launcher is None:
            return {}, "launcher_identity_not_confirmed"
        for p in processes.values():
            if (self.tracker.role(p) != "infrastructure_name_only"
                    or ntpath.dirname(p.image) in SYSTEM_DIRECTORIES):
                continue
            if (ntpath.basename(p.image) != "wineserver" or p.parent != launcher.pid
                    or p.game_id != self.tracker.game_id or p.executable_error or not self.wineserver_path):
                return {}, "unverified_infrastructure_process"
            try:
                identity = Path(self.wineserver_path).stat()
            except OSError:
                return {}, "wineserver_reference_unavailable"
            if p.executable_id != f"{identity.st_dev}:{identity.st_ino}":
                return {}, "wineserver_identity_not_confirmed"
        by_pid = {p.pid: p for p in processes.values()}
        targets = {p.identity: p for p in processes.values() if p.image == SOFTDENCHI_PROXY}
        if not targets:
            return {}, "no_proxy_remaining"
        for p in targets.values():
            if (p.identity in self.tracker.baseline or p.game_id != self.tracker.game_id
                    or p.executable_id != launcher.executable_id or not p.executable
                    or p.executable_error or p.native_program):
                return {}, "proxy_identity_not_confirmed"
            if self.game_origin_confirmed(p, processes, launcher):
                continue
            cursor = p
            visited = set()
            while cursor.image == SOFTDENCHI_PROXY:
                if cursor.identity in visited:
                    return {}, "proxy_origin_not_confirmed"
                visited.add(cursor.identity)
                parent = by_pid.get(cursor.parent)
                if parent is None or parent.started > cursor.started:
                    return {}, "proxy_origin_not_confirmed"
                cursor = parent
            if (cursor.image != SOFTDENCHI_SERVICE or cursor.game_id != self.tracker.game_id
                    or cursor.executable_id != launcher.executable_id
                    or cursor.executable_error or cursor.native_program):
                return {}, "proxy_origin_not_confirmed"
            service_parent = by_pid.get(cursor.parent)
            if (service_parent is None or service_parent.started > cursor.started
                    or ntpath.dirname(service_parent.image) not in SYSTEM_DIRECTORIES
                    or ntpath.basename(service_parent.image) != "services.exe"
                    or service_parent.parent != launcher.pid
                    or service_parent.game_id != self.tracker.game_id
                    or service_parent.executable_id != launcher.executable_id):
                return {}, "service_origin_not_confirmed"
        return targets, None

    def attempt(self, processes, now):
        if self.attempted or self.unavailable:
            return
        reason = self.readiness()
        if reason:
            self.reject(reason)
            return
        targets, reason = self.targets(processes)
        if reason:
            self.reject(reason)
            return
        open_pidfd = getattr(os, "pidfd_open", None)
        send = getattr(signal, "pidfd_send_signal", None)
        if not callable(open_pidfd) or not callable(send):
            self.unavailable = True
            self.reject("pidfd_api_unavailable")
            return
        descriptors = {}
        try:
            # Pin every selected kernel process, then re-read /proc. PID reuse
            # after that read cannot redirect a pidfd to a replacement process.
            for key, p in targets.items():
                descriptors[key] = open_pidfd(p.pid, 0)
            for key, p in targets.items():
                fresh, unreadable = self.reader(self.prefix)
                for event in self.tracker.update(fresh, unreadable, time.monotonic()):
                    self.emit(event)
                self.observe_origins(fresh, unreadable)
                current = fresh.get(key)
                if current is None:
                    self.emit({"event": "cleanup_target_gone", "pid": p.pid, "started": p.started})
                    continue
                reason = self.readiness(continuing=True)
                active = {q.identity for q in fresh.values() if q.image == SOFTDENCHI_PROXY}
                if reason or not active.issubset(targets):
                    self.reject(reason or "new_proxy_appeared")
                    break
                if not self.signalled:
                    verified, reason = self.targets(fresh)
                    if reason or set(verified) != set(targets):
                        self.reject(reason or "proxy_batch_changed")
                        break
                if (current.image != p.image or current.executable_id != p.executable_id
                        or current.executable != p.executable or current.executable_error
                        or current.native_program or current.game_id != p.game_id):
                    self.reject("proxy_changed_before_signal")
                    break
                if self.stopped():
                    self.reject("observer_stopping")
                    break
                send(descriptors[key], signal.SIGTERM, None, 0)
                self.attempted = True
                self.sent_at = now
                self.signalled.append(key)
                self.tracker.signalled.add(key)
                self.emit({"event": "cleanup_sigterm_sent", "pid": p.pid, "started": p.started,
                           "executable_id": p.executable_id, "method": "pidfd",
                           "origin": "observed_game_ancestry" if key in self.game_origins else "service_or_pinned_batch"})
        except ProcessLookupError:
            self.reject("target_exited_during_cleanup")
        except (OSError, NotImplementedError) as exc:
            self.unavailable = True
            self.emit({"event": "cleanup_failed", "error_type": type(exc).__name__,
                       "errno": getattr(exc, "errno", errno.ENOSYS)})
        finally:
            for descriptor in descriptors.values():
                os.close(descriptor)

    def report(self, processes, now):
        if self.sent_at is None or self.reported or now - self.sent_at < 5:
            return
        self.reported = True
        self.emit({"event": "cleanup_followup", "remaining_signalled": [list(key) for key in self.signalled
                                                                        if key in processes],
                   "decision": self.tracker.last_decision})


class Observer:
    def __init__(self, env, target, output, mirror=None, wineserver_path=None):
        self.prefix = env["WINEPREFIX"]
        self.tracker = Tracker(target, env.get("SteamGameId", ""))
        self.output = output
        self.outputs = [output] if mirror is None or mirror is output else [output, mirror]
        self.stop_event = threading.Event()
        self.thread = None
        self.started = time.monotonic()
        self.launcher_returned_at = None
        # (processes, unreadable, wall, elapsed, kind), replaced as one value after each read.
        self.last_observation = None
        self.cleanup_enabled = env.get("PROTON_SOFTDENCHI_CLEANUP") == "1"
        self.cleaner = (ProxyCleanup(self.prefix, self.tracker, self.emit, self.stop_event.is_set,
                                    reader=lambda prefix: self.observe(prefix, "pre_send"),
                                    wineserver_path=wineserver_path)
                        if self.cleanup_enabled else None)

    def observe(self, prefix, kind):
        processes, unreadable = snapshot(prefix)
        self.last_observation = (processes, unreadable, time.time(), time.monotonic(), kind)
        return processes, unreadable

    def emit(self, event):
        event = {"schema": 5, "elapsed": round(time.monotonic() - self.started, 3),
                 "wall": round(time.time(), 3), **event}
        line = "softdenchi-observer " + json.dumps(event, ensure_ascii=True) + "\n"
        for output in self.outputs:
            try:
                output.write(line)
                output.flush()
            except (OSError, ValueError):
                # Still write the other destination if one log is unavailable.
                pass

    def poll(self):
        processes, unreadable = self.observe(self.prefix, "periodic")
        for event in self.tracker.update(processes, unreadable, time.monotonic()):
            self.emit(event)
        if self.cleaner is not None:
            self.cleaner.observe_origins(processes, unreadable)
            now = time.monotonic()
            if self.tracker.last_decision["phase"] == "helpers_remaining_candidate":
                self.cleaner.attempt(processes, now)
            self.cleaner.report(processes, now)

    def start(self):
        preflight = pidfd_preflight() if self.cleanup_enabled else {"available": False, "reason": "observe_only"}
        if self.cleaner is not None and not preflight["available"]:
            self.cleaner.unavailable = True
        self.emit({"event": "start", "observe_only": not self.cleanup_enabled, "poll_seconds": 1,
                   "cleanup_enabled": self.cleanup_enabled,
                   "cleanup_preflight": preflight,
                   "pidfd_available": callable(getattr(os, "pidfd_open", None))
                                      and callable(getattr(signal, "pidfd_send_signal", None)),
                   "grace_seconds": self.tracker.grace,
                   "native_reference_status": native_reference_status(),
                   "limits": ["sampled_proc_not_wine_system_flags", "authentication_state_unknown",
                              "prefix_membership_not_session_ownership",
                              "processes_without_readable_wineprefix_not_associated",
                              "argv0_not_verified_executable_image",
                              "native_auxiliary_lifetime_not_cleaned_up",
                              "unobserved_short_lived_processes_and_handoffs"]})
        if self.cleaner is not None and self.cleaner.unavailable:
            self.emit({"event": "cleanup_skipped", "reason": "pidfd_preflight_failed"})
        # Capture baseline before starting the game.
        self.poll()
        self.thread = threading.Thread(target=self.run, name="softdenchi-observer", daemon=True)
        self.thread.start()

    def run(self):
        try:
            heartbeat = time.monotonic()
            while not self.stop_event.wait(1):
                self.poll()
                if time.monotonic() - heartbeat >= 30:
                    self.emit({"event": "heartbeat", "decision": self.tracker.last_decision})
                    heartbeat = time.monotonic()
        except Exception as exc:  # noqa: BLE001 -- diagnostics must not affect game execution
            self.emit({"event": "observation_failed", "error_type": type(exc).__name__})

    def launcher_returned(self):
        """Called by Proton right after the Wine launcher returned a value (not on exceptions)."""
        self.launcher_returned_at = (time.time(), time.monotonic())

    def observation_summary(self):
        observation = self.last_observation
        if observation is None:
            return None
        processes, unreadable, wall, monotonic, kind = observation
        listed = sorted(processes.values(), key=lambda p: p.pid)
        # static_role is the image-only classification, not the lineage-aware role of decisions.
        return {"kind": kind, "wall": round(wall, 3), "elapsed": round(monotonic - self.started, 3),
                "unreadable_processes": unreadable, "omitted": max(0, len(listed) - LINGERING_LIMIT),
                "lingering_groups": len(getattr(processes, "lingering", ())),
                "processes": [{"pid": p.pid, "started": p.started, "image": p.image,
                               "static_role": self.tracker.role(p)} for p in listed[:LINGERING_LIMIT]]}

    def stop(self, returncode=None):
        returned = self.launcher_returned_at
        self.stop_event.set()
        timed_out = False
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=2)
            timed_out = self.thread.is_alive()
        try:
            summary = self.observation_summary()
        except Exception as exc:  # noqa: BLE001 -- diagnostics must not affect game execution
            summary = {"error_type": type(exc).__name__}
        self.emit({"event": "stop", "observe_only": not self.cleanup_enabled,
                   "launcher_returncode": returncode,
                   "launcher_returned_wall": None if returned is None else round(returned[0], 3),
                   "launcher_returned_elapsed": None if returned is None else round(returned[1] - self.started, 3),
                   "observer_join_timed_out": timed_out,
                   "last_observation": summary,
                   "cleanup_signalled": [list(key) for key in self.cleaner.signalled] if self.cleaner else []})
