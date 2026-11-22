"""Read-only Linux proc observations, scoped to the proc directory owner of self.

Absence in this view is not proof about other UIDs/namespaces or Android/proot.
No signals are sent. Only prefix-related environment values are interpreted.
"""

import ntpath
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from preparation_common import require, safe_path

MAX_PROCESSES = 32768
MAX_ENVIRON = 1024 * 1024


def _read(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "invalid proc field")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "excessive proc field")
    return raw


def _identity(raw, pid):
    text = raw.decode("utf-8")
    require(text.startswith(str(pid) + " ("), "proc PID changed")
    _, sep, tail = text.rpartition(")")
    parts = tail.split()
    require(sep and len(parts) >= 20 and parts[19].isdecimal(), "invalid proc stat")
    return parts[0], int(parts[19])


def process_start_time(pid, proc_root=Path("/proc")):
    """Start time (clock ticks since boot, as in /proc/PID/stat) of one process, or an error."""
    root_fd = os.open(safe_path(proc_root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(str(int(pid)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            return _identity(_read(fd, "stat", 8192), str(int(pid)))[1]
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def process_parents(proc_root=Path("/proc")):
    """Same-owner processes: PID -> (parent PID, start time). Unreadable entries are left out."""
    proc_root = safe_path(proc_root)
    result = {}
    root_fd = os.open(proc_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        own_fd = os.open(str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            owner = os.fstat(own_fd).st_uid
        finally:
            os.close(own_fd)
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries):
                require(index < MAX_PROCESSES, "too many proc entries")
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                descriptor = None
                try:
                    descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                    if os.fstat(descriptor).st_uid == owner:
                        _, parent, started = _parent_identity(_read(descriptor, "stat", 8192), entry.name)
                        result[int(entry.name)] = (parent, started)
                except (OSError, ValueError, UnicodeError):
                    continue
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    finally:
        os.close(root_fd)
    return result


def descends_from(parents, key, root, limit=256):
    """True when the process ``key`` (pid, start) has ``root`` (pid, start) as an ancestor in ``parents``."""
    cursor, seen = key, set()
    for _ in range(limit):
        info = parents.get(cursor[0])
        if info is None or info[1] != cursor[1] or cursor[0] in seen:
            return False
        seen.add(cursor[0])
        parent = parents.get(info[0])
        if parent is None or parent[1] > cursor[1]:
            return False
        if (info[0], parent[1]) == tuple(root):
            return True
        cursor = (info[0], parent[1])
    return False


def _matches(raw, compatdata):
    return _prefix_fields(raw, compatdata)[0]


def _prefix_fields(raw, compatdata):
    """(any field matches, every present field matches) for STEAM_COMPAT_DATA_PATH and WINEPREFIX."""
    require(not raw or raw.endswith(b"\0"), "truncated process environment")
    wanted = {b"STEAM_COMPAT_DATA_PATH": str(compatdata), b"WINEPREFIX": str(compatdata / "pfx")}
    selected = {}
    for part in raw.split(b"\0"):
        key, sep, value = part.partition(b"=")
        if sep and key in wanted:
            require(key not in selected, "duplicate process prefix field")
            selected[key] = os.fsdecode(value)
    results = [os.path.isabs(value) and os.path.realpath(value) == wanted[key] for key, value in selected.items()]
    return any(results), bool(results) and all(results)


def observe_processes(compatdata, proc_root=Path("/proc")):
    compatdata, proc_root = safe_path(compatdata), safe_path(proc_root)
    active, unknown, inspected = 0, 0, 0
    failures = {}

    def failed(stage):
        failures[stage] = failures.get(stage, 0) + 1
    root_fd = os.open(proc_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        own_fd = os.open(str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            owner = os.fstat(own_fd).st_uid
        finally:
            os.close(own_fd)
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries):
                require(index < MAX_PROCESSES, "too many proc entries")
                if not entry.name.isascii() or not entry.name.isdecimal() or int(entry.name) == os.getpid():
                    continue
                descriptor = None
                stage = "open-pid"
                try:
                    descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                    stage = "pid-owner"
                    if os.fstat(descriptor).st_uid != owner:
                        continue
                    inspected += 1
                    stage = "stat-before"
                    before = _identity(_read(descriptor, "stat", 8192), entry.name)
                    if before[0] in ("Z", "X"):
                        continue
                    stage = "prefix-environment"
                    matches = _matches(_read(descriptor, "environ", MAX_ENVIRON), compatdata)
                    stage = "stat-after"
                    after = _identity(_read(descriptor, "stat", 8192), entry.name)
                    stage = "identity-recheck"
                    require(before[1] == after[1], "proc identity changed")
                    if after[0] not in ("Z", "X") and matches:
                        active += 1
                except FileNotFoundError:
                    # Missing fields on a still-present PID are not proof of exit.
                    try:
                        os.stat(entry.name, dir_fd=root_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    unknown += 1
                    failed(stage)
                except (OSError, ValueError, UnicodeError):
                    unknown += 1
                    failed(stage)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    finally:
        os.close(root_fd)
    return {"scope": "same-proc-directory-owner-as-self", "active_count": active, "unknown_count": unknown,
            "inspected_count": inspected, "clear_in_view": active == 0 and unknown == 0,
            "device_namespace_verified": False, "failure_stages": failures}


def _under(path, root):
    """Path-component containment of a resolved path (``...beta1`` is not under ``...beta10``)."""
    return path == root or path.startswith(root.rstrip("/") + "/")


def observe_slot_users(slot_root, proc_root=Path("/proc")):
    """Own-uid processes that use a preparation slot (design: Proton update 4.7).

    A process uses the slot when its executable, its working directory or a path argument
    (relative ones resolved from its working directory) resolves inside the slot. ``proton``
    is a Python script started by ``env python3``, so its executable is outside the slot and
    only the argument shows it. Processes of other owners are not counted (as in the prefix
    observation); a process of the same owner that cannot be read is ``unknown``. Arguments
    are never returned, only counts.
    """
    root = os.path.realpath(safe_path(slot_root))
    proc_root = safe_path(proc_root)
    users, unknown, inspected = 0, 0, 0
    root_fd = os.open(proc_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        own_fd = os.open(str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            owner = os.fstat(own_fd).st_uid
        finally:
            os.close(own_fd)
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries):
                require(index < MAX_PROCESSES, "too many proc entries")
                if not entry.name.isascii() or not entry.name.isdecimal() or int(entry.name) == os.getpid():
                    continue
                descriptor = None
                try:
                    descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                    if os.fstat(descriptor).st_uid != owner:
                        continue
                    inspected += 1
                    if _identity(_read(descriptor, "stat", 8192), entry.name)[0] in ("Z", "X"):
                        continue
                    cwd = os.readlink("cwd", dir_fd=descriptor)
                    exe = os.readlink("exe", dir_fd=descriptor)
                    argv = [os.fsdecode(item) for item in _read(descriptor, "cmdline", MAX_ENVIRON).split(b"\0") if item]
                    paths = [exe, cwd] + [arg if arg.startswith("/") else os.path.join(cwd, arg)
                                          for arg in argv if "/" in arg]
                    if any(_under(os.path.realpath(path), root) for path in paths):
                        users += 1
                except FileNotFoundError:
                    try:
                        os.stat(entry.name, dir_fd=root_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    unknown += 1
                except (OSError, ValueError, UnicodeError):
                    unknown += 1
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    finally:
        os.close(root_fd)
    return {"scope": "same-proc-directory-owner-as-self", "users": users, "unknown": unknown, "inspected": inspected,
            "clear": users == 0 and unknown == 0}


@dataclass(frozen=True)
class ProcessStopCheck:
    compatdata: object = field(repr=False)
    proc_root: object = field(default=Path("/proc"), repr=False)

    def check(self):
        # Two observations reduce races; they do not serialize outside launchers.
        first = observe_processes(self.compatdata, self.proc_root)
        second = observe_processes(self.compatdata, self.proc_root)
        return {"clear_in_view": first["clear_in_view"] and second["clear_in_view"],
                "active_count": max(first["active_count"], second["active_count"]),
                "unknown_count": max(first["unknown_count"], second["unknown_count"]),
                "scope": first["scope"], "device_namespace_verified": False, "observations": 2,
                "inspected_count": max(first["inspected_count"], second["inspected_count"]),
                "failure_stages": {stage: max(first["failure_stages"].get(stage, 0), second["failure_stages"].get(stage, 0))
                                   for stage in first["failure_stages"].keys() | second["failure_stages"].keys()}}


SYSTEM_DIRECTORIES = frozenset((r"c:\windows\system32", r"c:\windows\syswow64"))
# lsass.exe (service dispatcher) and tabtip.exe are made Wine system processes; only their system-directory images count.
WINE_INFRASTRUCTURE = frozenset(("services.exe", "winedevice.exe", "explorer.exe", "plugplay.exe", "svchost.exe",
                                 "rpcss.exe", "conhost.exe", "lsass.exe", "tabtip.exe"))
# Proton's UI automation helper, started by explorer.exe from the tool's files/share/xalia.
XALIA_IMAGE_SUFFIX = r"\files\share\xalia\xalia.exe"


def xalia_images(tool):
    """DOS image forms of the selected compatibility tool's xalia.exe (as given and resolved)."""
    path = Path(tool) / "files/share/xalia/xalia.exe"
    unix = {str(path), os.path.realpath(path)}
    return frozenset(windows_image(prefix + name) for name in unix for prefix in ("z:", "\\\\?\\unix", "\\??\\unix"))


MAX_ARGV0 = 4096
MAX_UNREADABLE_PIDS = 16


def windows_image(value):
    """Normalize argv[0] as a DOS image path (lower case, backslashes), without arguments."""
    value = value.replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\"):
        value = value.removeprefix(prefix)
    return ntpath.normpath(value).casefold()


def inventory_processes(compatdata, proc_root=Path("/proc")):
    """Same-owner processes of one prefix: identity, parent and argv[0] image only.

    No environment values, arguments, command lines or other prefixes are kept.
    Anything that cannot be read consistently is counted as unreadable; the first
    ``MAX_UNREADABLE_PIDS`` of their PIDs are kept for diagnosis.
    """
    compatdata, proc_root = safe_path(compatdata), safe_path(proc_root)
    processes, unreadable, unreadable_pids = [], 0, []
    root_fd = os.open(proc_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        own_fd = os.open(str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            owner = os.fstat(own_fd).st_uid
        finally:
            os.close(own_fd)
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries):
                require(index < MAX_PROCESSES, "too many proc entries")
                if not entry.name.isascii() or not entry.name.isdecimal() or int(entry.name) == os.getpid():
                    continue
                descriptor = None
                try:
                    descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                    if os.fstat(descriptor).st_uid != owner:
                        continue
                    before = _parent_identity(_read(descriptor, "stat", 8192), entry.name)
                    if before[0] in ("Z", "X"):
                        continue
                    any_match, consistent = _prefix_fields(_read(descriptor, "environ", MAX_ENVIRON), compatdata)
                    if not any_match:
                        continue
                    try:
                        exe = os.stat("exe", dir_fd=descriptor)
                        executable_id = f"{exe.st_dev}:{exe.st_ino}"
                    except OSError:
                        executable_id = None
                    argv0 = _read(descriptor, "cmdline", MAX_ARGV0 * 4).split(b"\0", 1)[0]
                    after = _parent_identity(_read(descriptor, "stat", 8192), entry.name)
                    if after[2] != before[2] or after[0] in ("Z", "X") or not argv0 or len(argv0) > MAX_ARGV0:
                        unreadable += 1
                        unreadable_pids.append(int(entry.name))
                        continue
                    image = windows_image(os.fsdecode(argv0))
                    processes.append({"pid": int(entry.name), "started": after[2], "parent": after[1], "image": image,
                                      "prefix_consistent": consistent, "executable_id": executable_id})
                except FileNotFoundError:
                    continue
                except (OSError, ValueError, UnicodeError):
                    unreadable += 1
                    unreadable_pids.append(int(entry.name))
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    finally:
        os.close(root_fd)
    return {"scope": "same-proc-directory-owner-as-self", "processes": sorted(processes, key=lambda p: (p["pid"], p["started"])),
            "unreadable_count": unreadable, "unreadable_pids": sorted(unreadable_pids)[:MAX_UNREADABLE_PIDS],
            "device_namespace_verified": False}


def _parent_identity(raw, pid):
    text = raw.decode("utf-8")
    require(text.startswith(str(pid) + " ("), "proc PID changed")
    _, sep, tail = text.rpartition(")")
    parts = tail.split()
    require(sep and len(parts) >= 20 and parts[1].isdecimal() and parts[19].isdecimal(), "invalid proc stat")
    return parts[0], int(parts[1]), int(parts[19])


def describe_image(image):
    """Exportable classification: basename plus a coarse directory class, never other paths."""
    directory, name = ntpath.split(image)
    if image.startswith("\\") and not image.startswith("\\\\"):
        place = "native"
    elif directory in SYSTEM_DIRECTORIES:
        place = "windows-system"
    elif image.endswith(XALIA_IMAGE_SUFFIX):
        # Report-only place; classification requires the selected tool's exact path.
        place = "proton-share-xalia"
    elif directory == r"c:\program files (x86)\softdenchi":
        place = "softdenchi-x86"
    else:
        place = "other"
    return {"name": name, "place": place}
