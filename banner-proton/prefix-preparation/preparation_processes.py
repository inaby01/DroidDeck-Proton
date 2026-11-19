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


def _matches(raw, compatdata):
    require(not raw or raw.endswith(b"\0"), "truncated process environment")
    wanted = {b"STEAM_COMPAT_DATA_PATH": str(compatdata), b"WINEPREFIX": str(compatdata / "pfx")}
    selected = {}
    for part in raw.split(b"\0"):
        key, sep, value = part.partition(b"=")
        if sep and key in wanted:
            require(key not in selected, "duplicate process prefix field")
            selected[key] = os.fsdecode(value)
    return any(os.path.isabs(value) and os.path.realpath(value) == wanted[key] for key, value in selected.items())


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
WINE_INFRASTRUCTURE = frozenset(("services.exe", "winedevice.exe", "explorer.exe", "plugplay.exe", "svchost.exe",
                                 "rpcss.exe", "conhost.exe"))
MAX_ARGV0 = 4096


def windows_image(value):
    """Normalize argv[0] as a DOS image path (lower case, backslashes), without arguments."""
    value = value.replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\"):
        value = value.removeprefix(prefix)
    return ntpath.normpath(value).casefold()


def inventory_processes(compatdata, proc_root=Path("/proc")):
    """Same-owner processes of one prefix: identity, parent and argv[0] image only.

    No environment values, arguments, command lines or other prefixes are kept.
    Anything that cannot be read consistently is counted as unreadable.
    """
    compatdata, proc_root = safe_path(compatdata), safe_path(proc_root)
    processes, unreadable = [], 0
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
                    if before[0] in ("Z", "X") or not _matches(_read(descriptor, "environ", MAX_ENVIRON), compatdata):
                        continue
                    argv0 = _read(descriptor, "cmdline", MAX_ARGV0 * 4).split(b"\0", 1)[0]
                    after = _parent_identity(_read(descriptor, "stat", 8192), entry.name)
                    if after[2] != before[2] or after[0] in ("Z", "X") or not argv0 or len(argv0) > MAX_ARGV0:
                        unreadable += 1
                        continue
                    image = windows_image(os.fsdecode(argv0))
                    processes.append({"pid": int(entry.name), "started": after[2], "parent": after[1], "image": image})
                except FileNotFoundError:
                    continue
                except (OSError, ValueError, UnicodeError):
                    unreadable += 1
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    finally:
        os.close(root_fd)
    return {"scope": "same-proc-directory-owner-as-self", "processes": sorted(processes, key=lambda p: (p["pid"], p["started"])),
            "unreadable_count": unreadable, "device_namespace_verified": False}


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
    elif directory == r"c:\program files (x86)\softdenchi":
        place = "softdenchi-x86"
    else:
        place = "other"
    return {"name": name, "place": place}
