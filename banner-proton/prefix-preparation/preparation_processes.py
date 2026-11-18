"""Read-only Linux proc observations, scoped to the proc directory owner of self.

Absence in this view is not proof about other UIDs/namespaces or Android/proot.
No signals are sent. Only prefix-related environment values are interpreted.
"""

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
                    before = _identity(_read(descriptor, "stat", 8192), entry.name)
                    if before[0] in ("Z", "X"):
                        continue
                    matches = _matches(_read(descriptor, "environ", MAX_ENVIRON), compatdata)
                    after = _identity(_read(descriptor, "stat", 8192), entry.name)
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
                except (OSError, ValueError, UnicodeError):
                    unknown += 1
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    finally:
        os.close(root_fd)
    return {"scope": "same-proc-directory-owner-as-self", "active_count": active, "unknown_count": unknown,
            "inspected_count": inspected, "clear_in_view": active == 0 and unknown == 0,
            "device_namespace_verified": False}


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
                "scope": first["scope"], "device_namespace_verified": False}
