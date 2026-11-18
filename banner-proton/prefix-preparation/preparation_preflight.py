"""Explicit temporary capability probes, not prefix readiness or preparation.

Read-only by default. Opt-in probes create only a new private directory, launch
our fixed native Python children and open/close an X11 display without a window.
No Wine, installers, helpers, settings or existing prefix contents are changed.
"""

import argparse
import errno
import hashlib
import json
import os
import re
import secrets
import select
import stat
import subprocess
import sys
from pathlib import Path

from preparation_common import VERSION, read_bytes, require, safe_path
from preparation_processes import ProcessStopCheck, _identity, _matches, _read
from preparation_publication import _publish, _rename_function
from preparation_runtime import inspect_runtime

CHILD = '''import select, signal, sys
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
signal.alarm(20)
sys.stdout.buffer.write(b"R"); sys.stdout.buffer.flush()
select.select([sys.stdin], [], [], 15)
'''
GUI_CHILD = '''import ctypes, signal
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
signal.alarm(3)
try:
    lib = ctypes.CDLL("libX11.so.6")
except OSError:
    raise SystemExit(3)
lib.XOpenDisplay.argtypes = [ctypes.c_char_p]
lib.XOpenDisplay.restype = ctypes.c_void_p
lib.XCloseDisplay.argtypes = [ctypes.c_void_p]
lib.XCloseDisplay.restype = ctypes.c_int
handle = lib.XOpenDisplay(None)
if not handle:
    raise SystemExit(2)
lib.XCloseDisplay(handle)
signal.alarm(0)
'''


def _error(error, stage):
    return {"status": "unavailable", "stage": stage, "error_class": type(error).__name__, "errno": getattr(error, "errno", None)}


def _directory(path):
    path = safe_path(path)
    parent = path
    while not parent.exists():
        parent = parent.parent
    require(parent.is_dir(), "existing ancestor is not a directory")
    info = parent.stat()
    fs = os.statvfs(parent)
    return {"path": str(path), "exists": path.exists(), "existing_ancestor": str(parent),
            "ancestor_owned_by_self": info.st_uid == os.getuid(), "ancestor_mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "available_bytes": fs.f_bavail * (fs.f_frsize or fs.f_bsize), "write_permission": "unverified"}


def _proc_observation(marker):
    try:
        return ProcessStopCheck(marker).check()
    except (OSError, ValueError) as error:
        return {**_error(error, "process-scan"), "clear_in_view": False, "device_namespace_verified": False}


def _child_fields(child, marker):
    fd = None
    try:
        fd = os.open("/proc/" + str(child.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        owner = os.fstat(fd).st_uid
        stage = "child-stat-before"
        before = _identity(_read(fd, "stat", 8192), str(child.pid))
        stage = "child-environ"
        matches = _matches(_read(fd, "environ", 1024**2), marker)
        stage = "child-stat-after"
        after = _identity(_read(fd, "stat", 8192), str(child.pid))
        own_fd = os.open("/proc/" + str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            same_owner = owner == os.fstat(own_fd).st_uid
        finally:
            os.close(own_fd)
        return {"status": "read", "same_proc_owner_as_self": same_owner,
                "marker_matched": matches, "stable_identity": before[1] == after[1],
                "alive": before[0] not in ("Z", "X") and after[0] not in ("Z", "X")}
    except (OSError, ValueError, UnicodeError) as error:
        return _error(error, locals().get("stage", "child-directory"))
    finally:
        if fd is not None:
            os.close(fd)


def _process_probe(marker):
    result = {"status": "unavailable", "before": _proc_observation(marker), "device_namespace_verified": False}
    child = None
    try:
        env = {"PATH": "/usr/bin:/bin", "WINEPREFIX": str(marker / "pfx"), "STEAM_COMPAT_DATA_PATH": str(marker)}
        child = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "-c", CHILD], env=env,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        readable, _, _ = select.select([child.stdout], [], [], 3)
        require(readable and child.stdout.read(1) == b"R", "native probe child did not become ready")
        result["child_fields"] = _child_fields(child, marker)
        result["during"] = _proc_observation(marker)
    except (OSError, ValueError) as error:
        result["failure"] = _error(error, "native-child-probe")
    finally:
        if child is not None:
            try:
                child.communicate(b"x", timeout=4)
                result["child_exited"] = child.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                result["child_exited"] = False
            for stream in (child.stdin, child.stdout):
                if stream is not None:
                    stream.close()
        result["after"] = _proc_observation(marker)
    direct = result.get("child_fields", {})
    if (result.get("child_exited") is True and direct.get("status") == "read" and
        all(direct.get(key) is True for key in ("same_proc_owner_as_self", "marker_matched", "stable_identity", "alive")) and
        result["before"].get("clear_in_view") is True and result["after"].get("clear_in_view") is True and
        result.get("during", {}).get("active_count", 0) >= 1 and result["during"].get("unknown_count") == 0):
        result["status"] = "native-child-observed-and-cleared"
    return result


def _gui_probe(environment):
    result = {"status": "unset-or-unsupported-local-display", "window_created": False, "wine_gui_verified": False,
              "credentials_recorded": False}
    if not re.fullmatch(r":[0-9]{1,5}(?:\.[0-9]{1,3})?", environment.get("DISPLAY", "")):
        return result
    selected = {key: environment[key] for key in ("DISPLAY", "HOME", "XAUTHORITY", "XDG_RUNTIME_DIR", "LANG", "LC_ALL")
                if environment.get(key)}
    require(all(type(value) is str and len(value.encode()) <= 4096 and not any(c in value for c in "\0\r\n")
                for value in selected.values()), "invalid GUI environment")
    if selected.get("HOME"):
        safe_path(selected["HOME"])
    authority = selected.get("XAUTHORITY") or (str(Path(selected["HOME"]) / ".Xauthority") if selected.get("HOME") else None)
    if authority:
        safe_path(authority)  # Validate only; cookie contents are handled privately by system Xlib.
    child = None
    try:
        child = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "-c", GUI_CHILD], env=selected,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.wait(timeout=5)
        result["status"] = {0: "x11-display-opened-and-closed", 2: "x11-display-open-failed", 3: "system-xlib-unavailable"}.get(
            child.returncode, "gui-probe-failed-or-deadline")
    except (OSError, subprocess.TimeoutExpired) as error:
        result.update(_error(error, "gui-probe"))
    return result


def _inode(fd, name):
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode), "probe object changed type")
    return info.st_dev, info.st_ino


def _rename_probe(fd, guard, objects):
    rename = _rename_function()
    guard()
    os.mkdir("tree", 0o700, dir_fd=fd)
    os.mkdir("collision", 0o700, dir_fd=fd)
    identities = {name: _inode(fd, name) for name in ("tree", "collision")}
    objects.update(identities)
    try:
        _publish(rename, fd, fd, "collision")
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
    else:
        raise ValueError("empty-directory collision was replaced")
    require(all(_inode(fd, name) == value for name, value in identities.items()), "collision objects changed")
    guard()
    _publish(rename, fd, fd, "published")
    objects["published"] = objects.pop("tree")
    require(_inode(fd, "published") == identities["tree"], "published inode changed")
    os.fsync(fd)
    return {"status": "non-replacing-rename-supported", "empty_collision_preserved": True,
            "fresh_destination_published": True}


def _temporary_probes(parent, environment):
    parent = safe_path(parent)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    name = ".droiddeck-preflight-" + secrets.token_hex(16)
    result = {"temporary_path": str(parent / name), "cleanup": "not-created"}
    try:
        info = os.fstat(parent_fd)
        parent_identity = info.st_dev, info.st_ino
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "unsafe probe parent")
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        result["cleanup"] = "retained-needs-inspection"
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        os.fchmod(fd, 0o700)
        identity = _inode(parent_fd, name)
        def guard():
            current = safe_path(parent).stat()
            require((current.st_dev, current.st_ino) == parent_identity and _inode(parent_fd, name) == identity,
                    "probe parent or private directory changed")
        try:
            objects = {}
            result["rename"] = _rename_probe(fd, guard, objects)
        except (OSError, ValueError) as error:
            result["rename"] = _error(error, "non-replacing-rename")
        result["process"] = _process_probe(parent / name / "marker-compatdata")
        try:
            result["gui"] = _gui_probe(environment)
        except (OSError, ValueError) as error:
            result["gui"] = _error(error, "gui-input")
        guard()
        # Only our fixed empty probe objects may be removed. Unexpected contents
        # are retained, including when a probe failed after creating an object.
        with os.scandir(fd) as children:
            names = [entry.name for entry in children]
        require(set(names) == objects.keys(), "unexpected probe contents")
        for item in names:
            require(_inode(fd, item) == objects[item], "probe object identity changed")
            require(stat.S_IMODE(os.stat(item, dir_fd=fd, follow_symlinks=False).st_mode) == 0o700,
                    "probe permissions changed")
            os.rmdir(item, dir_fd=fd)
        guard()
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        result["cleanup"] = "removed-own-empty-probe-directory"
    except (OSError, ValueError) as error:
        result["failure"] = _error(error, "temporary-probes-or-cleanup")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)
    return result


def inspect_preflight(steam, settings, probe_temporary=False, environment=None):
    require(type(probe_temporary) is bool, "explicit boolean probe option required")
    env = os.environ if environment is None else environment
    steam, settings = safe_path(steam), safe_path(settings)
    require(steam != settings and not steam.is_relative_to(settings) and not settings.is_relative_to(steam), "overlapping roots")
    runtime = inspect_runtime(Path("/"), env)
    paths = {"steam": _directory(steam), "settings": _directory(settings),
             "tools": _directory(steam / "compatibilitytools.d"), "compatdata": _directory(steam / "steamapps/compatdata")}
    result = {"schema_version": 1, "tool_version": VERSION, "mode": "inspect-preflight", "runtime": runtime,
              "paths": paths, "registration_export": "not-acquired", "added_games_environment_present": bool(env.get("BL_ADDED_GAMES")),
              "prefix_contents_read": False, "settings_contents_read": False, "preparation_complete": False,
              "blockers": ["registration-freshness-unverified", "device-process-stop-scope-unverified",
                           "wine-runtime-unverified", "dependencies-and-prefix-capacity-unverified", "execution-not-exposed"], "writes": []}
    if not probe_temporary:
        result["probes"] = {"status": "not-requested"}
        return result
    if sys.platform != "linux" or not steam.is_dir():
        result["probes"] = {"status": "requires-linux-and-existing-steam-root"}
        return result
    parent = steam / "compatibilitytools.d" if (steam / "compatibilitytools.d").exists() else steam
    probes = _temporary_probes(parent, env)
    result["probes"] = probes
    result["probe_filesystem_scope"] = "existing-tool-parent" if parent != steam else "steam-root-tools-parent-absent"
    if probes["cleanup"] != "not-created":
        result["writes"] = [{"path": probes["temporary_path"], "scope": "new-private-temporary-probes-only", "cleanup": probes["cleanup"]}]
    return result


def preflight_main(argv=None):
    parser = argparse.ArgumentParser(description="Runtime preflight; optional private temporary/native/GUI probes, no prefix changes.")
    parser.add_argument("--probe-temporary", action="store_true")
    parser.add_argument("--steam-root", type=Path, default=Path.home() / ".local/share/Steam")
    parser.add_argument("--settings-root", type=Path, default=Path.home() / ".local/share/droiddeck-compat")
    args = parser.parse_args(argv)
    try:
        report = inspect_preflight(args.steam_root, args.settings_root, args.probe_temporary)
    except (OSError, ValueError, TypeError) as error:
        report = {"mode": "inspect-preflight", "tool_version": VERSION, **_error(error, "preflight-input"), "preparation_complete": False}
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 2  # A preflight never establishes complete preparation readiness.


def preflight_script():
    parent = Path(__file__).resolve().parent
    sources = {name: read_bytes(parent / (name + ".py")).decode("utf-8") for name in
               ("preparation_common", "preparation_runtime", "preparation_processes", "preparation_publication", "preparation_preflight")}
    code = ("import sys, types\n" + "sources = " + repr(sources) + "\n" +
            "for name, source in sources.items():\n"
            "    module = types.ModuleType(name)\n"
            "    sys.modules[name] = module\n"
            "    exec(compile(source, name, 'exec'), module.__dict__)\n"
            "raise SystemExit(sys.modules['preparation_preflight'].preflight_main())\n")
    compile(code, "preflight-script", "exec")
    delimiter = "DROIDDECK_PREFLIGHT_" + hashlib.sha256(code.encode()).hexdigest()[:16]
    require(delimiter not in code.splitlines(), "invalid preflight delimiter")
    return ('#!/bin/bash\n# Standalone preflight; pass --probe-temporary to opt into private probes.\n'
            'DROIDDECK_AUDIT_SHELL_UMASK=$(umask) /usr/bin/python3 -I -B - "$@" <<\'' + delimiter + "'\n" + code + delimiter + "\n")
