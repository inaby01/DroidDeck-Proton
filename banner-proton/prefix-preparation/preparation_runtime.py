"""Read-only runtime inventory. No connection, helper import or launch occurs."""

import hashlib
import os
import platform
import re
import stat
from pathlib import Path

from preparation_common import (
    Invalid,
    read_bytes,
    regular_open,
    require,
    safe_path,
    unchanged,
)

SOURCES = {
    "usr/local/bin/steam-compatibility": "9728f4c8c6646335e3f28297e3cae0ea4f8c44c7da83c02a0c2cd46b682bf61e",
    "usr/local/bin/droiddeck-proton-run": "c0582db64d71eb7257e7940b36ccbda76c5279bc1fa414b0c15f6f2a9919bff7",
    "usr/local/bin/droiddeck-game-env": "e6b6dc3fdacc07cfdc65b3b7d041365e5a71ec14eaf7f7c6b84fee717801c044",
}
LIBRARIES = ("usr/local/lib/libfakeinput.so", "usr/local/lib/libblsession.so", "usr/local/lib/libblaudit.so")
ENV_NAMES = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PULSE_SERVER", "PROOT_FP_KEY", "LD_PRELOAD", "LD_AUDIT")


def _socket(root, relative):
    try:
        path = safe_path(root / relative, root)
        return "present-unconnected" if stat.S_ISSOCK(path.lstat().st_mode) else "not-a-socket"
    except FileNotFoundError:
        return "missing"
    except (OSError, ValueError):
        return "unreadable-or-linked"


def inspect_runtime(root, environment=None):
    root = safe_path(root)
    require(root.is_dir(), "runtime root absent")
    env = os.environ if environment is None else environment
    source_results = {}
    for name, expected in SOURCES.items():
        try:
            raw = read_bytes(root / name)
            measured = hashlib.sha256(raw).hexdigest()
            source_results[name] = {"status": "matched" if measured == expected else "different", "sha256": measured,
                                    "executable": os.access(root / name, os.X_OK)}
        except FileNotFoundError:
            source_results[name] = {"status": "missing"}
        except (OSError, ValueError):
            source_results[name] = {"status": "unreadable-or-linked"}
    libraries = {}
    for name in LIBRARIES:
        try:
            with regular_open(root / name, 32*1024*1024) as stream:
                before = os.fstat(stream.fileno())
                header = stream.read(20)
                stream.seek(0)
                digest, total = hashlib.sha256(), 0
                while chunk := stream.read(1024*1024):
                    total += len(chunk)
                    require(total <= before.st_size, "runtime library grew")
                    digest.update(chunk)
                unchanged(before, os.fstat(stream.fileno()))
                require(total == before.st_size, "runtime library truncated")
                arm64 = len(header) == 20 and header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20],"little") == 183
                libraries[name] = {"status": "measured", "sha256": digest.hexdigest(), "elf_arm64": arm64,
                                   "basis": "local-measurement"}
        except FileNotFoundError:
            libraries[name] = {"status": "missing"}
        except (OSError, ValueError):
            libraries[name] = {"status": "unreadable-or-linked"}
    release = {}
    try:
        release_path = root / "etc/os-release"
        if release_path.is_symlink():
            require(os.readlink(release_path) in ("../usr/lib/os-release","/usr/lib/os-release"), "unknown OS metadata link")
            release_path = root / "usr/lib/os-release"
        for line in read_bytes(release_path,8192).decode("utf-8").splitlines():
            key,sep,value = line.partition("=")
            if sep and key in ("ID","VERSION_ID"):
                release[key] = value.strip('"')
    except (OSError, ValueError):
        pass
    label = {"status": "missing", "sha256": None}
    try:
        raw = read_bytes(root / "etc/steam-compatibility-label",4096)
        label = {"status": "measured", "sha256": hashlib.sha256(raw).hexdigest()}
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        label = {"status": "unreadable-or-linked", "sha256": None}
    process_basis = inspect_process_basis(root / "proc", env) if root == Path("/") else {
        "self_proc_readable":False,"proc_uid_matches_getuid":None,"proc_owner_matches_getuid":None,
        "umask":None,"device_namespace_verified":False,"status":"root-snapshot-not-live"}
    display = env.get("DISPLAY","")
    match = re.fullmatch(r":([0-9]{1,5})(?:\.[0-9]{1,3})?",display)
    display_socket = _socket(root,"tmp/.X11-unix/X"+match[1]) if match else "unset-or-unsupported-format"
    sources_match = all(result["status"] == "matched" and result["executable"] for result in source_results.values())
    blockers = ["runtime-execution-unverified", "android-proot-process-scope-unverified", "gui-and-audio-connections-unverified"]
    if not sources_match:
        blockers.append("runtime-source-missing-or-different")
    if release != {"ID":"ubuntu","VERSION_ID":"26.04"}:
        blockers.append("runtime-os-unconfirmed")
    return {"mode":"inspect-runtime", "view":"current-root" if root == Path("/") else "root-snapshot",
            "auditor_python":platform.python_version(), "auditor_architecture":platform.machine(), "os_release":release,
            "runtime_sources":source_results,"sources_match_pinned_version":sources_match,"libraries":libraries,
            "label":label,"process_observation_basis":process_basis,"environment_presence":{name:bool(env.get(name)) for name in ENV_NAMES},
            "display_socket":display_socket,"connections_attempted":False,"helpers_executed":False,
            "blockers":blockers,"preparation_complete":False,"writes":[]}


def _probe_error(error, stage):
    result = {"status":"failed","stage":stage,"error_type":type(error).__name__}
    if isinstance(error, OSError):
        result["errno"] = error.errno
    elif isinstance(error, Invalid):
        # Invalid from the shared reader contains fixed validation messages only.
        result["validation"] = str(error)
    return result


def _status_projection(raw):
    values = {"uid_matches_getuid":None,"umask":None}
    for line in raw.decode("utf-8").splitlines():
        key,sep,value = line.partition(":")
        if sep and key == "Umask" and re.fullmatch(r"[0-7]{4}",value.strip()):
            values["umask"] = value.strip()
        elif sep and key == "Uid" and value.split() and value.split()[0].isdecimal():
            values["uid_matches_getuid"] = int(value.split()[0]) == os.getuid()
    return values


def _status_via_directory_fd(proc, name):
    stage, parent, directory = "open-proc-root", None, None
    try:
        safe_path(proc)
        parent = os.open(proc,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        stage = "open-pid-directory"
        require(name.isascii() and name.isdecimal(), "non-numeric proc target")
        directory = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        owner_matches = os.fstat(directory).st_uid == os.getuid()
        stage = "open-status-no-follow"
        fd = os.open("status",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        with os.fdopen(fd,"rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode), "non-regular proc status")
            stage = "bounded-status-read"
            raw = stream.read(65537)
            require(len(raw) <= 65536, "proc status too large")
        stage = "parse-selected-status-fields"
        return {"status":"read","owner_matches_getuid":owner_matches,"link_count":info.st_nlink,
                **_status_projection(raw)}
    except (OSError,ValueError) as error:
        return _probe_error(error,stage)
    finally:
        if directory is not None:
            os.close(directory)
        if parent is not None:
            os.close(parent)


def inspect_process_basis(proc, environment):
    result = {"self_proc_readable":False,"proc_uid_matches_getuid":None,"proc_owner_matches_getuid":None,
              "umask":None,"device_namespace_verified":False}
    pid = str(os.getpid())
    stage = "shared-reader"
    try:
        raw = read_bytes(proc / pid / "status",65536)
        stage = "parse-selected-status-fields"
        values = _status_projection(raw)
        stage = "pid-directory-owner"
        result.update(self_proc_readable=True,proc_uid_matches_getuid=values["uid_matches_getuid"],
                      proc_owner_matches_getuid=(proc / pid).stat().st_uid == os.getuid(),umask=values["umask"])
        result["shared_reader"] = {"status":"read"}
    except (OSError,ValueError) as error:
        result["shared_reader"] = _probe_error(error,stage)
    result["numeric_pid_fd_reader"] = _status_via_directory_fd(proc,pid)
    try:
        safe_path(proc)
        target = os.readlink(proc / "self")
        match = re.fullmatch(r"(?:/proc/)?([0-9]{1,20})",target)
        result["proc_self_link"] = {"status":"numeric" if match else "unsupported-target",
                                    "matches_python_pid":bool(match and match[1] == pid)}
        if match:
            result["proc_self_fd_reader"] = _status_via_directory_fd(proc,match[1])
    except (OSError,ValueError) as error:
        result["proc_self_link"] = _probe_error(error,"read-proc-self-link")
    shell_umask = environment.get("DROIDDECK_AUDIT_SHELL_UMASK","")
    result["shell_umask"] = shell_umask if re.fullmatch(r"[0-7]{4}",shell_umask) else None
    result["reader_diagnostics_only"] = True
    return result


def runtime_audit_command():
    """Return a pasteable, self-contained read-only audit; no device file copy needed."""
    parent = Path(__file__).resolve().parent
    sources = {name: read_bytes(parent / (name+".py")).decode("utf-8")
               for name in ("preparation_common","preparation_runtime")}
    code = ("import json, sys, types\nfrom pathlib import Path\n"
            "sources = " + repr(sources) + "\n"
            "for name, source in sources.items():\n"
            "    module = types.ModuleType(name)\n"
            "    sys.modules[name] = module\n"
            "    exec(compile(source, name, 'exec'), module.__dict__)\n"
            "try:\n"
            "    result = sys.modules['preparation_runtime'].inspect_runtime(Path('/'))\n"
            "    print(json.dumps({'tool_version': sys.modules['preparation_common'].VERSION, **result}, ensure_ascii=True, indent=2))\n"
            "except (OSError, ValueError, TypeError):\n"
            "    print(json.dumps({'mode':'inspect-runtime','status':'input-unreadable','writes':[]}))\n"
            "    raise SystemExit(1)\n")
    compile(code,"runtime-audit-command","exec")
    delimiter = "DROIDDECK_RUNTIME_AUDIT_"+hashlib.sha256(code.encode()).hexdigest()[:16]
    require(delimiter not in code.splitlines(), "invalid audit delimiter")
    return "DROIDDECK_AUDIT_SHELL_UMASK=$(umask) /usr/bin/python3 -I -B - <<'"+delimiter+"'\n"+code+delimiter+"\n"
