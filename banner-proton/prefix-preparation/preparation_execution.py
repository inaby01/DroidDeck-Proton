"""Internal preparation launcher; no CLI execution or dependency installer yet.

Full payload identity, pinned registration and proc observations are mandatory.
The caller must additionally establish provenance and actual runtime/stop scope;
identity and proc visibility alone do not establish trust or compatibility.
"""

import ast
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from dataclasses import dataclass, field

from preparation_common import (
    SHA256,
    VERSION,
    Invalid,
    app_id,
    fields,
    read_bytes,
    regular_open,
    require,
    safe_path,
    unchanged,
)
from preparation_payload import PayloadInventory, verify_tree
from preparation_processes import ProcessStopCheck
from preparation_runtime_context import HOOK_KEYS, RuntimeEnvironmentPlan
from preparation_target import RegistrationPin

RUNTIME_KEYS = frozenset((
    "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PULSE_SERVER", "DBUS_SESSION_BUS_ADDRESS",
    "LANG", "LC_ALL", "TZ", "FEX_ROOTFS", "FEX_APP_CONFIG_LOCATION",
))
SETTINGS_KEYS = frozenset((
    "PROTON_LOG", "PROTON_SOFTDENCHI_OBSERVE", "PROTON_SOFTDENCHI_CLEANUP", "PROTONFIXES_DISABLE",
    "WINEDEBUG", "DXVK_LOG_LEVEL", "DXVK_NVAPI_LOG_LEVEL", "VKD3D_DEBUG", "VKD3D_SHADER_DEBUG",
    "WINE_MONO_TRACE", "GST_DEBUG_NO_COLOR",
))
DISABLED = {"PROTON_SOFTDENCHI_OBSERVE": "0", "PROTON_SOFTDENCHI_CLEANUP": "0",
            "PROTONFIXES_DISABLE": "1", "COPYPREFIX": "0", "PROTON_LOG": "0", "WINEDEBUG": "-all"}
OPERATIONS = {"initialize": ("run", "cmd.exe", "/d", "/c", "exit", "0"),
              "probe": ("runinprefix", "cmd.exe", "/d", "/c", "exit", "0")}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _settings(raw):
    """Accept only shipped literal dictionaries and the installer's literal update.

    This is an additional restriction on an already trusted, pinned distribution,
    not a sandbox or an attempt to approve arbitrary Python settings.
    """
    try:
        tree = ast.parse(raw)
        require(0 < len(tree.body) <= 16, "unsupported user settings")
        configured = False
        for node in tree.body:
            if isinstance(node, ast.Assign):
                require(not configured and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                        and node.targets[0].id == "user_settings", "unsupported user settings assignment")
                configured = True
                value = ast.literal_eval(node.value)
            else:
                require(configured and isinstance(node, ast.Expr) and isinstance(node.value, ast.Call),
                        "executable user settings forbidden")
                call = node.value
                require(isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                        and call.func.value.id == "user_settings" and call.func.attr == "update"
                        and len(call.args) == 1 and not call.keywords, "executable user settings forbidden")
                value = ast.literal_eval(call.args[0])
            require(type(value) is dict and value.keys() <= SETTINGS_KEYS and
                    all(type(v) is str and len(v) <= 4096 and "\0" not in v for v in value.values()),
                    "unsupported user settings values")
    except (SyntaxError, ValueError, TypeError, RecursionError) as error:
        raise Invalid("unsupported user settings") from error


def _identities(tool, expected):
    fields(expected, ("proton", "version", "user_settings.py"))
    measured = {}
    for name, digest in expected.items():
        path = safe_path(tool / name, tool)
        if name == "user_settings.py" and digest is None:
            require(not os.path.lexists(path), "unexpected user settings")
            measured[name] = None
            continue
        require(type(digest) is str and SHA256.fullmatch(digest), "trusted launcher hash required")
        raw = read_bytes(path, 1024 * 1024 if name == "proton" else 128 * 1024)
        measured[name] = hashlib.sha256(raw).hexdigest()
        require(measured[name] == digest, "launcher inputs changed")
        if name == "user_settings.py":
            _settings(raw)
        if name == "version":
            require(raw.strip() and len(raw) <= 4096, "invalid payload version")
    require(os.access(tool / "proton", os.X_OK), "Proton launcher not executable")
    return measured


def inspect_initialization_inputs(*, tool, steam, registration_id, expected_hashes, work, home):
    """Read-only qualification inputs for a future dedicated initialization test.

    Does not make directories, lock, launch or interpret observations as permission.
    Proc absence remains limited to the visible same-owner view, including on proot.
    """
    tool, steam, work, home = map(safe_path, (tool, steam, work, home))
    key = app_id(registration_id)
    compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
    result = {"mode": "inspect-initialization-inputs", "command": list(OPERATIONS["initialize"]),
              "execution_authorized": False, "prefix_initialization_authorized": False,
              "preparation_complete": False, "writes": [], "checks": {},
              "blockers": ["initialization-test-not-exposed", "device-process-scope-unverified",
                           "wine-runtime-and-gui-unverified", "initialization-growth-unmeasured"]}

    def inspect(name, function):
        try:
            value = function()
            result["checks"][name] = {"status": "accepted", **(value if type(value) is dict else {})}
        except (OSError, ValueError, TypeError, KeyError) as error:
            result["checks"][name] = {"status": "rejected", "error_class": type(error).__name__,
                                      "errno": getattr(error, "errno", None)}
            result["blockers"].append(name + "-rejected")

    def launcher():
        _identities(tool, expected_hashes)
        return {"identity": "matched", "settings": "restricted-literal-only", "code_executed": False}

    def prefix():
        _aliases(steam, key)
        exists = os.path.lexists(compatdata)
        require(not exists, "new compatdata required")
        return {"exists": False, "action": "new-prefix-only-blocked"}

    def private_paths():
        for private in (work, home):
            require(not os.path.lexists(private), "private launch path already exists")
            for protected in (steam, tool):
                require(private != protected and not private.is_relative_to(protected) and
                        not protected.is_relative_to(private), "launch directories overlap")
            ancestor = private.parent
            while not ancestor.exists():
                ancestor = ancestor.parent
            safe_path(ancestor)
            info = ancestor.stat()
            require(ancestor.is_dir() and info.st_uid == os.getuid() and not info.st_mode & 0o022,
                    "unsafe private launch ancestor")
        require(work != home and not work.is_relative_to(home) and not home.is_relative_to(work),
                "overlapping private launch paths")
        return {"existing_paths_adopted": False, "creation_authorized": False}

    def processes():
        observation = ProcessStopCheck(compatdata).check()
        if not observation["clear_in_view"]:
            result["blockers"].append("target-process-view-not-clear")
        return observation

    inspect("launcher-inputs", launcher)
    inspect("prefix-absence", prefix)
    inspect("private-launch-paths", private_paths)
    inspect("process-observation", processes)
    return result


def inspect_prelaunch_context(*, steam, settings, home, environment, runtime_root):
    """Independent metadata observations, also usable when target planning fails.

    No directories, locks, connections or subprocesses; no credential content,
    command lines, environment values or mount tables are exported.
    """
    result = {"scope": "read-only-prelaunch-context", "checks": {}, "writes": [],
              "execution_authorized": False, "active_connection_tested": False}

    def inspect(name, function):
        try:
            result["checks"][name] = {"status": "accepted", **function()}
        except (OSError, ValueError, TypeError, KeyError) as error:
            result["checks"][name] = {"status": "rejected", "error_class": type(error).__name__,
                                      "errno": getattr(error, "errno", None)}

    def filesystem(path):
        path = safe_path(path)
        nearest = path
        while not nearest.exists():
            nearest = nearest.parent
        safe_path(nearest)
        info, fs = nearest.stat(), os.statvfs(nearest)
        require(nearest.is_dir(), "filesystem directory required")
        return {"exists": path.exists(), "ancestor_owner_matches_self": info.st_uid == os.getuid(),
                "ancestor_mode": format(stat.S_IMODE(info.st_mode), "04o"),
                "ancestor_other_writer": bool(info.st_mode & 0o022),
                "available_bytes": fs.f_bavail * (fs.f_frsize or fs.f_bsize),
                "available_inodes": fs.f_favail,
                "read_only": bool(fs.f_flag & getattr(os, "ST_RDONLY", 1)),
                "noexec": bool(fs.f_flag & getattr(os, "ST_NOEXEC", 8)),
                "actual_write_tested": False}

    for name, path in (("steam", steam), ("tool-parent", steam / "compatibilitytools.d"),
                       ("compatdata-parent", steam / "steamapps/compatdata"), ("settings", settings),
                       ("private-work-parent", home / ".local/share/droiddeck-preparation-work"),
                       ("private-state-parent", home / ".local/state/droiddeck-prefix-preparation")):
        inspect("filesystem-" + name, lambda path=path: filesystem(path))

    def metadata(path):
        path = safe_path(path)
        if not path.exists():
            return {"exists": False}
        info = path.stat()
        return {"exists": True, "regular": stat.S_ISREG(info.st_mode),
                "socket": stat.S_ISSOCK(info.st_mode), "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                "owner_matches_self": info.st_uid == os.getuid(), "link_count": info.st_nlink,
                "readable": os.access(path, os.R_OK), "content_read": False}

    def display():
        value = environment.get("DISPLAY", "")
        require(type(value) is str, "invalid display input")
        match = re.fullmatch(r":([0-9]{1,5})(?:\.[0-9]{1,3})?", value)
        if match is None:
            return {"present": bool(value), "local_socket_form": False, "connection_verified": False}
        return {"present": True, "local_socket_form": True, "connection_verified": False,
                "endpoint": metadata(runtime_root / "tmp/.X11-unix" / ("X" + match[1]))}

    def authority():
        path = environment.get("XAUTHORITY")
        if path:
            return {"explicit": True, **metadata(safe_path(path))}
        parent_home = environment.get("HOME")
        return {"explicit": False, **metadata(safe_path(parent_home or home) / ".Xauthority")}

    inspect("gui-display-metadata", display)
    inspect("gui-authority-metadata", authority)
    for name, relative in (("system-python", "usr/bin/python3"), ("arm64-loader", "lib/ld-linux-aarch64.so.1")):
        # System paths are commonly symlinks: observe existence/access only,
        # never follow them to read content or treat them as trusted code.
        def system_file(relative=relative):
            path = runtime_root / relative
            return {"exists": path.exists(), "executable": os.access(path, os.X_OK), "code_executed": False}
        inspect(name, system_file)
    result["environment_presence"] = {key: bool(environment.get(key)) for key in
        ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY", "PULSE_SERVER", "DBUS_SESSION_BUS_ADDRESS",
         "FEX_ROOTFS", "FEX_APP_CONFIG_LOCATION", "PROOT_FP_KEY", "LD_PRELOAD", "LD_AUDIT")}
    result["copy_prefix_requested"] = environment.get("COPYPREFIX") == "1"
    return result


def _prefix(compatdata):
    safe_path(compatdata)
    require(compatdata.is_dir(), "prefix absent")
    for name in ("pfx", "pfx/drive_c", "pfx/drive_c/windows"):
        require(safe_path(compatdata / name, compatdata).is_dir(), "prefix structure missing")
    version = read_bytes(compatdata / "version", 4096)
    require(version.strip(), "prefix version absent")
    # Check only the registry header, never collect whole registries or authentication data.
    for name in ("system.reg", "user.reg"):
        with regular_open(compatdata / "pfx" / name, 64 * 1024**2) as stream:
            before = os.fstat(stream.fileno())
            require(stream.read(32).startswith(b"WINE REGISTRY Version 2"), "registry header missing")
            unchanged(before, os.fstat(stream.fileno()))
    return hashlib.sha256(version).hexdigest()


def _aliases(steam, key):
    base = safe_path(steam / "steamapps/compatdata", steam)
    require(base.is_dir(), "existing compatdata parent required")
    with os.scandir(base) as entries:
        for index, entry in enumerate(entries):
            require(index < 4096, "too many compatdata entries")
            name = entry.name
            if name.isascii() and name.lstrip("-").isdecimal():
                require(len(name) <= 11, "invalid compatdata ID")
                if int(name) % 2**32 == int(key):
                    require(name == key, "signed or noncanonical prefix alias exists")
    return base


@dataclass(frozen=True)
class LaunchPlan:
    operation: str
    registration_id: str
    digest: str
    context_digest: str
    payload_pin_digest: str
    target_pin_digest: str
    spec: dict = field(repr=False)
    environment: dict = field(repr=False)
    argv: tuple = field(repr=False)

    def summary(self):
        return {"operation": self.operation, "app_id": self.registration_id, "input_digest": self.digest,
                "command": list(OPERATIONS[self.operation]), "payload": "identity-pinned-provenance-unverified",
                "payload_pin_digest": self.payload_pin_digest, "target_pin_digest": self.target_pin_digest,
                "runtime_equivalence": "unverified", "preparation_complete": False, "writes": []}


def plan_launch(*, tool, steam, registration_id, install, work, home, runtime_environment,
                expected_hashes, payload_inventory=None, payload_overlays=None, target_pin=None, runtime_plan=None, operation="initialize",
                prefix_version_sha256=None, origin_launch_id=None):
    """Read-only plan. Hashes/runtime inputs come from trusted adapters, never profile JSON."""
    require(operation in OPERATIONS, "unsupported preparation operation")
    require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
    tool, steam, install, work, home = map(safe_path, (tool, steam, install, work, home))
    require(all(path.is_dir() for path in (tool, steam, install, work, home)), "launch directories absent")
    key = app_id(registration_id)
    require(isinstance(target_pin, RegistrationPin) and target_pin.registration_id == key
            and target_pin.steam == steam and target_pin.exe.parent == install, "matching target pin required")
    target_pin.verify()
    base = _aliases(steam, key)
    compatdata = safe_path(base / key, base)
    # Only dedicated work/home areas, separate from payload, game and Steam data.
    for private in (work, home):
        for protected in (tool, install, steam):
            require(private != protected and not private.is_relative_to(protected) and
                    not protected.is_relative_to(private), "launch directories overlap")
    if operation == "initialize":
        require(prefix_version_sha256 is None and origin_launch_id is None and not os.path.lexists(compatdata), "new compatdata required")
    else:
        _launch_id(origin_launch_id)
        require(type(prefix_version_sha256) is str and SHA256.fullmatch(prefix_version_sha256)
                and _prefix(compatdata) == prefix_version_sha256, "unverified or changed prefix version")
    overlays = {} if payload_overlays is None else copy.deepcopy(payload_overlays)
    payload_digest = _payload_digest(payload_inventory, overlays)
    verify_tree(tool, payload_inventory, overlays)
    source_entries = {**payload_inventory.entries, **overlays}
    launcher_hashes = {}
    for name in ("proton", "version", "user_settings.py"):
        entry = source_entries.get(name)
        require(entry is not None or name == "user_settings.py", "payload launcher inputs absent")
        require(entry is None or entry["kind"] == "file", "payload launcher input must be regular")
        launcher_hashes[name] = None if entry is None else entry["sha256"]
    require(launcher_hashes == expected_hashes, "launcher hashes differ from pinned payload")
    hashes = _identities(tool, launcher_hashes)
    if runtime_plan is not None:
        require(isinstance(runtime_plan, RuntimeEnvironmentPlan) and runtime_plan.root == safe_path("/")
                and runtime_plan.view == "current-root", "live runtime environment plan required")
        runtime_plan.verify()
        require(runtime_environment == runtime_plan.environment, "runtime environment differs from pinned plan")
    allowed_runtime_keys = RUNTIME_KEYS if runtime_plan is None else RUNTIME_KEYS | HOOK_KEYS | {"XAUTHORITY"}
    require(type(runtime_environment) is dict and runtime_environment.keys() <= allowed_runtime_keys,
            "unsupported preparation runtime variable")
    require(all(type(v) is str and len(v.encode()) <= 4096 and not any(c in v for c in "\0\r\n")
                for v in runtime_environment.values()), "invalid preparation runtime value")
    number = int(key)
    steam_id = key if number < 2**31 else "0"
    game_id = key if number < 2**31 else str(number << 32 | 0x02000000)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
           **runtime_environment, **DISABLED,
           "WINEPREFIX": str(compatdata / "pfx"), "STEAM_COMPAT_DATA_PATH": str(compatdata),
           "STEAM_COMPAT_CLIENT_INSTALL_PATH": str(steam), "STEAM_COMPAT_INSTALL_PATH": str(install),
           "STEAM_COMPAT_LIBRARY_PATHS": str(steam / "steamapps"), "STEAM_COMPAT_TOOL_PATHS": str(tool),
           "SteamAppId": steam_id, "STEAM_COMPAT_APP_ID": steam_id,
           "SteamGameId": game_id, "SteamOverlayGameId": game_id}
    spec = {"tool": tool, "steam": steam, "registration_id": key, "install": install, "work": work,
            "home": home, "runtime_environment": dict(runtime_environment), "expected_hashes": hashes,
            "payload_inventory": payload_inventory, "payload_overlays": overlays, "target_pin": target_pin, "runtime_plan": runtime_plan,
            "operation": operation, "prefix_version_sha256": prefix_version_sha256, "origin_launch_id": origin_launch_id}
    signature = {k: str(v) if hasattr(v, "parts") else v for k, v in spec.items()}
    signature["payload_inventory"] = payload_digest
    signature["target_pin"] = target_pin.digest
    signature["runtime_plan"] = None if runtime_plan is None else runtime_plan.identity_digest
    # Protocol keys remain private and are rechecked live, not persisted as credentials/digests.
    signature["runtime_environment"] = {key:("present" if key == "PROOT_FP_KEY" else value)
                                        for key,value in runtime_environment.items()}
    signature["tool_version"] = VERSION
    context = {k: v for k, v in signature.items() if k not in ("operation", "prefix_version_sha256", "origin_launch_id")}
    return LaunchPlan(operation, key, _digest(signature), _digest(context), payload_digest, target_pin.digest, spec, env, (str(tool / "proton"), *OPERATIONS[operation]))


def _payload_digest(inventory, overlays):
    require(isinstance(inventory, PayloadInventory), "full payload inventory required")
    require(inventory.external_links == 0, "external payload links not supported for launch")
    return _digest({"archive_sha512": inventory.archive_sha512, "inventory_digest": inventory.digest,
                    "overlays": overlays})


def _verify_payload(plan):
    inventory, overlays = plan.spec["payload_inventory"], plan.spec["payload_overlays"]
    require(_payload_digest(inventory, overlays) == plan.payload_pin_digest, "payload pin changed")
    return verify_tree(plan.spec["tool"], inventory, overlays)


def _verify_runtime(plan):
    context = plan.spec["runtime_plan"]
    if context is not None:
        context.verify()
        require(plan.spec["runtime_environment"] == context.environment, "runtime inputs changed")


def _verify_target(plan):
    pin = plan.spec["target_pin"]
    require(isinstance(pin, RegistrationPin) and pin.digest == plan.target_pin_digest, "target pin changed")
    return pin.verify()


def _launch_id(value):
    require(type(value) is str and value.startswith("launch-") and len(value) == 39 and
            all(c in "0123456789abcdef" for c in value[7:]), "invalid launch ID")


def validate_launch_record(record):
    fields(record, ("schema_version", "tool_version", "launch_id", "app_id", "operation", "input_digest",
                    "status", "exit_code", "prefix_version_sha256", "context_digest", "payload_pin_digest", "target_pin_digest", "preparation_complete"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 2, "unknown launch record")
    require(type(record["tool_version"]) is str and len(record["tool_version"]) <= 64, "invalid launch version")
    _launch_id(record["launch_id"])
    require(app_id(record["app_id"]) == record["app_id"] and record["operation"] in OPERATIONS, "invalid launch target")
    for key in ("input_digest", "context_digest", "payload_pin_digest", "target_pin_digest"):
        require(type(record[key]) is str and SHA256.fullmatch(record[key]), "invalid launch digest")
    require(record["status"] in ("running", "needs-user", "failed", "initialized-unverified", "probe-exited")
            and record["preparation_complete"] is False, "invalid launch state")
    require(record["exit_code"] is None or type(record["exit_code"]) is int, "invalid launch exit code")
    version = record["prefix_version_sha256"]
    require(version is None or type(version) is str and SHA256.fullmatch(version), "invalid prefix version digest")


class LaunchSession:
    """A live child handle. Caller retains preparation locks through wait/stop checks.

    Timeout never kills a child or claims Wine has stopped. An abandoned session
    stays running/needs-user on disk; reopening inventory never promotes it.
    """

    def __init__(self, plan, store, ready, stop_check):
        self.plan, self.store, self.ready = plan, store, ready
        self.stop_check = stop_check
        self.process = None
        self.record_hash = None
        self.record = {"schema_version": 2, "tool_version": VERSION, "launch_id": "launch-" + secrets.token_hex(16),
                       "app_id": plan.registration_id, "operation": plan.operation, "input_digest": plan.digest,
                       "context_digest": plan.context_digest, "payload_pin_digest": plan.payload_pin_digest, "target_pin_digest": plan.target_pin_digest, "status": "running", "exit_code": None, "prefix_version_sha256": None,
                       "preparation_complete": False}

    def _guard(self):
        self.store._guard()
        require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
        compatdata = self.plan.spec["steam"] / "steamapps/compatdata" / self.plan.registration_id
        require(self.store._held_target == hashlib.sha256(str(compatdata).encode()).hexdigest(), "target launch lock required")
        if self.plan.operation == "probe":
            origin, _ = self.store.read_record("launches", self.plan.spec["origin_launch_id"] + ".json")
            validate_launch_record(origin)
            require(origin["operation"] == "initialize" and origin["status"] == "initialized-unverified"
                    and origin["exit_code"] == 0 and origin["app_id"] == self.plan.registration_id
                    and origin["target_pin_digest"] == self.plan.target_pin_digest
                    and origin["payload_pin_digest"] == self.plan.payload_pin_digest
                    and origin["context_digest"] == self.plan.context_digest
                    and origin["prefix_version_sha256"] == self.plan.spec["prefix_version_sha256"],
                    "matching initialization record required")
        require(callable(self.ready), "trusted launch readiness checks required")
        checks = self.ready()
        fields(checks, ("target", "payload", "runtime", "stopped"))
        require(all(type(value) is bool for value in checks.values()), "boolean launch checks required")
        require(isinstance(self.stop_check, ProcessStopCheck) and
                safe_path(self.stop_check.compatdata) == compatdata, "matching process observation required")
        observation = self.stop_check.check()
        checks = dict(checks)
        checks["stopped"] = checks["stopped"] and observation["clear_in_view"]
        return checks

    def _save(self):
        validate_launch_record(self.record)
        self.record_hash = self.store.write_record("launches", self.record["launch_id"] + ".json",
                                                  self.record, expected_hash=self.record_hash)
        return dict(self.record)

    def start(self):
        require(self.process is None and self.record_hash is None, "launch session already started")
        checks = self._guard()
        require(all(checks.values()), "launch prerequisites not verified")
        fresh = plan_launch(**self.plan.spec)
        require(fresh == self.plan, "launch plan changed")
        for path in (self.plan.spec["tool"], self.plan.spec["steam"], self.plan.spec["install"],
                     self.plan.spec["work"], self.plan.spec["home"]):
            root = self.store.root
            require(root != path and not root.is_relative_to(path) and not path.is_relative_to(root), "store overlaps launch directories")
        self._save()
        try:
            compatdata = self.plan.spec["steam"] / "steamapps/compatdata" / self.plan.registration_id
            if self.plan.operation == "initialize":
                compatdata.mkdir(mode=0o700)  # Never replace or remove an existing prefix, including failed attempts.
            checks = self._guard()
            require(all(checks.values()), "launch prerequisites changed")
            _verify_runtime(self.plan)
            _verify_target(self.plan)
            _verify_payload(self.plan)
            _identities(self.plan.spec["tool"], self.plan.spec["expected_hashes"])
            safe_path(compatdata)
            _aliases(self.plan.spec["steam"], self.plan.registration_id)
            self.process = subprocess.Popen(self.plan.argv, cwd=self.plan.spec["work"], env=self.plan.environment,
                                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            shell=False, close_fds=True, start_new_session=True)
        except (OSError, Invalid):
            self.record["status"] = "failed"
            self._save()
            raise
        return self

    def wait(self, timeout=30):
        require(type(timeout) is int and 1 <= timeout <= 120, "bounded wait required")
        require(self.process is not None, "launch session not started")
        self._guard()
        if self.record["status"] in ("failed", "initialized-unverified", "probe-exited"):
            return dict(self.record)
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.record["status"] = "needs-user"
            return self._save()
        self.record["exit_code"] = code
        checks = self._guard()
        self.record["status"] = "needs-user" if not checks["stopped"] else "failed"
        if checks["stopped"] and checks["target"] and checks["payload"] and checks["runtime"] and code == 0:
            try:
                _verify_runtime(self.plan)
                _verify_target(self.plan)
                _verify_payload(self.plan)
                _identities(self.plan.spec["tool"], self.plan.spec["expected_hashes"])
                _aliases(self.plan.spec["steam"], self.plan.registration_id)
                compatdata = self.plan.spec["steam"] / "steamapps/compatdata" / self.plan.registration_id
                version = _prefix(compatdata)
                expected = self.plan.spec["prefix_version_sha256"]
                require(expected is None or expected == version, "prefix version changed")
                self.record["prefix_version_sha256"] = version
                self.record["status"] = "initialized-unverified" if self.plan.operation == "initialize" else "probe-exited"
            except (OSError, Invalid):
                self.record["status"] = "failed"
        return self._save()
