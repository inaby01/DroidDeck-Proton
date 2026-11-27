"""Launch plans for the tool's own Wine runs (initialization, recheck, installers).

Full payload identity, pinned registration and proc observations are mandatory.
The caller must additionally establish provenance and actual runtime/stop scope;
identity and proc visibility alone do not establish trust or compatibility.
"""

import ast
import copy
import hashlib
import json
import os
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
from preparation_payload import PayloadInventory, verify_fex_runtime_tree, verify_tree
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
                prefix_version_sha256=None, trial_recheck_id=None, fex_runtime_contract=False):
    """Read-only plan. Hashes/runtime inputs come from trusted adapters, never profile JSON.

    ``fex_runtime_contract`` is for the managed initialization scopes only: the reviewed
    preparation slot may then hold FEX's one empty AppConfig directory.
    """
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
        require(trial_recheck_id is None and prefix_version_sha256 is None and not os.path.lexists(compatdata), "new compatdata required")
    else:
        # The origin is a registered-game prefix record (the probe trial origin was removed in 1.0.1).
        prefix = "gprefix-"
        require(type(trial_recheck_id) is str and trial_recheck_id.startswith(prefix) and len(trial_recheck_id) == len(prefix) + 32 and
                all(c in "0123456789abcdef" for c in trial_recheck_id[len(prefix):]),
                "managed trial origin required")
        require(type(prefix_version_sha256) is str and SHA256.fullmatch(prefix_version_sha256)
                and _prefix(compatdata) == prefix_version_sha256, "unverified or changed prefix version")
    overlays = {} if payload_overlays is None else copy.deepcopy(payload_overlays)
    payload_digest = _payload_digest(payload_inventory, overlays)
    require(type(fex_runtime_contract) is bool, "invalid runtime contract flag")
    if trial_recheck_id is None and not fex_runtime_contract:
        verify_tree(tool, payload_inventory, overlays)
    else:
        verify_fex_runtime_tree(tool, payload_inventory, overlays)
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
    # CPython must not read bytecode caches from the tool tree (they are only matched by header):
    # point the cache prefix at an absent path in the private work area; nothing is written there.
    bytecode_prefix = work / BYTECODE_PREFIX
    require(not os.path.lexists(bytecode_prefix), "bytecode cache prefix present")
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
           "SteamGameId": game_id, "SteamOverlayGameId": game_id, "PYTHONPYCACHEPREFIX": str(bytecode_prefix)}
    spec = {"tool": tool, "steam": steam, "registration_id": key, "install": install, "work": work,
            "home": home, "runtime_environment": dict(runtime_environment), "expected_hashes": hashes,
            "payload_inventory": payload_inventory, "payload_overlays": overlays, "target_pin": target_pin, "runtime_plan": runtime_plan,
            "operation": operation, "prefix_version_sha256": prefix_version_sha256, "trial_recheck_id": trial_recheck_id,
            "fex_runtime_contract": fex_runtime_contract}
    signature = {k: str(v) if hasattr(v, "parts") else v for k, v in spec.items()}
    signature["payload_inventory"] = payload_digest
    signature["target_pin"] = target_pin.digest
    signature["runtime_plan"] = None if runtime_plan is None else runtime_plan.identity_digest
    # Protocol keys remain private and are rechecked live, not persisted as credentials/digests.
    signature["runtime_environment"] = {key:("present" if key == "PROOT_FP_KEY" else value)
                                        for key,value in runtime_environment.items()}
    signature["tool_version"] = VERSION
    context = {k: v for k, v in signature.items() if k not in ("operation", "prefix_version_sha256")}
    return LaunchPlan(operation, key, _digest(signature), _digest(context), payload_digest, target_pin.digest, spec, env, (str(tool / "proton"), *OPERATIONS[operation]))


BYTECODE_PREFIX = ".no-bytecode-cache"


def require_no_bytecode_cache(launch):
    """Right before spawning: the bytecode cache prefix of the plan must still be absent."""
    require(not os.path.lexists(launch.environment["PYTHONPYCACHEPREFIX"]), "bytecode cache prefix present")


def _payload_digest(inventory, overlays):
    require(isinstance(inventory, PayloadInventory), "full payload inventory required")
    require(inventory.external_links == 0, "external payload links not supported for launch")
    return _digest({"archive_sha512": inventory.archive_sha512, "inventory_digest": inventory.digest,
                    "overlays": overlays})
