"""DroidDeck 0.7.1 target-only binding plans and an internal guarded writer.

No global synchronizer, helper import, Proton launch or prefix mutation occurs here.
The writer is not exposed by the CLI until real dependency/payload/stop checks exist.
"""

import contextlib
import copy
import fcntl
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass, field

from preparation_common import (
    MAX_JSON,
    SHA256,
    VERSION,
    Invalid,
    app_id,
    bounded,
    checked,
    fields,
    pairs,
    read_bytes,
    require,
    safe_path,
    string,
)
from preparation_vdf import TOOL_ID, Document, patch_game_mapping

STEAM_PATH = ("InstallConfigStore", "Software", "Valve", "Steam")
STOCK_TOOL = "droiddeck-proton-arm64"
FILES = ("games", "config", "state")


def _json(raw, default):
    if raw is None:
        return copy.deepcopy(default)
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        bounded(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid binding JSON") from error
    require(type(value) is dict, "binding JSON must be an object")
    return value


def _raw(path):
    safe_path(path)
    return read_bytes(path) if path.exists() else None


def _encoded(before, value, original):
    if before is not None and value == original:
        return before
    bounded(value)
    raw = (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode()
    require(len(raw) <= MAX_JSON, "binding result too large")
    return raw


def _choice(value):
    if value is None:
        return
    fields(value, ("valve", "dir"), ("name",))
    require(type(value["valve"]) is bool, "invalid choice kind")
    name = string(value["dir"])
    require("/" not in name and name not in (".", ".."), "invalid choice directory")
    if "name" in value:
        require(type(value["name"]) is str and TOOL_ID.fullmatch(value["name"]), "invalid choice tool ID")


def _requests(value):
    require(type(value) is dict and len(value) <= 4096, "invalid game request map")
    for key, choice in value.items():
        require(app_id(key) == key, "noncanonical request ID")
        _choice(choice)


def registered_tool(steam, directory):
    """Only inspect an already registered custom tool; never adopt or execute it."""
    name = string(directory)
    require("/" not in name and name not in (".", ".."), "invalid tool directory")
    root = safe_path(steam / "compatibilitytools.d" / name, steam)
    require(root.is_dir(), "tool directory absent")
    paths = {key: safe_path(root / filename, root) for key, filename in (
        ("catalog", "compatibilitytool.vdf"), ("manifest", "toolmanifest.vdf"),
        ("wrapper", "droiddeck-proton-wrap"), ("proton", "proton"))}
    raw = {key: checked("binding-tool-read-" + key, read_bytes, path) for key, path in paths.items()}
    tools = checked("binding-tool-catalog", lambda: Document(raw["catalog"]).node(("compatibilitytools", "compat_tools")).value)
    require(type(tools) is dict and len(tools) == 1, "tool catalog must identify exactly one tool")
    tool_id = next(iter(tools))
    require(TOOL_ID.fullmatch(tool_id), "invalid registered tool ID")
    entry = tools[tool_id].value
    require(type(entry) is dict and "install_path" in entry and entry["install_path"].value == ".",
            "custom tool must use its own directory")
    require(all(key in entry and entry[key].value == value for key, value in
                (("from_oslist", "windows"), ("to_oslist", "linux"))), "unsupported tool platforms")
    manifest = checked("binding-tool-manifest", lambda: Document(raw["manifest"]).node(("manifest",)).value)
    require(type(manifest) is dict and "commandline" in manifest and
            manifest["commandline"].value == "/droiddeck-proton-wrap %verb%", "tool wrapper not registered")
    require(os.access(paths["wrapper"], os.X_OK) and os.access(paths["proton"], os.X_OK), "tool launchers not executable")
    return tool_id, {key: hashlib.sha256(data).hexdigest() for key, data in raw.items()}


def _games_document(raw):
    value = _json(raw, {"version": 1, "games": {}})
    fields(value, ("version", "games"))
    require(type(value["version"]) is int and value["version"] == 1, "unknown choices version")
    _requests(value["games"])
    return value


def binding_error(error):
    """Fixed diagnostic vocabulary only; never expose exception text or values."""
    conditions = {
        "unsupported VDF token": "vdf-token",
        "duplicate or incomplete VDF entry": "vdf-duplicate-or-incomplete",
        "missing VDF block": "vdf-missing-block",
        "VDF too large": "vdf-size",
        "expected VDF string": "vdf-string",
        "invalid VDF tail": "vdf-tail",
        "unclosed VDF block": "vdf-unclosed",
        "unknown or missing fields": "object-fields",
        "unknown choices version": "choices-version",
        "invalid binding JSON": "json-encoding-or-structure",
        "binding JSON must be an object": "json-object",
        "invalid game request map": "request-map",
        "noncanonical request ID": "request-id",
        "invalid app ID": "app-id",
        "invalid choice kind": "choice-kind",
        "invalid choice directory": "choice-directory",
        "invalid choice tool ID": "choice-tool-id",
        "unsupported auto history format": "auto-history",
        "invalid selection history": "selection-history",
        "invalid history ID": "history-id",
        "single-link regular file required": "regular-single-link-file",
        "tool wrapper not registered": "tool-wrapper",
        "tool launchers not executable": "launcher-executable",
        "invalid registered tool ID": "tool-id",
    }
    return {"check": getattr(error, "preparation_check", "binding-input"),
            "error_class": type(error).__name__, "errno": getattr(error, "errno", None),
            "condition": conditions.get(str(error), "input-rejected")}


def inspect_binding_inputs(steam, settings, registration_id, directory):
    """Independent bounded read checks after a rejected plan; no raw config data.

    A successful subcheck is diagnostic only and cannot authorize a writer. Each
    input is reopened safely; these observations are not a coherent binding plan.
    """
    results = {}

    def inspect(name, function):
        try:
            function()
            results[name] = {"status": "accepted"}
        except (OSError, ValueError, TypeError, KeyError) as error:
            results[name] = {"status": "rejected", **binding_error(error)}

    inspect("registered-tool", lambda: registered_tool(steam, directory))
    inspect("games-schema", lambda: _games_document(_raw(safe_path(settings / "games.json", settings))))

    def state_field(name):
        state = _json(_raw(safe_path(settings / "state.json", settings)), {})
        if name not in state:
            return
        value = state[name]
        if name == "games_applied":
            _requests(value)
        elif name == "auto":
            require(type(value) is dict, "unsupported auto history format")
        else:
            require(type(value) is list and len(value) <= 4096, "invalid selection history")
            require(all(type(app) is str and app_id(app) == app for app in value), "invalid history ID")

    for name in ("games_applied", "auto", "picked", "native_choices"):
        inspect("state-" + name, lambda name=name: state_field(name))
    inspect("target-mapping", lambda: patch_game_mapping(
        _raw(safe_path(steam / "config/config.vdf", steam)), registration_id, "Diagnostic-Tool"))
    return {"scope": "independent-read-only-checks", "coherent_plan": False,
            "checks": results, "writes": [], "execution_authorized": False}


@dataclass(frozen=True)
class BindingPlan:
    registration_id: str
    directory: str
    tool: str
    digest: str
    other_pending_count: int
    paths: dict = field(repr=False)
    before: dict = field(repr=False)
    after: dict = field(repr=False)
    tool_hashes: dict = field(repr=False)

    def summary(self):
        return {"adapter": "droiddeck-0.7.1-target-only", "app_id": self.registration_id,
                "directory": self.directory, "tool": self.tool, "input_digest": self.digest,
                "planned_files": [name for name in FILES if self.before[name] != self.after[name]],
                "other_pending_count": self.other_pending_count, "other_games_changed": False,
                "default_changed": False, "wrapper": "present-unverified", "launcher": "present-unverified",
                "payload": "uninspected",
                "blockers": ["dependency-postconditions-unverified", "payload-integrity-unverified",
                             "binding-writer-not-exposed"], "writes": []}


def plan_binding(steam, settings, registration_id, directory):
    steam, settings = safe_path(steam), safe_path(settings)
    require(steam != settings and not steam.is_relative_to(settings) and not settings.is_relative_to(steam),
            "Steam/settings roots must be separate")
    require(steam.is_dir() and settings.is_dir(), "existing Steam/settings directories required")
    key = app_id(registration_id)
    tool, tool_hashes = checked("binding-registered-tool", registered_tool, steam, directory)
    paths = {"config": safe_path(steam / "config/config.vdf", steam),
             "games": safe_path(settings / "games.json", settings), "state": safe_path(settings / "state.json", settings)}
    before = {name: checked("binding-read-" + name, _raw, path) for name, path in paths.items()}
    require(before["config"] is not None, "existing config required")
    original_games = checked("binding-games-schema", _games_document, before["games"])
    original_state = checked("binding-state-schema", _json, before["state"], {})
    recorded = original_state.get("games_applied")
    require(recorded is None and "games_applied" not in original_state or type(recorded) is dict, "invalid applied history")
    if recorded is not None:
        checked("binding-applied-history", _requests, recorded)
    applied = copy.deepcopy(recorded if recorded is not None else
                            original_games["games"] if "tools" in original_state else {})
    pending = sum(1 for app, choice in original_games["games"].items() if app != key and (app not in applied or applied[app] != choice))
    games, state = copy.deepcopy(original_games), copy.deepcopy(original_state)
    wanted = {"valve": False, "dir": directory}
    games["games"][key] = wanted
    applied[key] = wanted
    state["games_applied"] = applied
    steam_node = checked("binding-steam-config", lambda: Document(before["config"]).node(STEAM_PATH).value)
    require(type(steam_node) is dict, "invalid Steam block")
    mapping_node = steam_node.get("CompatToolMapping")
    mapping = mapping_node.value if mapping_node is not None else {}
    require(type(mapping) is dict, "invalid mapping block")
    current = {}
    for app, entry in mapping.items():
        require(app == "0" or app_id(app) == app, "invalid mapping app ID")
        require(type(entry.value) is dict, "invalid mapping entry")
        entry_name = entry.value.get("name")
        require(entry_name is None or type(entry_name.value) is str, "invalid mapping name")
        current[app] = entry_name.value if entry_name else ""
    auto = state.get("auto", {app: value for app, value in current.items() if app != "0" and value == STOCK_TOOL})
    require(type(auto) is dict, "unsupported auto history format")
    state["auto"] = {app: value for app, value in auto.items() if app != key}
    for history in ("picked", "native_choices"):
        if history in state:
            require(type(state[history]) is list and len(state[history]) <= 4096, "invalid selection history")
            require(all(type(app) is str and app_id(app) == app for app in state[history]), "invalid history ID")
    picked = state.get("picked", [])
    state["picked"] = picked if key in picked else picked + [key]
    if "native_choices" in state:
        state["native_choices"] = [app for app in state["native_choices"] if app != key]
    after = {"config": checked("binding-target-mapping", patch_game_mapping, before["config"], key, tool),
             "games": _encoded(before["games"], games, original_games),
             "state": _encoded(before["state"], state, original_state)}
    fingerprint = {"version": VERSION, "app_id": key, "directory": directory, "tool": tool,
                   "roots": [str(steam), str(settings)], "tool_hashes": tool_hashes,
                   "files": {name: hashlib.sha256(raw).hexdigest() if raw is not None else None for name, raw in before.items()}}
    digest = hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()
    return BindingPlan(key, directory, tool, digest, pending, paths, before, after, tool_hashes)


@contextlib.contextmanager
def droiddeck_lock(settings):
    """Same lock filename/flock as DroidDeck 0.7.1, with nonblocking safety checks."""
    settings = safe_path(settings)
    require(settings.is_dir(), "settings directory missing")
    descriptor = os.open(safe_path(settings / "lock", settings), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                not stat.S_IMODE(info.st_mode) & 0o022, "invalid DroidDeck lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Invalid("DroidDeck settings are locked") from error

        def check():
            safe_path(settings / "lock", settings)
            current = (settings / "lock").stat()
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and current.st_nlink == 1
                    and current.st_uid == os.getuid() and not stat.S_IMODE(current.st_mode) & 0o022,
                    "DroidDeck lock replaced or changed")
        check()
        yield check
    finally:
        os.close(descriptor)


def _atomic(path, data, previous, guard, replaced):
    safe_path(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = "prefix-binding-" + secrets.token_hex(16) + ".tmp"
    try:
        mode = 0o600
        if previous is not None:
            info = path.stat()
            require(info.st_uid == os.getuid() and info.st_nlink == 1, "binding file ownership changed")
            mode = stat.S_IMODE(info.st_mode)
            require(not mode & 0o022 and not mode & 0o7000, "unsafe binding file mode")
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd), "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        guard()
        require(_raw(path) == previous, "binding file changed before replace")
        parent = path.parent.stat()
        pinned = os.fstat(fd)
        require((parent.st_dev, parent.st_ino) == (pinned.st_dev, pinned.st_ino), "binding parent changed")
        os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        replaced()
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def validate_binding_record(record):
    bounded(record)
    fields(record, ("schema_version", "tool_version", "binding_id", "app_id", "input_digest", "status",
                    "completed_files", "preparation_complete"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and
            record["tool_version"] == VERSION, "unknown binding record version")
    require(type(record["binding_id"]) is str and record["binding_id"].startswith("binding-") and
            len(record["binding_id"]) == 40 and all(c in "0123456789abcdef" for c in record["binding_id"][8:]), "invalid binding ID")
    require(app_id(record["app_id"]) == record["app_id"], "invalid binding app ID")
    require(type(record["input_digest"]) is str and SHA256.fullmatch(record["input_digest"]), "invalid binding digest")
    require(record["status"] in ("binding-running", "binding-failed", "binding-verified") and
            record["preparation_complete"] is False, "invalid binding status")
    completed = record["completed_files"]
    require(type(completed) is list and len(completed) <= len(FILES) and
            all(name in FILES for name in completed) and len(completed) == len(set(completed)), "invalid binding progress")


def apply_binding(plan, steam, settings, store, ready):
    """Internal only: caller holds tool/prefix locks and supplies real readiness checks.

    ready must recheck target registration, dependency postconditions, trusted payload and stopped processes.
    No CLI readiness flags, automatic rollback or full-sync invocation are available.
    """
    steam, settings = safe_path(steam), safe_path(settings)
    store._guard()
    require(store._held_target == hashlib.sha256(str(safe_path(steam / "steamapps/compatdata" / plan.registration_id)).encode()).hexdigest(),
            "binding requires the target preparation lock")
    require(callable(ready), "trusted readiness callback required")
    def check_ready():
        checks = ready()
        fields(checks, ("target", "dependencies", "payload", "stopped"))
        require(all(value is True for value in checks.values()), "binding prerequisites not verified")
    check_ready()
    for root in (steam, settings):
        require(not (store.root == root or store.root.is_relative_to(root) or root.is_relative_to(store.root)), "backup root overlaps settings")
    with droiddeck_lock(settings) as check_lock:
        fresh = plan_binding(steam, settings, plan.registration_id, plan.directory)
        require(fresh.digest == plan.digest and fresh.after == plan.after and fresh.before == plan.before
                and fresh.paths == plan.paths and fresh.tool_hashes == plan.tool_hashes, "binding plan changed")
        expected = dict(plan.before)

        def guard():
            store._guard()
            check_lock()
            check_ready()
            require(all(_raw(plan.paths[name]) == raw for name, raw in expected.items()), "binding inputs changed")
            _, hashes = registered_tool(steam, plan.directory)
            require(hashes == plan.tool_hashes, "tool changed during binding")

        guard()
        run_id = "binding-" + secrets.token_hex(16)
        result = {"schema_version": 1, "tool_version": VERSION, "binding_id": run_id,
                  "app_id": plan.registration_id, "input_digest": plan.digest, "status": "binding-running",
                  "completed_files": [], "preparation_complete": False}
        record_hash = store.write_record("bindings", run_id + ".json", result)
        try:
            with store.directory(("backups",), create=True) as fd:
                store._capacity(fd)
                os.mkdir(run_id, mode=0o700, dir_fd=fd)
                os.fsync(fd)
            with store.directory(("backups", run_id)) as fd:
                for name, raw in plan.before.items():
                    if raw is not None:
                        with store._new(fd, name + ".backup") as stream:
                            stream.write(raw)
                            stream.flush()
                            os.fsync(stream.fileno())
                os.fsync(fd)
            for name in FILES:
                if expected[name] == plan.after[name]:
                    continue
                def applied(name=name):
                    result["completed_files"].append(name)
                    expected[name] = plan.after[name]
                _atomic(plan.paths[name], plan.after[name], expected[name], guard, applied)
                record_hash = store.write_record("bindings", run_id + ".json", result, record_hash)
            guard()
            result["status"] = "binding-verified"
            store.write_record("bindings", run_id + ".json", result, record_hash)
        except (OSError, Invalid):
            result["status"] = "binding-failed"
            store.write_record("bindings", run_id + ".json", result, record_hash)
            raise
        return result
