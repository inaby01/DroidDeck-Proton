"""Handler ``prefix-dll``: place one declared x86 DLL into an initialized game prefix's syswow64.

The DLL is copied from the operator's asset folder only when its size, SHA-256 and PE
architecture match the recipe's asset declaration. Nothing else is changed: no registry,
no DLL overrides, no registration, no overwrite, replacement or removal of an existing
file, no game folder change, no Wine. A name that the selected Proton ships as a builtin
is refused (a native copy would hide the builtin).

The asset is read into memory and checked first. The destination name is then created
with ``O_EXCL`` (an existing name is never replaced), its device/inode is recorded before
any byte is written, and the content is written and read back through the same
descriptor. Nothing is ever removed or renamed. A partly written file (``created``) left
by an interrupted run is never touched again: inode numbers can be reused across runs, so
it cannot be proven to be this tool's file; the run stops and the operator recovers it.
Every step works relative to one opened ``syswow64`` whose identity is part of the plan.
(0.29.0 named an ``O_TMPFILE`` file through ``/proc/self/fd``; that failed on the device
with errno 95.)

``present-verified`` means a match with the declaration; whether a game loads the file is
only observable at launch.
"""

import hashlib
import io
import os
import re
import secrets
import signal
import stat
import time
from dataclasses import dataclass, field

from preparation_assets import (
    asset_blockers,
    digest_json,
    inspect_assets_from_folder,
    measure_stream,
    pe_machine,
    source_path,
    validate_manifest,
)
from preparation_common import (
    VERSION,
    Invalid,
    app_id,
    fields,
    identifier,
    regular_open,
    require,
    revision,
    safe_path,
    string,
)

HANDLER = "prefix-dll"
RECORDS = "prefix-dlls"
SCOPE = "registered-game-prefix-dll"
ID_PREFIX = "prefixdll-"
DESTINATION = "syswow64"
# Wine places this x86 builtin in every 64-bit prefix's syswow64.
REFERENCE = "kernel32.dll"
NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,59}\.(?i:dll)\Z", re.ASCII)
LIMIT = 64 * 1024 * 1024
RESERVE = 16 * 1024 * 1024
# ``linked`` is read from 0.29.0 records only.
PHASES = ("planned", "created", "linked", "present-verified", "failed")
IDENTIFIED = ("created", "linked", "present-verified")
BUILTIN_ROOTS = ("files/lib/wine/", "files/share/default_pfx")
WINE_MARKERS = (b"Wine builtin DLL", b"Wine placeholder DLL")


def validate_prefix_dll_recipe(item):
    """Recipe fields of a ready or blocked ``prefix-dll`` dependency."""
    fields(item, ("dependency_id", "revision", "handler", "status", "reason", "asset", "destination"))
    identifier(item["dependency_id"])
    revision(item["revision"])
    require(item["handler"] == HANDLER and item["status"] in ("ready", "blocked"), "invalid prefix DLL recipe")
    string(item["reason"])
    require(item["destination"] == DESTINATION, "prefix DLL destination must be syswow64")
    spec = item["asset"]
    validate_manifest({"schema_version": 1, "assets": [spec]})
    require(type(spec["filename"]) is str and NAME.fullmatch(spec["filename"]) is not None, "invalid prefix DLL file name")
    require(spec["format"] == "pe" and spec["pe_machine"] == "x86", "prefix DLL must be an x86 PE")
    require(spec["expected_size"] is None or spec["expected_size"] <= LIMIT, "prefix DLL larger than the copy limit")
    if item["status"] == "ready":
        # Static declaration blockers (provenance, terms, unknown hash or size) keep a recipe from being ready.
        declared = {"sha256": spec["expected_sha256"], "size": spec["expected_size"], "pe_machine": spec["pe_machine"]}
        require(not asset_blockers(spec, declared), "prefix DLL asset is not reviewed for use")
    return item


def target_name(item):
    return item["asset"]["filename"].lower()


def system_directory(compatdata):
    compatdata = safe_path(compatdata)
    return safe_path(compatdata / "pfx/drive_c/windows" / DESTINATION, compatdata)


def builtin_names(inventory):
    """Basenames (lower case) the verified Proton payload ships as builtins or prefix templates."""
    return {name.rsplit("/", 1)[-1].lower() for name, entry in inventory.entries.items()
            if entry["kind"] in ("file", "hardlink", "symlink") and name.startswith(BUILTIN_ROOTS)}


def _identity(info):
    return {"device": info.st_dev, "inode": info.st_ino}


def _matches(fd, name):
    return sorted(entry for entry in os.listdir(fd) if entry.isascii() and entry.lower() == name)


def _pe_of(path_or_fd, dir_fd=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path_or_fd, flags, dir_fd=dir_fd)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= LIMIT, "reference is not a bounded regular file")
        return pe_machine(stream, info.st_size)


def check_layout(fd, directory, inventory, tool):
    """The x86 system directory of a 64-bit prefix: its reference builtin is x86.

    It is either a symbolic link to the verified payload's i386 builtin (Proton links the
    prefix builtins to its own files), or an x86 regular file. ``system32`` is not used: on
    ARM64 devices it holds both ARM64 and x64 images.
    """
    member = "files/lib/wine/i386-windows/" + REFERENCE
    info = os.stat(REFERENCE, dir_fd=fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        entry = inventory.entries.get(member)
        require(entry is not None and entry["kind"] in ("file", "hardlink"), "payload lacks the reference builtin")
        # Compared by identity: Proton may write the link with another spelling of the tool path.
        expected = safe_path(tool / member, safe_path(tool))
        resolved = os.stat(REFERENCE, dir_fd=fd, follow_symlinks=True)
        require(stat.S_ISREG(resolved.st_mode) and _identity(resolved) == _identity(os.stat(expected, follow_symlinks=False)),
                "reference builtin links outside the selected Proton")
        require(_pe_of(expected) == "x86", "reference builtin is not x86")
        return "payload-link"
    require(stat.S_ISREG(info.st_mode), "reference builtin is not a regular file or payload link")
    require(_pe_of(REFERENCE, fd) == "x86", "reference builtin is not x86")
    return "regular-file"


def examine(fd, name):
    """Raw facts about the destination name in an opened directory (read-only)."""
    matches = _matches(fd, name)
    if not matches:
        return {"kind": "none"}
    if len(matches) > 1:
        return {"kind": "multiple", "names": matches}
    info = os.stat(matches[0], dir_fd=fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        return {"kind": "symlink", "name": matches[0]}
    if not stat.S_ISREG(info.st_mode):
        return {"kind": "other", "name": matches[0]}
    if info.st_size > LIMIT:
        return {"kind": "file", "name": matches[0], "identity": _identity(info), "links": info.st_nlink, "measured": None}
    descriptor = os.open(matches[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "destination changed during inspection")
        head = stream.read(0x80)
        try:
            measured = measure_stream(stream, LIMIT, "pe")
        except Invalid:
            measured = None
    marker = any(mark in head[0x40:0x80] for mark in WINE_MARKERS)
    return {"kind": "file", "name": matches[0], "identity": _identity(opened), "links": opened.st_nlink,
            "size": opened.st_size, "measured": measured, "wine_marker": marker}


def _read_all(fd, size):
    data = bytearray()
    while len(data) < size:
        chunk = os.pread(fd, min(1024 * 1024, size - len(data)), len(data))
        require(chunk, "file shrank while reading")
        data += chunk
    require(not os.pread(fd, 1, size), "file grew while reading")
    return bytes(data)


def _write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.pwrite(fd, data[offset:offset + 1024 * 1024], offset)
        require(written > 0, "short write")
        offset += written


def load_asset(root, spec):
    """The asset bytes, read once and checked against the declaration (before anything is created)."""
    with regular_open(source_path(root, spec), LIMIT) as source:
        size = os.fstat(source.fileno()).st_size
        data = source.read(LIMIT + 1)
    # The SHA-256 below is the guarantee. Timestamps are not compared: on Android's shared storage
    # they were seen to change while a copied file was read (menu 12, 2026-11-21).
    require(len(data) == size, "asset changed while reading")
    machine = pe_machine(io.BytesIO(data), len(data))
    require((len(data), hashlib.sha256(data).hexdigest(), machine) ==
            (spec["expected_size"], spec["expected_sha256"], spec["pe_machine"]), "asset differs from its declaration")
    return data


def matches_asset(facts, spec):
    measured = facts.get("measured")
    return (measured is not None and not facts.get("wine_marker") and
            (measured["size"], measured["sha256"], measured["pe_machine"]) ==
            (spec["expected_size"], spec["expected_sha256"], spec["pe_machine"]))


def state_of(facts, spec):
    """Design 5: absent / present-verified / incompatible from the destination facts."""
    if facts["kind"] == "none":
        return {"state": "absent"}
    reasons = {"multiple": "several files differ only in case", "symlink": "symbolic link", "other": "not a regular file"}
    if facts["kind"] in reasons:
        return {"state": "incompatible", "reason": reasons[facts["kind"]]}
    if facts.get("wine_marker"):
        return {"state": "incompatible", "reason": "Wine builtin or placeholder file"}
    if not matches_asset(facts, spec):
        return {"state": "incompatible", "reason": "size, hash or architecture differs"}
    if facts["links"] != 1:
        return {"state": "incompatible", "reason": "several links"}
    return {"state": "present-verified"}


def inspect_prefix_dll(compatdata, item, inventory, tool):
    """Read-only state of one ``prefix-dll`` dependency (the caller observes the process view)."""
    name = target_name(item)
    try:
        directory = system_directory(compatdata)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except (OSError, Invalid) as error:
        return {"state": "incompatible", "reason": "syswow64 unavailable: " + type(error).__name__}
    try:
        info = os.fstat(fd)
        try:
            layout = check_layout(fd, directory, inventory, tool)
        except (OSError, Invalid) as error:
            # Only our own messages; an OSError text may carry local paths.
            detail = str(error) if isinstance(error, Invalid) else type(error).__name__
            return {"state": "incompatible", "reason": "x86 system directory not confirmed: " + detail}
        if name in builtin_names(inventory):
            return {"state": "incompatible", "reason": "the selected Proton ships a builtin of this name"}
        try:
            facts = examine(fd, name)
        except (OSError, Invalid) as error:
            return {"state": "uninspected", "reason": "destination unreadable: " + type(error).__name__}
        return {**state_of(facts, item["asset"]), "directory": _identity(info), "layout": layout}
    finally:
        os.close(fd)


def _record_id(value):
    require(type(value) is str and value.startswith(ID_PREFIX) and len(value) == len(ID_PREFIX) + 32 and
            all(c in "0123456789abcdef" for c in value[len(ID_PREFIX):]), "invalid prefix DLL record ID")
    return value


def _identity_value(value):
    fields(value, ("device", "inode"))
    require(all(type(value[key]) is int and value[key] >= 0 for key in ("device", "inode")), "invalid identity")
    return value


def validate_prefix_dll_record(record):
    fields(record, ("schema_version", "tool_version", "scope", "record_id", "created_ns", "app_id", "trial_id",
                    "dependency_id", "recipe_revision", "recipe_digest", "asset_sha256", "input_digest", "destination",
                    "name", "directory", "file_identity", "phase", "resumed_from", "error", "preparation_complete"))
    require(record["schema_version"] == 1 and type(record["tool_version"]) is str and record["scope"] == SCOPE,
            "invalid prefix DLL record")
    _record_id(record["record_id"])
    require(type(record["created_ns"]) is int and record["created_ns"] > 0, "invalid record time")
    require(app_id(record["app_id"]) == record["app_id"], "invalid record app ID")
    string(record["trial_id"])
    identifier(record["dependency_id"])
    revision(record["recipe_revision"])
    for key in ("recipe_digest", "asset_sha256", "input_digest"):
        require(type(record[key]) is str and re.fullmatch(r"[0-9a-f]{64}", record[key]), "invalid record digest")
    require(record["destination"] == DESTINATION and type(record["name"]) is str and NAME.fullmatch(record["name"]) and
            record["name"] == record["name"].lower(), "invalid record destination")
    _identity_value(record["directory"])
    require(record["phase"] in PHASES, "invalid record phase")
    # The created file's identity is recorded from its creation on; a failure means nothing was created.
    require((record["file_identity"] is not None) == (record["phase"] in IDENTIFIED), "file identity must follow creation")
    if record["file_identity"] is not None:
        _identity_value(record["file_identity"])
    if record["resumed_from"] is not None:
        _record_id(record["resumed_from"])
    if record["error"] is not None:
        fields(record["error"], ("check", "error_class", "errno"))
    require(record["preparation_complete"] is False, "a DLL record cannot grant full readiness")
    return record


def history(store, key, trial_id, dependency_id, name):
    """Records of this DLL target (oldest first) and the count of unreadable records of any target."""
    listed = store.inventory()["prefix_dlls"]
    invalid = sum(item.get("status") == "invalid" for item in listed)
    items = [item for item in listed if item.get("status") != "invalid" and
             (item["app_id"], item["trial_id"], item["dependency_id"], item["name"]) == (key, trial_id, dependency_id, name)]
    return sorted(items, key=lambda item: item["created_ns"]), invalid


def resume_action(latest, invalid, directory, facts, spec):
    """Design 7: (action, reason), action install / skip / stop.

    An interruption leaves nothing, a recorded partial file (``created``) or the finished
    file. A destination matching the declaration is accepted whatever the phase. A partial
    file is never written again (it cannot be proven to be this tool's file across runs).
    """
    if invalid:
        return "stop", "invalid-prefix-dll-record-present"
    if latest is not None and latest["directory"] != directory:
        return "stop", "syswow64-replaced-since-previous-record"
    found = state_of(facts, spec)
    current = found["state"] + (":" + found["reason"] if "reason" in found else "")
    phase = latest and latest["phase"]
    if current == "present-verified":
        return "skip", None if phase in (None, "present-verified") else "placed-before-the-record-was-completed"
    if current == "absent" and phase in (None, "planned", "failed", "created"):
        return "install", None
    if phase == "created":
        return "stop", "partial-file-of-the-previous-run-operator-recovery:" + current
    return "stop", "prefix-dll-state-" + current + ("" if phase is None else " after " + phase)


@dataclass(frozen=True)
class PrefixDllPlan:
    digest: str
    recheck: object = field(repr=False)
    item: dict = field(repr=False)
    asset_root: object = field(repr=False)
    measured: object = field(repr=False)
    state: dict = field(repr=False)
    directory: dict = field(repr=False)
    latest: object = field(repr=False)
    facts: dict = field(repr=False)
    action: str
    reason: object
    capacity: dict = field(repr=False)
    blockers: tuple

    def summary(self):
        spec = self.item["asset"]
        return {"scope": SCOPE, "input_digest": self.digest, "trial_id": self.recheck.record["trial_id"],
                "app_id": self.recheck.record["app_id"], "dependency_id": self.item["dependency_id"],
                "recipe_revision": self.item["revision"], "destination": DESTINATION + "/" + target_name(self.item),
                "asset": {"filename": spec["filename"], "sha256": spec["expected_sha256"], "size": spec["expected_size"],
                          "measured_sha256": self.measured and self.measured["sha256"]},
                "state": self.state,
                "destination_file": {key: self.facts[key] for key in ("kind", "name", "size", "identity", "links")
                                     if key in self.facts},
                "previous_record": self.latest and {k: self.latest[k] for k in ("record_id", "phase", "file_identity", "error")},
                "action": self.action, "reason": self.reason, "capacity": self.capacity, "blockers": list(self.blockers),
                "registry_changed": False, "dll_overrides_changed": False, "overwrite": False, "wine_started": False,
                "preparation_complete": False}


def plan_prefix_dll(*, record, record_sha256, item, config, directory, renderer, source, games, steam, settings, home,
                    environment, runtime_root, stop_check, inventory=None):
    """Read-only plan for one ``prefix-dll`` dependency of an initialized game prefix.

    The process view is observed before and after the inspection; an unclear view makes the
    state ``uninspected`` (design 5), which stops.
    """
    from preparation_dependency_install import _capacity, _tool_directory
    from preparation_game_prefix import RECORDS as GAME_RECORDS
    from preparation_processes import ProcessStopCheck
    from preparation_recheck import plan_recheck
    from preparation_store import PrivateStore
    validate_prefix_dll_recipe(item)
    require(item["status"] == "ready", "prefix DLL recipe is blocked")
    base = plan_recheck(record=record, record_sha256=record_sha256, config=config, directory=directory, renderer=renderer,
                        source=source, games=games, steam=steam, settings=settings, home=home, environment=environment,
                        runtime_root=runtime_root, records=GAME_RECORDS, inventory=inventory)
    spec = item["asset"]
    directory = safe_path(directory)
    report = inspect_assets_from_folder({"schema_version": 1, "assets": [spec]}, directory)[0]
    blockers = ["asset:" + reason for reason in report["blockers"]]
    require(isinstance(stop_check, ProcessStopCheck) and stop_check.compatdata == base.compatdata,
            "matching process observation required")
    if stop_check.check()["clear_in_view"]:
        state = inspect_prefix_dll(base.compatdata, item, base.inventory, _tool_directory(base))
        if not stop_check.check()["clear_in_view"]:
            state = {"state": "uninspected", "reason": "concurrent-process-observed"}
    else:
        state = {"state": "uninspected", "reason": "target-process-view-not-clear"}
    name = target_name(item)
    latest, invalid, facts = None, 0, {"kind": "none"}
    identity = state.get("directory")
    if identity is None or state["state"] == "uninspected":
        action, reason = "stop", "prefix-dll-state-" + state["state"] + ":" + str(state.get("reason"))
        blockers.append(reason)
    else:
        with PrivateStore(base.store_root) as store:
            listed, invalid = history(store, record["app_id"], record["trial_id"], item["dependency_id"], name)
            if listed:
                latest, _ = store.read_record(RECORDS, listed[-1]["record_id"] + ".json")
                validate_prefix_dll_record(latest)
        if latest is not None and (latest["recipe_digest"], latest["asset_sha256"]) != (digest_json(item), spec["expected_sha256"]):
            action, reason = "stop", "previous-record-for-another-recipe-or-asset"
        else:
            fd = os.open(system_directory(base.compatdata), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(_identity(os.fstat(fd)) == identity, "syswow64 changed during planning")
                facts = examine(fd, name)
            finally:
                os.close(fd)
            # The common conditions (design 7 step 1: view, layout, builtin names) were checked above.
            action, reason = resume_action(latest, invalid, identity, facts, spec)
        if action == "stop" and reason not in blockers:
            blockers.append(reason if reason.startswith("prefix-dll") else "prefix-dll-" + reason)
    capacity = {**_capacity(((base.compatdata, (spec["expected_size"] or 0) + RESERVE),)), "reserve_bytes": RESERVE}
    if action != "skip" and not capacity["sufficient"]:
        blockers.append("insufficient-capacity")
    signature = {"version": VERSION, "scope": SCOPE, "recheck_plan": base.digest, "recipe": digest_json(item),
                 "measured": report["measured"], "state": digest_json(state), "directory": identity,
                 "latest": latest and digest_json(latest), "facts": digest_json(facts),
                 "action": action, "capacity_sufficient": capacity["sufficient"], "blockers": sorted(blockers)}
    return PrefixDllPlan(digest_json(signature), base, item, directory, report["measured"], state, identity, latest,
                         facts, action, reason, capacity, tuple(sorted(blockers)))


class PrefixDllSession:
    """One guarded copy under the caller's private and DroidDeck locks."""

    def __init__(self, plan, store, refresh, confirmation, stop_check):
        from preparation_recheck import RecheckSession
        require(isinstance(plan, PrefixDllPlan), "trusted prefix DLL plan required")
        self.plan, self.store, self.refresh, self.confirmation, self.stop = plan, store, refresh, confirmation, stop_check
        self.base_guard = RecheckSession(plan.recheck, store, None, None, stop_check)
        # ``step`` names the operation in progress, so a failure records which one it was.
        self.hash, self.step = None, "prepare"
        self.made = False  # whether this run created the destination (known from the descriptor, not the phase)
        p = plan.recheck
        self.record = {"schema_version": 1, "tool_version": VERSION, "scope": SCOPE,
                       "record_id": ID_PREFIX + secrets.token_hex(16), "created_ns": time.time_ns(),
                       "app_id": p.record["app_id"], "trial_id": p.record["trial_id"],
                       "dependency_id": plan.item["dependency_id"], "recipe_revision": plan.item["revision"],
                       "recipe_digest": digest_json(plan.item), "asset_sha256": plan.item["asset"]["expected_sha256"],
                       "input_digest": plan.digest, "destination": DESTINATION, "name": target_name(plan.item),
                       "directory": dict(plan.directory), "file_identity": None, "phase": "planned",
                       "resumed_from": plan.latest and plan.latest["record_id"], "error": None,
                       "preparation_complete": False}

    def _save(self):
        validate_prefix_dll_record(self.record)
        self.hash = self.store.write_record(RECORDS, self.record["record_id"] + ".json", self.record, expected_hash=self.hash)
        return dict(self.record)

    def _guard(self):
        # Locks, origin record, payload and tool tree, runtime, registration, prefix identity and version, settings.
        self.base_guard._guard()
        require(self.stop.check()["clear_in_view"], "target process view not clear")

    def _directory(self, fd):
        """The open directory, the current path and the plan name the same syswow64."""
        path = system_directory(self.plan.recheck.compatdata)
        current = os.stat(path, follow_symlinks=False)
        require(stat.S_ISDIR(current.st_mode) and _identity(current) == _identity(os.fstat(fd)) == self.plan.directory,
                "syswow64 replaced")

    def apply(self):
        p = self.plan
        require(self.hash is None and self.confirmation == p.digest, "exact unused confirmation required")
        require(p.action == "install", "prefix DLL plan writes nothing")
        require(not p.blockers, "prefix DLL plan blocked")
        # The plan digest includes the latest record: compare it before this run writes its own record.
        # After that, the running guard (prefix, payload, settings, registration, process view, directory) applies.
        require(self.refresh().digest == p.digest, "prefix DLL plan changed")
        self._guard()
        fd = os.open(system_directory(p.recheck.compatdata), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self._directory(fd)
            return self._install(fd)
        finally:
            os.close(fd)

    def _verify(self, fd, data):
        """Content and identity through the descriptor that was written."""
        self.step = "fsync-file"
        os.fsync(fd)
        self.step = "read-back"
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and _identity(info) == self.record["file_identity"],
                "written file is not the recorded file")
        require(info.st_size == len(data) and _read_all(fd, info.st_size) == data, "written file differs from the asset")

    def _install(self, fd):
        name = self.record["name"]
        self._save()  # planned, before anything is created
        created = None
        try:
            self.step = "read-asset"
            data = load_asset(self.plan.asset_root, self.plan.item["asset"])
            self.step = "create"
            self._guard()
            self._directory(fd)
            require(not _matches(fd, name), "destination appeared")
            blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT})
            try:
                created = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
                self.made = True
                self.step = "record-created"
                self.record.update(phase="created", file_identity=_identity(os.fstat(created)))
                self._save()  # identity before any byte, whatever the checks below say
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            self.step = "identity"
            info = os.fstat(created)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0, "created file is not a new file")
            self.step = "write"
            _write_all(created, data)
            self._verify(created, data)
            self.step = "fsync-directory"
            os.fsync(fd)
        except (OSError, ValueError, TypeError, KeyError) as error:
            return self._fail(error)
        finally:
            if created is not None:
                os.close(created)
        return self._post(fd)

    def _post(self, fd):
        try:
            self.step = "post-inspection"
            self._guard()
            self._directory(fd)
            from preparation_dependency_install import _tool_directory
            p = self.plan.recheck
            state = inspect_prefix_dll(p.compatdata, self.plan.item, p.inventory, _tool_directory(p))
            require(state.get("directory") in (None, self.plan.directory), "syswow64 replaced")
            placed = os.stat(self.record["name"], dir_fd=fd, follow_symlinks=False)
            require(_identity(placed) == self.record["file_identity"], "destination is not the recorded file")
            require(self.stop.check()["clear_in_view"], "target process view not clear")
            require(state["state"] == "present-verified", "placed DLL not verified: " + state.get("reason", state["state"]))
        except (OSError, ValueError, TypeError, KeyError) as error:
            return self._fail(error)
        # Outside the failure path: a failed final save is not recorded as an error of a verified file.
        self.record["phase"] = "present-verified"
        return self._save()

    def _fail(self, error):
        # Nothing is removed. Only a run that created nothing is ``failed``. If the destination was created
        # but its identity could not be recorded, the phase stays ``planned``: the empty file stops the next run.
        if self.record["phase"] == "planned" and not self.made:
            self.record["phase"] = "failed"
        self.record["error"] = {"check": self.step, "error_class": type(error).__name__,
                                "errno": getattr(error, "errno", None)}
        return self._save()
