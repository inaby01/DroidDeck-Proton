"""The guarded initialization session shared by registered-game new prefixes.

Game prefixes (preparation_game_prefix) subclass the session; the dedicated probe trial was
removed in 1.0.1 and its records are no longer read.
"""

import hashlib
import os
import secrets
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from preparation_binding import _raw
from preparation_common import (
    SHA256,
    VERSION,
    app_id,
    checked,
    fields,
    require,
    safe_path,
)
from preparation_execution import (
    OPERATIONS,
    _aliases,
    _identities,
    _prefix,
    plan_launch,
    require_no_bytecode_cache,
)
from preparation_payload import runtime_writes, verify_fex_runtime_tree
from preparation_processes import ProcessStopCheck
from preparation_static_placement import _private_xalia_context

RESERVE = 1024**3


@dataclass(frozen=True)
class TrialPlan:
    digest: str
    placement: object = field(repr=False)
    home: object = field(repr=False)
    work: object = field(repr=False)
    private_home: object = field(repr=False)
    compatdata: object = field(repr=False)
    baseline_bytes: int

    def summary(self):
        return {"input_digest": self.digest, "app_id": self.placement.installation.target.registration_id,
                "command": list(OPERATIONS["initialize"]), "prefix": str(self.compatdata),
                "work": str(self.work), "home": str(self.private_home), "baseline_bytes": self.baseline_bytes,
                "growth_reserve_bytes": RESERVE, "growth_upper_bound_known": False,
                "process_scope": "same-proc-directory-owner-as-self", "device_namespace_verified": False,
                "runtime_execution_verified": False, "binding_written": False, "dependencies_installed": False,
                "preparation_complete": False, "execution_authorized": False, "writes": []}


def _live_runtime(installation):
    require(installation.runtime.root == Path("/") and installation.runtime.view == "current-root",
            "live current-root runtime required for trial")


def _new_private(path, anchor):
    """Create fixed private paths through owned, non-writable, no-follow ancestors."""
    path, anchor = safe_path(path), safe_path(anchor)
    require(path.is_relative_to(anchor) and path != anchor, "private path outside home")
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path.relative_to(anchor).parts
        for index, name in enumerate(parts):
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "unsafe private ancestor")
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                require(index != len(parts) - 1, "private trial leaf already exists")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "private trial leaf not owned 0700")
        current = safe_path(path).stat()
        require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), "private trial path replaced")
    finally:
        os.close(fd)


def validate_trial_record(record, scope, id_prefix):
    """A registered-game prefix initialization record (``scope``, ``id_prefix`` of preparation_game_prefix)."""
    fields(record, ("schema_version", "tool_version", "scope", "trial_id", "app_id", "input_digest", "status", "phase",
                    "exit_code", "prefix_version_sha256", "runtime_execution_verified", "device_namespace_verified",
                    "preparation_complete"),
           ("error", "stop_observation", "settings_identity_unchanged", "profile", "prefix_identity",
            "wineprefix_identity", "vc_runtime_fingerprint"))
    if "vc_runtime_fingerprint" in record:
        from preparation_vc_record import validate_initial
        validate_initial(record["vc_runtime_fingerprint"])
    require("profile" in record, "game records require a profile")
    fields(record["profile"], ("profile_id", "revision", "profile_digest", "exe_sha256", "exe_size", "selection",
                               "exe_path_sha256", "title_sha256"))
    require(all(type(record["profile"][name]) is str and SHA256.fullmatch(record["profile"][name]) for name in
                ("exe_sha256", "profile_digest", "exe_path_sha256", "title_sha256")) and
            type(record["profile"]["exe_size"]) is int and record["profile"]["exe_size"] > 0 and
            record["profile"]["selection"] in ("operator-selected-unverified", "profile-hash-matched"),
            "invalid game profile binding")
    # The created prefix directory is recorded before spawn and is required from then on.
    require(("prefix_identity" in record) == (record["phase"] in ("spawn", "waiting", "deadline-child-not-killed",
                                                                  "post-checks")), "game prefix identity inconsistent")
    # The WINEPREFIX identity is recorded with a successful initialization only.
    require(("wineprefix_identity" in record) == (record["status"] == "initialized-unverified"),
            "game Wine prefix identity inconsistent")
    for name in ("prefix_identity", "wineprefix_identity"):
        if name in record:
            fields(record[name], ("device", "inode"))
            require(all(type(record[name][key]) is int and record[name][key] >= 0 for key in ("device", "inode")),
                    "invalid game prefix identity")
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and record["scope"] == scope,
            "unsupported trial record")
    require(type(record["tool_version"]) is str and len(record["tool_version"]) <= 64, "invalid trial version")
    key = record["trial_id"]
    require(type(key) is str and key.startswith(id_prefix) and len(key) == len(id_prefix) + 32 and
            all(c in "0123456789abcdef" for c in key[len(id_prefix):]), "invalid trial ID")
    require(app_id(record["app_id"]) == record["app_id"], "invalid trial app ID")
    require(type(record["input_digest"]) is str and SHA256.fullmatch(record["input_digest"]), "invalid trial digest")
    require(record["status"] in ("preparing", "running", "needs-user", "failed", "initialized-unverified"), "invalid trial status")
    require(record["phase"] in ("before-writes", "private-directories", "prefix-create", "spawn", "waiting",
                                "deadline-child-not-killed", "post-checks"), "invalid trial phase")
    require(record["exit_code"] is None or type(record["exit_code"]) is int, "invalid trial exit code")
    version = record["prefix_version_sha256"]
    require(version is None or type(version) is str and SHA256.fullmatch(version), "invalid trial prefix digest")
    require(all(record[name] is False for name in ("runtime_execution_verified", "device_namespace_verified", "preparation_complete")),
            "trial cannot assert full readiness")
    return record


class TrialSession:
    """Caller holds global, target and cooperative settings locks until handoff.

    Timeout never kills Wine. An explicit handoff preserves needs-user state and
    all created paths. Existing trials are never adopted or automatically retried.
    """

    # The subclass (preparation_game_prefix.GamePrefixSession) names its scope and journal.
    scope = records = id_prefix = None

    def __init__(self, plan, store, refresh, confirmed_digest, stop_check):
        self.plan, self.store, self.refresh = plan, store, refresh
        self.confirmed_digest, self.stop_check = confirmed_digest, stop_check
        self.process = None
        self.hash = None
        self.settings_identity = None
        self.record = {"schema_version": 1, "tool_version": VERSION, "scope": self.scope,
            "trial_id": self.id_prefix + secrets.token_hex(16), "app_id": plan.placement.installation.target.registration_id,
            "input_digest": plan.digest, "status": "preparing", "phase": "before-writes", "exit_code": None,
            "prefix_version_sha256": None, "runtime_execution_verified": False, "device_namespace_verified": False,
            "preparation_complete": False}

    def _prefix_created(self):
        """Hook for scopes that bind later steps to the created prefix directory."""

    def _initialized(self):
        """Hook for scopes that bind later steps to the initialized WINEPREFIX."""

    def _save(self):
        validate_trial_record(self.record, self.scope, self.id_prefix)
        self.hash = self.store.write_record(self.records, self.record["trial_id"] + ".json", self.record, expected_hash=self.hash)
        return dict(self.record)

    def _settings_identity(self):
        p = self.plan.placement
        paths = {"games": p.settings / "games.json", "state": p.settings / "state.json",
                 "config": p.installation.target.steam / "config/config.vdf"}
        result = {}
        for name, path in paths.items():
            raw = _raw(path)
            result[name] = None if raw is None else hashlib.sha256(raw).hexdigest()
        return result

    def _guard(self):
        p = self.plan
        self.store._guard()
        require(self.store.root == p.placement.store_root and self.store._held_target ==
                hashlib.sha256(str(p.compatdata).encode()).hexdigest(), "matching trial locks required")
        require(isinstance(self.stop_check, ProcessStopCheck) and self.stop_check.compatdata == p.compatdata,
                "matching real process check required")
        installation = p.placement.installation
        _live_runtime(installation)
        installation.target.verify()
        installation.runtime.verify()
        policy = _private_xalia_context(installation, p.placement.review)
        if policy is not None:
            policy.guard()
        summary = installation.summary()
        # The template and caches the plan accepted must still be the ones used right before spawn.
        require(runtime_writes(verify_fex_runtime_tree(safe_path(summary["destination"]), installation.inventory,
                                                       installation.customization.overlays)) == summary.get("tool_runtime_writes"),
                "tool runtime writes changed")
        require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
        _aliases(installation.target.steam, installation.target.registration_id)
        if self.settings_identity is not None:
            require(self._settings_identity() == self.settings_identity, "settings changed during trial")

    def start(self):
        require(self.process is None and self.hash is None and isinstance(self.plan, TrialPlan), "trial already started")
        require(self.confirmed_digest == self.plan.digest, "exact trial confirmation required")
        require(self.refresh().digest == self.plan.digest, "trial inputs changed")
        self._guard()
        require(self.stop_check.check()["clear_in_view"], "target process view not clear")
        p = self.plan
        self.settings_identity = self._settings_identity()
        self._save()
        try:
            self.record["phase"] = "private-directories"
            self._save()
            _new_private(p.work, p.home)
            _new_private(p.private_home, p.home)
            installation = p.placement.installation
            entries = {**installation.inventory.entries, **installation.customization.overlays}
            hashes = {name: entries[name]["sha256"] if name in entries else None for name in ("proton", "version", "user_settings.py")}
            self.launch = checked("trial-launch-plan", plan_launch, tool=safe_path(installation.summary()["destination"]),
                steam=installation.target.steam, registration_id=installation.target.registration_id, install=installation.target.exe.parent,
                work=p.work, home=p.private_home, runtime_environment=installation.runtime.environment, expected_hashes=hashes,
                payload_inventory=installation.inventory, payload_overlays=installation.customization.overlays,
                target_pin=installation.target, runtime_plan=installation.runtime)
            self._guard()
            require(self.stop_check.check()["clear_in_view"], "target process view changed")
            require(not os.path.lexists(p.compatdata), "trial prefix appeared")
            self.record["phase"] = "prefix-create"
            self._save()
            p.compatdata.mkdir(mode=0o700)
            self._prefix_created()
            self.record.update(status="running", phase="spawn")
            self._save()
            self._guard()
            require_no_bytecode_cache(self.launch)
            self.process = subprocess.Popen(self.launch.argv, cwd=p.work, env=self.launch.environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                shell=False, close_fds=True, start_new_session=True)
            self.record["phase"] = "waiting"
            self._save()
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.record.update(status="needs-user" if self.process is not None else "failed",
                error={"check": getattr(error, "preparation_check", self.record["phase"]),
                       "error_class": type(error).__name__, "errno": getattr(error, "errno", None)})
            self._save()
            raise
        return self

    def _vc_fingerprint(self):
        """Design: inherited VC record 3. Right after initialization; never raises."""
        from preparation_vc_record import capture_initial
        try:
            writes = self.plan.placement.installation.summary().get("tool_runtime_writes") or {}
            tail = (writes.get("droiddeck_redist") or {}).get("registry_tail_sha256")
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            return {"state": "unreadable", "error_class": type(error).__name__}
        return capture_initial(self.plan.compatdata, tail)

    def wait(self, timeout=30):
        require(type(timeout) is int and 1 <= timeout <= 120 and self.process is not None, "bounded live trial wait required")
        if self.record["status"] in ("failed", "initialized-unverified"):
            return dict(self.record)
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.record.update(status="needs-user", phase="deadline-child-not-killed")
            return self._save()
        self.record.update(exit_code=code, phase="post-checks")
        try:
            self.record["settings_identity_unchanged"] = self._settings_identity() == self.settings_identity
            require(self.record["settings_identity_unchanged"], "settings changed during trial")
            observation = self.stop_check.check()
            # Wine services can outlive cmd.exe briefly. Give this visible view
            # bounded grace before asking the operator; never signal processes.
            deadline = time.monotonic() + min(timeout, 5)
            while not observation["clear_in_view"] and time.monotonic() < deadline:
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
                observation = self.stop_check.check()
            self.record["stop_observation"] = observation
            if not observation["clear_in_view"]:
                self.record["status"] = "needs-user"
            elif code != 0:
                self.record["status"] = "failed"
            else:
                self._guard()
                _identities(self.launch.spec["tool"], self.launch.spec["expected_hashes"])
                self.record["prefix_version_sha256"] = _prefix(self.plan.compatdata)
                self._initialized()
                self.record["vc_runtime_fingerprint"] = self._vc_fingerprint()
                self.record["status"] = "initialized-unverified"
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.record.update(status="failed", error={"check": "trial-post-checks", "error_class": type(error).__name__,
                                                     "errno": getattr(error, "errno", None)})
            if hasattr(error, "tree_diagnostic"):
                self.record["error"]["tree_diagnostic"] = error.tree_diagnostic
        return self._save()
