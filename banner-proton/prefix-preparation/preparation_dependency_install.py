"""Interactive SoftDenchi bootstrap on one rechecked managed trial prefix only.

The ordinary execution readiness is unchanged. A visible Wine builtin window is
shown first; the original bootstrap starts only after the operator confirms the
window appeared and the visible process view is clear again. No silent
arguments, no MSI-only launch, no forced termination, no repair, no retry on
another prefix. The final state is decided by the offline inspection, never by
the Unix exit status alone.
"""

import hashlib
import os
import secrets
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import (
    INPUT_LIMITS,
    digest_json,
    inspect_assets,
    measure_stream,
    validate_manifest,
)
from preparation_common import (
    SHA256,
    VERSION,
    Invalid,
    app_id,
    fields,
    regular_open,
    require,
    safe_path,
)
from preparation_dependency_state import inspect_dependency_state
from preparation_execution import plan_launch
from preparation_processes import ProcessStopCheck
from preparation_recheck import RecheckSession, plan_recheck, validate_recheck_record
from preparation_softdenchi_recipe import (
    HANDLER,
    bind_asset,
    recipe_digest,
    softdenchi_recipe,
    validate_recipe,
)
from preparation_store import PrivateStore
from preparation_trial import _new_private
from preparation_trial_audit import measure_prefix

SCOPE = "managed-prefix-dependency-installation"
RECORDS = "dependency-installs"
RESERVE = 1024**3
STOP_GRACE = 60
GUI_COMMAND = ("runinprefix", "winver.exe")
STATUSES = ("running", "needs-user", "failed", "stopped-before-installer", "cancelled-absent", "partial",
            "incompatible", "installed-unverified", "present-verified")
PHASES = ("planned", "gui-check-spawned", "gui-check-exited", "gui-check-stopped", "gui-check-not-confirmed",
          "installer-staged", "installer-spawned", "installer-exited", "stop-observed", "post-inspected")
PRE_INSTALLER = frozenset(("planned", "gui-check-spawned", "gui-check-exited", "gui-check-stopped", "gui-check-not-confirmed",
                           "installer-staged"))
POST_STATUS = {"present-verified": "present-verified", "present-unverified": "installed-unverified", "partial": "partial",
               "incompatible": "incompatible", "absent": "cancelled-absent", "uninspected": "needs-user"}


def validate_dependency_config(value):
    fields(value, ("handler", "recipe_revision", "asset"))
    require(value["handler"] == HANDLER, "only the SoftDenchi interactive handler is supported")
    require(type(value["recipe_revision"]) is int and value["recipe_revision"] >= 1, "invalid recipe revision")
    validate_manifest({"schema_version": 1, "assets": [value["asset"]]})
    return value


def _install_id(value):
    require(type(value) is str and value.startswith("depinstall-") and len(value) == 43 and
            all(c in "0123456789abcdef" for c in value[11:]), "invalid installation ID")
    return value


def validate_install_record(record):
    fields(record, ("schema_version", "tool_version", "scope", "install_id", "created_ns", "trial_id", "recheck_id", "app_id",
                    "handler", "recipe_revision", "recipe_digest", "asset_sha256", "input_digest", "previous_install_id",
                    "phase", "status", "gui_check", "installer", "pre_state", "post_state", "runtime_execution_verified",
                    "device_namespace_verified", "preparation_complete"),
           ("post_inspection", "stop_observation", "settings_identity_unchanged", "prefix_allocation", "error"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and record["scope"] == SCOPE,
            "unsupported installation record")
    require(type(record["tool_version"]) is str and 0 < len(record["tool_version"]) <= 64, "invalid installation version")
    _install_id(record["install_id"])
    require(type(record["created_ns"]) is int and record["created_ns"] > 0, "invalid installation time")
    require(app_id(record["app_id"]) == record["app_id"] and record["handler"] == HANDLER, "invalid installation target")
    require(type(record["recipe_revision"]) is int and record["recipe_revision"] >= 1, "invalid recipe revision")
    require(all(type(record[name]) is str and SHA256.fullmatch(record[name]) for name in
                ("recipe_digest", "asset_sha256", "input_digest")), "invalid installation digests")
    require(record["previous_install_id"] is None or _install_id(record["previous_install_id"]), "invalid previous installation")
    require(record["phase"] in PHASES and record["status"] in STATUSES, "invalid installation state")
    for section in ("gui_check", "installer"):
        fields(record[section], ("status", "unix_exit_status"), ("display_confirmed", "staged_unchanged"))
        require(record[section]["unix_exit_status"] is None or type(record[section]["unix_exit_status"]) is int,
                "invalid exit status")
    require(record["pre_state"] in ("absent",) and record["post_state"] in (None, "uninspected", "absent", "partial", "incompatible",
            "present-unverified", "present-verified"), "invalid dependency state")
    require(all(record[name] is False for name in ("runtime_execution_verified", "device_namespace_verified",
                                                   "preparation_complete")), "installation cannot grant full readiness")
    return record


def _capacity(needs):
    """Group required bytes by filesystem; unknown growth beyond the reserve is reported, not estimated."""
    groups = {}
    for path, need in needs:
        nearest = safe_path(path)
        while not nearest.exists():
            nearest = nearest.parent
        safe_path(nearest)
        info, fs = nearest.stat(), os.statvfs(nearest)
        available = fs.f_bavail * (fs.f_frsize or fs.f_bsize)
        entry = groups.setdefault(info.st_dev, {"available_bytes": available, "required_bytes": 0})
        entry["required_bytes"] += need
    sufficient = all(entry["available_bytes"] >= entry["required_bytes"] for entry in groups.values())
    return {"sufficient": sufficient, "filesystems": sorted(groups.values(), key=lambda item: item["required_bytes"]),
            "reserve_bytes": RESERVE, "growth_upper_bound_known": False}


def _recheck_evidence(store_root, record, prefix_version):
    with PrivateStore(store_root) as store:
        candidates = []
        for item in store.inventory()["rechecks"]:
            if item.get("trial_id") != record["trial_id"] or item.get("status") != "probe-exited-unverified":
                continue
            full, digest = store.read_record("rechecks", item["recheck_id"] + ".json")
            validate_recheck_record(full)
            if (full["exit_code"] == 0 and full.get("settings_identity_unchanged") is True and
                    full["app_id"] == record["app_id"] and full["prefix_version_sha256"] == prefix_version):
                candidates.append((full["recheck_id"], digest))
    require(candidates, "matching successful managed recheck required")
    return max(candidates)


def _installations(store_root, key):
    """Valid records of this registration (oldest first) and the count of unreadable records."""
    with PrivateStore(store_root) as store:
        listed = store.inventory()["dependency_installs"]
    invalid = sum(item.get("status") == "invalid" for item in listed)
    items = [item for item in listed if item.get("status") != "invalid" and item.get("app_id") == key]
    return sorted(items, key=lambda item: item["created_ns"]), invalid


def retry_blockers(latest, invalid):
    """A new attempt follows only a cancelled, pre-installer or interrupted record (design section 7)."""
    if invalid:
        return ["invalid-installation-record-present"]
    if latest is None or latest["status"] in ("cancelled-absent", "stopped-before-installer"):
        return []
    if latest["phase"] in PRE_INSTALLER or latest["status"] in ("running", "needs-user"):
        return []
    return ["previous-installation-" + latest["status"] + "-review-required"]


@dataclass(frozen=True)
class InstallPlan:
    digest: str
    recheck: object = field(repr=False)
    recheck_id: str
    recheck_sha256: str
    recipe: dict = field(repr=False)
    spec: dict = field(repr=False)
    asset_root: object = field(repr=False)
    measured: dict = field(repr=False)
    pre_state: dict = field(repr=False)
    previous: object = field(repr=False)
    inputs_root: object = field(repr=False)
    capacity: dict = field(repr=False)
    blockers: tuple

    def summary(self):
        p = self.recheck
        return {"scope": SCOPE, "input_digest": self.digest, "trial_id": p.record["trial_id"], "recheck_id": self.recheck_id,
                "app_id": p.record["app_id"], "prefix": str(p.compatdata), "handler": HANDLER,
                "recipe_revision": self.recipe["revision"], "asset": {"filename": self.spec["filename"],
                "sha256": self.measured["sha256"] if self.measured else None, "size": self.measured["size"] if self.measured else None},
                "pre_state": self.pre_state["state"], "pre_groups": self.pre_state["groups"],
                "previous_installation": self.previous, "capacity": self.capacity,
                "steps": [{"step": "gui-check", "command": list(GUI_COMMAND)},
                          {"step": "original-bootstrap", "command": ["runinprefix", "<private copy of " + self.spec["filename"] + ">"],
                           "arguments": [], "silent_arguments_inferred": False, "msi_only_bypass": False},
                          {"step": "offline-postconditions", "wine_started": False}],
                "license_decision": "operator-in-installer-window", "authentication_performed": False,
                "network_blocked": False, "forced_termination": False, "blockers": list(self.blockers),
                "execution_authorized": False, "device_namespace_verified": False, "preparation_complete": False, "writes": []}


def plan_dependency_install(**kwargs):
    """Read-only plan. Blockers are reported, never cleared by later steps.

    A failure carries the name of the check that stopped it (``preparation_check``).
    """
    progress = ["dependency-config"]
    try:
        return _plan_dependency_install(progress, **kwargs)
    except (OSError, ValueError, TypeError, KeyError) as error:
        if not hasattr(error, "preparation_check"):
            error.preparation_check = progress[-1]
        raise


def _plan_dependency_install(progress, *, record, record_sha256, config, directory, renderer, source, games, steam, settings,
                             home, environment, runtime_root, recipe=None):
    recipe = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
    dependency = validate_dependency_config(config.get("dependency_installation"))
    require(dependency["recipe_revision"] == recipe["revision"], "configured recipe revision differs")
    progress.append("managed-recheck-plan")
    base = plan_recheck(record=record, record_sha256=record_sha256, config=config, directory=directory, renderer=renderer,
                        source=source, games=games, steam=steam, settings=settings, home=home, environment=environment,
                        runtime_root=runtime_root)
    progress.append("recheck-evidence")
    recheck_id, recheck_sha256 = _recheck_evidence(base.store_root, record, base.prefix_version)
    progress.append("asset-inspection")
    spec = dependency["asset"]
    directory = safe_path(directory)
    report = inspect_assets({"schema_version": 1, "assets": [spec]}, directory)[0]
    blockers = ["asset:" + reason for reason in report["blockers"]]
    try:
        binding = bind_asset(recipe, spec, report["measured"])
    except Invalid:
        binding = None
        blockers.append("asset-not-recipe-bootstrap")
    progress.append("dependency-state")
    pre = inspect_dependency_state(base.compatdata, recipe)
    if pre["state"] != "absent":
        blockers.append("dependency-state-" + pre["state"] + "-preserve-and-inspect")
    progress.append("installation-history")
    previous, invalid = _installations(base.store_root, record["app_id"])
    latest = previous[-1] if previous else None
    blockers.extend(retry_blockers(latest, invalid))
    progress.append("capacity")
    home = safe_path(home)
    inputs_root = safe_path(base.work.parent / "inputs", home)
    size = spec["expected_size"]
    capacity = _capacity(((base.store_root, size), (inputs_root, size), (base.compatdata, RESERVE)))
    if not capacity["sufficient"]:
        blockers.append("insufficient-capacity")
    signature = {"version": VERSION, "scope": SCOPE, "recheck_plan": base.digest, "recheck": recheck_sha256,
                 "recipe": recipe_digest(recipe), "binding": binding, "spec": digest_json(spec), "measured": report["measured"],
                 # The history is shown, not pinned: this session's own record must not invalidate its plan.
                 "pre_state": digest_json(pre), "inputs": str(inputs_root),
                 "capacity_sufficient": capacity["sufficient"], "blockers": sorted(blockers)}
    return InstallPlan(digest_json(signature), base, recheck_id, recheck_sha256, recipe, spec, directory, report["measured"],
                       pre, latest, inputs_root, capacity, tuple(sorted(blockers)))


class DependencyInstallSession:
    def __init__(self, plan, store, refresh, confirmation, stop_check):
        require(isinstance(plan, InstallPlan), "trusted dependency installation plan required")
        self.plan, self.store, self.refresh, self.confirmation, self.stop = plan, store, refresh, confirmation, stop_check
        # Reuse the managed recheck guard: trial history, payload/FEX tree, runtime,
        # target, prefix version, settings identity and private paths.
        self.base_guard = RecheckSession(plan.recheck, store, None, None, stop_check)
        self.process, self.hash, self.staged = None, None, None
        p = plan.recheck
        self.record = {"schema_version": 1, "tool_version": VERSION, "scope": SCOPE,
                       "install_id": "depinstall-" + secrets.token_hex(16), "created_ns": time.time_ns(),
                       "trial_id": p.record["trial_id"], "recheck_id": plan.recheck_id, "app_id": p.record["app_id"],
                       "handler": HANDLER, "recipe_revision": plan.recipe["revision"], "recipe_digest": recipe_digest(plan.recipe),
                       "asset_sha256": plan.recipe["bootstrap"]["sha256"], "input_digest": plan.digest,
                       "previous_install_id": plan.previous and plan.previous["install_id"], "phase": "planned",
                       "status": "running", "gui_check": {"status": "not-started", "unix_exit_status": None},
                       "installer": {"status": "not-started", "unix_exit_status": None}, "pre_state": plan.pre_state["state"],
                       "post_state": None, "runtime_execution_verified": False, "device_namespace_verified": False,
                       "preparation_complete": False}

    def _save(self):
        validate_install_record(self.record)
        self.hash = self.store.write_record(RECORDS, self.record["install_id"] + ".json", self.record, expected_hash=self.hash)
        return dict(self.record)

    def _guard(self):
        self.base_guard._guard()
        require(self.store.read_record("rechecks", self.plan.recheck_id + ".json")[1] == self.plan.recheck_sha256,
                "managed recheck evidence changed")

    def _fail(self, check, error):
        self.record.update(status="failed", error={"check": check, "error_class": type(error).__name__,
                                                   "errno": getattr(error, "errno", None)})
        return self._save()

    def _launch(self):
        p = self.plan.recheck
        entries = {**p.inventory.entries, **p.customization.overlays}
        hashes = {name: entries[name]["sha256"] if name in entries else None for name in ("proton", "version", "user_settings.py")}
        return plan_launch(tool=safe_path(p.target.steam / "compatibilitytools.d" / p.customization.directory),
            steam=p.target.steam, registration_id=p.record["app_id"], install=p.target.exe.parent, work=p.work, home=p.private_home,
            runtime_environment=p.runtime.environment, expected_hashes=hashes, payload_inventory=p.inventory,
            payload_overlays=p.customization.overlays, target_pin=p.target, runtime_plan=p.runtime, operation="probe",
            prefix_version_sha256=p.prefix_version, trial_recheck_id=p.record["trial_id"])

    def _clear(self):
        require(isinstance(self.stop, ProcessStopCheck) and self.stop.compatdata == self.plan.recheck.compatdata,
                "matching process observation required")
        require(self.stop.check()["clear_in_view"], "target process view not clear")

    def _spawn(self, launch, tail):
        return subprocess.Popen((launch.argv[0], *tail), cwd=self.plan.recheck.work, env=launch.environment, shell=False,
                                close_fds=True, start_new_session=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start_gui_check(self):
        require(self.hash is None and self.process is None and self.confirmation == self.plan.digest,
                "exact unused confirmation required")
        require(not self.plan.blockers, "dependency installation blocked")
        require(self.refresh().digest == self.plan.digest, "dependency installation plan changed")
        self._guard()
        self._clear()
        launch = self._launch()
        self.record.update(phase="gui-check-spawned")
        self.record["gui_check"]["status"] = "running"
        self._save()
        try:
            self._guard()
            self._clear()
            self.process = self._spawn(launch, GUI_COMMAND)
        except (OSError, ValueError, TypeError, KeyError) as error:
            self._fail("gui-check-spawn", error)
            raise
        return self

    def _settings_unchanged(self):
        from preparation_recheck import _settings
        p = self.plan.recheck
        return _settings(p.target.steam, p.settings) == self.base_guard.settings_identity

    def _wait_child(self, section, timeout):
        require(type(timeout) is int and 1 <= timeout <= 120 and self.process is not None, "bounded wait required")
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.record[section]["status"] = "waiting"
            self.record["status"] = "needs-user"
            self._save()
            return False
        self.record[section].update(status="exited", unix_exit_status=code)
        self.record.update(phase="gui-check-exited" if section == "gui_check" else "installer-exited", status="running")
        self._save()
        observation = self.stop.check()
        deadline = time.monotonic() + STOP_GRACE
        while not observation["clear_in_view"] and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            observation = self.stop.check()
        self.record["stop_observation"] = observation
        self.record["settings_identity_unchanged"] = self._settings_unchanged()
        if not observation["clear_in_view"]:
            self.record[section]["status"] = "exited-processes-remain"
            self.record["status"] = "needs-user"
            self._save()
            return False
        self.process = None
        return True

    def wait_gui_check(self, timeout=30):
        require(self.record["phase"] in ("gui-check-spawned", "gui-check-exited"), "GUI check not running")
        try:
            if not self._wait_child("gui_check", timeout):
                return dict(self.record)
            require(self.record["settings_identity_unchanged"], "settings changed during GUI check")
            self._guard()
            self.record.update(phase="gui-check-stopped", status="running")
        except (OSError, ValueError, TypeError, KeyError) as error:
            return self._fail("gui-check-postconditions", error)
        return self._save()

    def confirm_display(self, confirmed):
        require(self.record["phase"] == "gui-check-stopped" and type(confirmed) is bool, "GUI check result not ready")
        self.record["gui_check"]["display_confirmed"] = confirmed
        if not confirmed:
            self.record.update(phase="gui-check-not-confirmed", status="stopped-before-installer")
        return self._save()

    def decline_installer(self):
        require(self.record["phase"] == "gui-check-stopped", "installer step not pending")
        self.record["status"] = "stopped-before-installer"
        return self._save()

    def _stage(self):
        """Copy the verified private cache to a new private input under the bootstrap's distributed name."""
        p, spec = self.plan.recheck, self.plan.spec
        home = p.work.parents[4]
        directory = safe_path(self.plan.inputs_root / self.record["install_id"], home)
        _new_private(directory, home)
        limit = INPUT_LIMITS[spec["format"]]
        target = safe_path(directory / spec["filename"], directory)
        with self.store.directory(("assets", PrivateStore.cache_name(spec))) as cache, \
                PrivateStore._existing(cache, "payload.bin", limit) as source:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as destination:
                info = os.fstat(destination.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "invalid staged input")
                measured = measure_stream(source, limit, spec["format"], destination)
                destination.flush()
                os.fsync(destination.fileno())
        self._check_staged(target, measured)
        return target

    def _measure(self):
        """Metadata-only prefix allocation; an unmeasurable prefix is recorded, never fatal."""
        try:
            value = measure_prefix(self.plan.recheck.compatdata)
            return {key: value[key] for key in ("entries", "regular_files", "symlinks_not_followed",
                                                "logical_file_bytes", "allocated_file_bytes")}
        except (OSError, ValueError) as error:
            return {"status": "uninspected", "error_class": type(error).__name__}

    def _check_staged(self, target, measured=None):
        boot = self.plan.recipe["bootstrap"]
        with regular_open(target, INPUT_LIMITS["pe"]) as stream:
            current = measure_stream(stream, INPUT_LIMITS["pe"], "pe")
        expected = {"sha256": boot["sha256"], "size": boot["size"], "pe_machine": boot["pe_machine"]}
        require(current == expected and (measured is None or measured == expected), "staged input differs from recipe bootstrap")
        return True

    def start_installer(self):
        require(self.record["phase"] == "gui-check-stopped" and self.record["gui_check"].get("display_confirmed") is True and
                self.process is None and self.record["status"] == "running", "confirmed GUI check required first")
        try:
            require(self.refresh().digest == self.plan.digest, "dependency installation plan changed")
            self._guard()
            self._clear()
            self.store.cache_asset(self.plan.spec, self.plan.asset_root)
            self.staged = self._stage()
            self.record["prefix_allocation"] = {"before": self._measure(), "after": None}
            self.record.update(phase="installer-staged")
            self.record["installer"]["status"] = "staged"
            self._save()
            launch = self._launch()
            self._guard()
            self._clear()
            self._check_staged(self.staged)
            self.record.update(phase="installer-spawned")
            self.record["installer"]["status"] = "running"
            self._save()
            self.process = self._spawn(launch, ("runinprefix", str(self.staged)))
        except (OSError, ValueError, TypeError, KeyError) as error:
            self._fail("installer-start", error)
            raise
        return self

    def wait_installer(self, timeout=30):
        require(self.record["phase"] in ("installer-spawned", "installer-exited"), "installer not running")
        try:
            if not self._wait_child("installer", timeout):
                return dict(self.record)
            self.record["phase"] = "stop-observed"
            self._save()
        except (OSError, ValueError, TypeError, KeyError) as error:
            return self._fail("installer-stop-observation", error)
        # Independent post-checks: each is collected even if another fails.
        errors = {}
        for name, check in (("inputs", self._guard), ("staged-input", lambda: self._check_staged(self.staged))):
            try:
                check()
                if name == "staged-input":
                    self.record["installer"]["staged_unchanged"] = True
            except (OSError, ValueError, TypeError, KeyError) as error:
                errors[name] = type(error).__name__
                if name == "staged-input":
                    self.record["installer"]["staged_unchanged"] = False
        try:
            post = inspect_dependency_state(self.plan.recheck.compatdata, self.plan.recipe)
            after = self.stop.check()
            if not after["clear_in_view"]:
                post = {**post, "state": "uninspected", "concurrent_process_observed": True}
        except (OSError, ValueError, TypeError, KeyError) as error:
            post = {"state": "uninspected", "error_class": type(error).__name__}
        allocation = self.record.get("prefix_allocation") or {"before": None}
        allocation["after"] = self._measure()
        before, after = allocation["before"], allocation["after"]
        allocation["growth_bytes"] = (after["allocated_file_bytes"] - before["allocated_file_bytes"]
                                      if before and after and "allocated_file_bytes" in before and "allocated_file_bytes" in after
                                      else None)
        self.record["prefix_allocation"] = allocation
        self.record.update(phase="post-inspected", post_state=post["state"], post_inspection=post)
        status = POST_STATUS[post["state"]]
        if errors or self.record["settings_identity_unchanged"] is not True:
            self.record["error"] = {"check": "installer-postconditions", "error_class": ",".join(sorted(errors)) or "SettingsChanged",
                                    "errno": None}
            status = "failed"
        self.record["status"] = status
        return self._save()


def inspect_managed_dependency(plan_base, store, stop_check, recipe=None):
    """Read-only reinspection under the managed locks; never starts Wine or installs."""
    recipe = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
    guard = RecheckSession(plan_base, store, None, None, stop_check)
    guard._guard()
    before = stop_check.check()
    if not before["clear_in_view"]:
        return {"state": "uninspected", "reason": "target-process-view-not-clear", "stop_observation": before}
    result = inspect_dependency_state(plan_base.compatdata, recipe)
    after = stop_check.check()
    if not after["clear_in_view"]:
        result = {**result, "state": "uninspected", "concurrent_process_observed": True}
    result["stop_observation"] = after
    return result


def describe_error(error, stage):
    """Check name and reason without echoing paths or input content.

    Only this tool's own fixed ``Invalid`` messages are reported verbatim; other
    exception texts can contain paths or data and are reduced to their class.
    """
    result = {"check": getattr(error, "preparation_check", stage), "error_class": type(error).__name__,
              "errno": getattr(error, "errno", None), "reason": str(error) if type(error) is Invalid else None}
    for name in ("tree_diagnostic", "installed_tree_diagnostic"):
        if hasattr(error, name):
            result[name] = getattr(error, name)
    return result


def _isolated(function):
    try:
        return {"status": "accepted", **function()}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        return {"status": "rejected", **describe_error(error, None)}


def collect_diagnostics(*, record, config, directory, renderer, environment, steam, settings, home, runtime_root, recipe=None):
    """Independent read-only observations kept in the same report when planning stops.

    No Wine, no locks, no writes. Environment values are reduced to presence booleans.
    The dependency state is read without a process stop observation and is diagnostic only.
    """
    import preparation_selection as selection
    from preparation_execution import _prefix

    recipe = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
    directory, steam, settings, home = map(safe_path, (directory, steam, settings, home))
    key = record["app_id"]
    compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
    store_root = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store", home)

    def presence():
        reference = config["runtime_reference"]["environment_presence"]
        differing = {name: {"reference": bool(value), "current": bool(environment.get(name))}
                     for name, value in sorted(reference.items()) if bool(value) != bool(environment.get(name))}
        return {"differing": differing, "values_exported": False}

    def registration():
        _, _, games = selection.registration_catalog(environment)
        return {"registered": key in games}

    def recheck_plan():
        source, _, games = selection.registration_catalog(environment)
        with PrivateStore(store_root) as store:
            digest = store.read_record("trials", record["trial_id"] + ".json")[1]
        plan_recheck(record=record, record_sha256=digest, config=config, directory=directory, renderer=renderer,
                     source=source, games=games, steam=steam, settings=settings, home=home, environment=environment,
                     runtime_root=runtime_root)
        return {}

    def rechecks():
        version = _prefix(compatdata)
        summary = []
        with PrivateStore(store_root) as store:
            items = [item for item in store.inventory()["rechecks"] if item.get("trial_id") == record["trial_id"]]
            for item in items:
                full, _ = store.read_record("rechecks", item["recheck_id"] + ".json")
                validate_recheck_record(full)
                summary.append({"recheck_id": full["recheck_id"], "status": full["status"], "exit_code": full["exit_code"],
                                "settings_identity_unchanged": full.get("settings_identity_unchanged"),
                                "prefix_version_matches_live": full["prefix_version_sha256"] == version})
        return {"records": summary}

    def asset():
        spec = config["dependency_installation"]["asset"]
        path = safe_path(directory / spec["filename"], directory)
        present = os.path.lexists(path)
        result = {"present": present, "metadata": selection._input_metadata(path) if present else None}
        if present:
            # Metadata above is kept even when the strict read below refuses the file.
            try:
                report = inspect_assets({"schema_version": 1, "assets": [spec]}, directory)[0]
            except (OSError, ValueError) as error:
                result["inspection"] = describe_error(error, "asset-inspection")
                return result
            result.update(blockers=report["blockers"], measured=report["measured"])
            try:
                bind_asset(recipe, spec, report["measured"])
                result["recipe_bootstrap"] = True
            except Invalid:
                result["recipe_bootstrap"] = False
        return result

    def state():
        found = inspect_dependency_state(compatdata, recipe)
        return {"state": found["state"], "groups": found["groups"], "trace_directories": found["trace_directories"],
                "product_traces": found["product_traces"], "process_view_checked": False}

    def history():
        previous, invalid = _installations(store_root, key)
        return {"records": previous, "invalid_records": invalid}

    checks = {name: _isolated(function) for name, function in (
        ("environment-presence", presence), ("registration", registration), ("managed-recheck-plan", recheck_plan),
        ("recheck-records", rechecks), ("asset-file", asset), ("dependency-state", state), ("installation-history", history))}
    return {"scope": "independent-read-only-diagnostics", "checks": checks, "wine_started": False, "writes": []}


def _select_trial(store, stream, output, prompt):
    records = [item for item in store.inventory()["trials"] if item["status"] != "invalid"]
    require(records, "no private trial records")
    for index, item in enumerate(records, 1):
        print(f"{index}. ID {item['app_id']} / {item['status']} / {item['trial_id']}", file=output)
    print(prompt, end="", file=output, flush=True)
    answer = stream.readline(32).strip()
    if answer == "q":
        return None, None
    require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(records), "invalid trial selection")
    return store.read_record("trials", records[int(answer) - 1]["trial_id"] + ".json")


def _context(directory, environment, steam, settings, home):
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    return safe_path(directory), environment, steam, settings, home


def _print_plan(plan, output, text):
    summary = plan.summary()
    asset = summary["asset"]
    print("対象prefix: " + text(summary["prefix"]), file=output)
    print("資材: " + text(asset["filename"]) + (f"（SHA-256 {asset['sha256'][:16]}…、{asset['size'] / 1024**2:.1f} MiB）"
                                               if asset["sha256"] else "（見つかりません）"), file=output)
    print("導入前の状態: " + summary["pre_state"], file=output)
    previous = summary["previous_installation"]
    print("前回の導入記録: " + ("なし" if previous is None else text(previous["status"] + " / " + previous["install_id"])), file=output)
    for item in summary["capacity"]["filesystems"]:
        print(f"容量: 必要下限 {item['required_bytes'] / 1024**2:.1f} MiB / 空き {item['available_bytes'] / 1024**3:.1f} GiB", file=output)
    print("展開一時領域とprefix増分の上限は未知です。", file=output)
    print("手順: 1) Wine内蔵winverの画面を表示 → 閉じる  2) 表示を確認後、正規インストーラを起動（ライセンス同意は画面であなたが操作）", file=output)
    print("      3) 終了後に停止を確認し、ファイル・登録・サービス・COMをWineを起動せず読み取り検査", file=output)
    print("書込範囲: このprefix内（Program Files、windows\\system32・syswow64・ucharge、レジストリ）。VC++2019前提資材も入り得ます。", file=output)
    print("          私有キャッシュ・私有入力コピー・導入記録・lock・結果JSON。ゲーム・割り当て設定・他prefixは変更しません。", file=output)
    print("ゲームの認証はしません。インストーラの通信は遮断していません。他namespaceの停止保証はありません。強制終了はしません。", file=output)


def interactive_dependency_install(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                                   steam=None, settings=None, home=None, runtime_root=Path("/"), recipe=None):
    import sys

    import preparation_selection as selection
    from preparation_binding import droiddeck_lock

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    directory, environment, steam, settings, home = _context(directory, os.environ if environment is None else environment,
                                                             steam, settings, home)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    protected, session, started, stage, record = [steam, settings], None, False, "selection-config", None
    try:
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True and "dependency_installation" in config, "dependency installation not enabled")
        stage = "trial-selection"
        with PrivateStore(management) as store:
            record, digest = _select_trial(store, stream, output, "ソフト電池を導入する管理済みprefixの番号（qで取消）: ")
        if record is None:
            return 0, None
        stage = "registration-catalog"
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())

        def refresh():
            current, _, now = selection.registration_catalog(environment)
            require(current == source, "registration source changed")
            return plan_dependency_install(record=record, record_sha256=digest, config=config, directory=directory,
                renderer=renderer, source=source, games=now, steam=steam, settings=settings, home=home,
                environment=environment, runtime_root=runtime_root, recipe=recipe)

        print("管理済みprefix・tool・資材・導入前状態を照合しています（Wineは起動しません）。", file=output, flush=True)
        stage = "dependency-plan"
        plan = refresh()
        _print_plan(plan, output, selection._text)
        report = {"mode": "managed-dependency-installation-result", "scope": SCOPE, "plan": plan.summary(),
                  "preparation_complete": False, "binding_written": False}
        if plan.blockers:
            for blocker in plan.blockers:
                print("停止理由: " + selection._text(blocker), file=output)
            print("変更せずに結果を保存します。", file=output)
            report["writes"] = []
        else:
            print("1) 画面確認（winver）を開始する場合は1、取消はq: ", end="", file=output, flush=True)
            if stream.readline(32).strip() != "1":
                return 0, None
            started, stage = True, "dependency-gui-check"
            selection._private_report_directory(home, protected)
            lock = hashlib.sha256(str(plan.recheck.compatdata).encode()).hexdigest()
            with PrivateStore(management) as store, store.locked(lock), droiddeck_lock(settings):
                session = DependencyInstallSession(plan, store, refresh, plan.digest, ProcessStopCheck(plan.recheck.compatdata))
                session.start_gui_check()
                print("winverの画面が出たら、内容を確認して閉じてください。", file=output, flush=True)
                outcome = _wait_loop(session.wait_gui_check, stream, output)
                if outcome["phase"] == "gui-check-stopped":
                    print("winverの画面が表示され、閉じられましたか？ 表示された場合は1、表示されなかった場合はq: ", end="", file=output, flush=True)
                    if session.confirm_display(stream.readline(32).strip() == "1")["phase"] == "gui-check-stopped":
                        print("2) 正規インストーラを起動する場合は1、取消はq: ", end="", file=output, flush=True)
                        if stream.readline(32).strip() == "1":
                            stage = "dependency-installer"
                            session.start_installer()
                            print("インストーラの画面で操作してください。完了を待っています。", file=output, flush=True)
                            _wait_loop(session.wait_installer, stream, output)
                        else:
                            session.decline_installer()
            report.update(installation=dict(session.record), writes=[
                {"scope": "managed-trial-prefix-by-wine-processes"}, {"scope": "private-cache-input-journal-and-locks"},
                {"scope": "cooperative-settings-lock-only"}])
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "managed-dependency-installation-result", "scope": SCOPE, "tool_version": VERSION, "stage": stage,
                  **describe_error(error, stage), "preparation_complete": False,
                  "writes": [] if not started else [{"scope": "partial-managed-installation-preserve"}]}
        if session is not None:
            report["installation"] = dict(session.record)
        print("検査停止: " + selection._text(report["check"]) + " / " + selection._text(report["reason"] or report["error_class"]),
              file=output)
        if record is not None and not started:
            print("独立した読み取り診断を集めています（Wineは起動しません）。", file=output, flush=True)
            report["diagnostics"] = collect_diagnostics(record=record, config=config, directory=directory, renderer=renderer,
                environment=environment, steam=steam, settings=settings, home=home, runtime_root=runtime_root, recipe=recipe)
        print("導入処理は停止しました。prefix・記録・資材を削除せず結果を保存します。", file=output)
    return _save_result(selection, directory, home, report, protected, output)


def _wait_loop(wait, stream, output):
    while True:
        outcome = wait(30)
        if outcome["status"] != "needs-user":
            return outcome
        print("未完了です。強制終了していません。1で再待機、qで記録を残して戻る: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            return outcome


def _save_result(selection, directory, home, report, protected, output):
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録とprefixは削除していません。", file=output)
        return 1, None
    state = report.get("installation", {}).get("status") or report.get("inspection", {}).get("state")
    if state:
        print("結果: " + state, file=output)
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    return 2, str(saved)


def interactive_dependency_reinspect(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                                     steam=None, settings=None, home=None, runtime_root=Path("/"), recipe=None):
    import sys

    import preparation_selection as selection

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    directory, environment, steam, settings, home = _context(directory, os.environ if environment is None else environment,
                                                             steam, settings, home)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    protected = [steam, settings]
    try:
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True and "dependency_installation" in config, "dependency installation not enabled")
        with PrivateStore(management) as store:
            record, digest = _select_trial(store, stream, output, "導入状態を読み取り検査するprefixの番号（qで取消）: ")
        if record is None:
            return 0, None
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        print("Wineを起動せず、決まった登録キーとファイルだけを読み取ります。", file=output, flush=True)
        base = plan_recheck(record=record, record_sha256=digest, config=config, directory=directory, renderer=renderer,
                            source=source, games=games, steam=steam, settings=settings, home=home, environment=environment,
                            runtime_root=runtime_root)
        selection._private_report_directory(home, protected)
        lock = hashlib.sha256(str(base.compatdata).encode()).hexdigest()
        with PrivateStore(management) as store, store.locked(lock):
            inspection = inspect_managed_dependency(base, store, ProcessStopCheck(base.compatdata), recipe)
            history = [item for item in store.inventory()["dependency_installs"] if item.get("app_id") == record["app_id"]]
        report = {"mode": "managed-dependency-reinspection-result", "scope": SCOPE, "app_id": record["app_id"],
                  "inspection": inspection, "installation_history": history, "wine_started": False,
                  "installation_records_updated": False, "preparation_complete": False,
                  "writes": [{"scope": "private-locks-and-result-json"}]}
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "managed-dependency-reinspection-result", "scope": SCOPE, "tool_version": VERSION,
                  **describe_error(error, "dependency-reinspection"), "preparation_complete": False, "writes": []}
        print("検査停止: " + selection._text(report["check"]) + " / " + selection._text(report["reason"] or report["error_class"]),
              file=output)
        print("読み取り検査は停止しました。変更はしていません。", file=output)
    return _save_result(selection, directory, home, report, protected, output)
