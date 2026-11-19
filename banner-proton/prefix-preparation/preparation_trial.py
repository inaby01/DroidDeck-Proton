"""Explicitly scoped first initialization trial; never normal execution readiness.

An absent dedicated probe prefix and reviewed preparation payload are mandatory.
The trial tests runtime compatibility; it cannot assert prior runtime validation or
other-namespace visibility. Ordinary LaunchSession prerequisites are unchanged.
"""

import hashlib
import os
import secrets
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import digest_json
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
)
from preparation_payload import verify_fex_runtime_tree
from preparation_processes import ProcessStopCheck
from preparation_static_placement import (
    StaticPlacementPlan,
    _private_xalia_context,
    _proof,
)

SCOPE = "dedicated-new-prefix-initialization-trial"
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
        return {"scope": SCOPE, "input_digest": self.digest, "app_id": self.placement.installation.target.registration_id,
                "command": list(OPERATIONS["initialize"]), "prefix": str(self.compatdata),
                "work": str(self.work), "home": str(self.private_home), "baseline_bytes": self.baseline_bytes,
                "growth_reserve_bytes": RESERVE, "growth_upper_bound_known": False,
                "process_scope": "same-proc-directory-owner-as-self", "device_namespace_verified": False,
                "runtime_execution_verified": False, "binding_written": False, "dependencies_installed": False,
                "preparation_complete": False, "execution_authorized": False, "writes": []}


def _live_runtime(installation):
    require(installation.runtime.root == Path("/") and installation.runtime.view == "current-root",
            "live current-root runtime required for trial")


def plan_trial(placement, home):
    require(isinstance(placement, StaticPlacementPlan), "trusted reviewed placement required")
    installation = placement.installation
    _live_runtime(installation)
    report = installation.summary()
    require(report["action"] == "reuse-verified-tree", "verified installed preparation tool required")
    require(report["tool_slot"] == "preparation" and not report["prefix"]["exists"], "new dedicated prefix required")
    require(_proof(installation, placement.probe_store_root) == placement.probe, "dedicated probe changed")
    inventory = installation.inventory
    require(inventory.external_links == 0, "external payload links forbidden")
    require(not any(name in inventory.entries for name in ("dist", "dist.lock", "steampipe_fixups.json")),
            "mutable distribution maintenance path not supported for trial")
    require(inventory.entries.get("files/share/default_pfx_arm64", {}).get("kind") == "directory",
            "shipped arm64 default prefix required")
    home = safe_path(home)
    key = installation.target.registration_id
    work = safe_path(home / ".local/share/droiddeck-preparation-work" / key / "work", home)
    private_home = safe_path(work.parent / "home", home)
    compatdata = safe_path(installation.target.steam / "steamapps/compatdata" / key, installation.target.steam)
    _aliases(installation.target.steam, key)
    require(not os.path.lexists(compatdata) and not os.path.lexists(work.parent), "new trial paths required")
    for path in (work.parent, placement.store_root):
        for protected in (installation.target.steam, placement.settings, installation.target.exe.parent):
            require(path != protected and not path.is_relative_to(protected) and not protected.is_relative_to(path),
                    "trial paths overlap protected inputs")
    policy = _private_xalia_context(installation, placement.review)
    if policy is not None:
        policy.guard()
    files = [value for name, value in inventory.entries.items() if name.startswith("files/share/default_pfx_arm64/")]
    fs = os.statvfs(compatdata.parent)
    block = fs.f_frsize or fs.f_bsize
    require(block > 0 and files, "prefix allocation baseline unavailable")
    baseline = block + sum(((entry["size"] + block - 1) // block) * block if entry["kind"] == "file" else block for entry in files)
    require(fs.f_bavail * block >= baseline + RESERVE, "insufficient prefix baseline and trial reserve")
    require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
    signature = {"scope": SCOPE, "version": VERSION, "placement": placement.digest,
                 "home": str(home), "work": str(work), "compatdata": str(compatdata), "baseline": baseline}
    return TrialPlan(digest_json(signature), placement, home, work, private_home, compatdata, baseline)


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


def validate_trial_record(record, scope=SCOPE, id_prefix="trial-"):
    fields(record, ("schema_version", "tool_version", "scope", "trial_id", "app_id", "input_digest", "status", "phase",
                    "exit_code", "prefix_version_sha256", "runtime_execution_verified", "device_namespace_verified",
                    "preparation_complete"), ("error", "stop_observation", "settings_identity_unchanged", "profile"))
    if "profile" in record:
        require(scope != SCOPE, "probe trials carry no game profile")
        fields(record["profile"], ("profile_id", "revision", "profile_digest", "exe_sha256", "exe_size", "selection"))
        require(type(record["profile"]["exe_sha256"]) is str and SHA256.fullmatch(record["profile"]["exe_sha256"]) and
                type(record["profile"]["exe_size"]) is int and record["profile"]["exe_size"] > 0 and
                type(record["profile"]["profile_digest"]) is str and SHA256.fullmatch(record["profile"]["profile_digest"]) and
                record["profile"]["selection"] in ("operator-selected-unverified", "profile-hash-matched"),
                "invalid game profile binding")
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

    # Subclasses reuse the same guarded flow for another explicit scope and journal.
    scope, records, id_prefix = SCOPE, "trials", "trial-"

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
        verify_fex_runtime_tree(safe_path(installation.summary()["destination"]), installation.inventory, installation.customization.overlays)
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
                target_pin=installation.target, runtime_plan=installation.runtime, fex_runtime_contract=True)
            self._guard()
            require(self.stop_check.check()["clear_in_view"], "target process view changed")
            require(not os.path.lexists(p.compatdata), "trial prefix appeared")
            self.record["phase"] = "prefix-create"
            self._save()
            p.compatdata.mkdir(mode=0o700)
            self.record.update(status="running", phase="spawn")
            self._save()
            self._guard()
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
                self.record["status"] = "initialized-unverified"
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.record.update(status="failed", error={"check": "trial-post-checks", "error_class": type(error).__name__,
                                                     "errno": getattr(error, "errno", None)})
            if hasattr(error, "tree_diagnostic"):
                self.record["error"]["tree_diagnostic"] = error.tree_diagnostic
        return self._save()


def interactive_trial(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                      steam=None, settings=None, home=None, runtime_root=None):
    """One explicit device action with preview, confirmation and automatic report."""
    import sys
    from pathlib import Path

    import preparation_selection as selection
    from preparation_binding import droiddeck_lock
    from preparation_installation import plan_installation
    from preparation_probe import EXE
    from preparation_static_placement import plan_static_placement
    from preparation_store import PrivateStore

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    directory = safe_path(directory)
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    runtime_root = Path("/") if runtime_root is None else runtime_root
    protected = [steam, settings]
    report, session = None, None
    stage, started = "trial-plan", False
    try:
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True and "placement_review" in config, "trial menu not enabled")
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        candidates = [key for key, game in games.items() if Path(game["exe"]).name == EXE]
        require(candidates, "registered dedicated probe required")
        for number, key in enumerate(candidates, 1):
            print(f"{number}. {selection._text(games[key]['title'])} [ID {key}]", file=output)
        print("初期化する専用検証登録の番号（qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32).strip()
        if answer == "q":
            return 0, None
        require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(candidates), "invalid trial selection")
        key = candidates[int(answer) - 1]
        management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
        probe_store = management.parent / "probe-store"

        def refresh():
            current, _, now = selection.registration_catalog(environment)
            require(current == source and key in now, "trial registration changed")
            payload = config["payload"]
            installation = plan_installation(archive=selection._archive(directory, payload), sha512=payload["sha512"],
                archive_root=payload["root"], mode=payload["mode"], runtime_root=runtime_root,
                runtime_audit=config["runtime_reference"], registrations=source, registration_id=key,
                exe_root=Path(now[key]["exe"]).parent, steam=steam, renderer=renderer,
                parent_environment=environment, tool_slot=payload.get("tool_slot", "legacy"))
            placement = plan_static_placement(installation, config["placement_review"], management, probe_store, settings)
            return plan_trial(placement, home)

        print("配布物・配置済みtool全体・runtime識別・専用登録・未作成prefixを再照合しています。", file=output, flush=True)
        plan = refresh()
        preview = plan.summary()
        print("新規prefix: " + selection._text(preview["prefix"]), file=output)
        print("専用work: " + selection._text(preview["work"]), file=output)
        print("専用HOME: " + selection._text(preview["home"]), file=output)
        print(f"出荷時prefix見積 {plan.baseline_bytes / 1024**2:.1f} MiB + 余裕1 GiB。実増分の上限は未測定です。", file=output)
        print("実行: 選択済み準備用Proton run cmd.exe /d /c exit 0（ゲーム・installerは起動しません）", file=output)
        print("新規prefix、専用work/HOME、私有trial記録/lock、設定の協調lock、結果JSONを書きます。", file=output)
        print("他namespaceの停止は保証できません。すべてのゲーム・Wineを終了してから続行してください。", file=output)
        print("時間超過や失敗では強制終了・削除・自動再試行せず、記録と作成物を残します。", file=output)
        print("この初期化試験を実行する場合は1、取消はq: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            return 0, None
        stage, started = "trial-start", True
        selection._private_report_directory(home, protected)
        lock = hashlib.sha256(str(plan.compatdata).encode()).hexdigest()
        with PrivateStore(management, create=True) as store, store.locked(lock), droiddeck_lock(settings):
            session = TrialSession(plan, store, refresh, plan.digest, ProcessStopCheck(plan.compatdata))
            session.start()
            while True:
                stage = "trial-wait"
                outcome = session.wait(30)
                if outcome["status"] != "needs-user":
                    break
                print("未完了です。強制終了していません。さらに待つ場合は1、記録を残して戻る場合はq: ", end="", file=output, flush=True)
                if stream.readline(32).strip() != "1":
                    break
            report = {"mode": "initialization-trial-result", "scope": SCOPE, "trial": outcome,
                      "planned_scope": preview, "prefix_created": plan.compatdata.exists(),
                      "wine_launch_attempted": True, "binding_written": False, "preparation_complete": False,
                      "writes": [{"scope": "dedicated-new-prefix", "path": str(plan.compatdata)},
                                 {"scope": "new-private-trial-work-home", "path": str(plan.work.parent)},
                                 {"scope": "private-trial-journal-and-locks", "path": str(management)},
                                 {"scope": "cooperative-settings-lock-only", "path": str(settings / "lock")}],
                      "raw_child_output_collected": False}
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "initialization-trial-result", "scope": SCOPE, "stage": stage,
                  "check": getattr(error, "preparation_check", stage), "error_class": type(error).__name__,
                  "errno": getattr(error, "errno", None), "preparation_complete": False,
                  "writes": [] if not started else [{"scope": "partial-trial-preserve-and-inspect"}]}
        if session is not None:
            report["trial"] = dict(session.record)
        print("初期化試験は停止しました。作成物を削除せず、結果を保存します。", file=output)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有trial記録と作成物を保持しています。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    print("初期化試験の状態: " + report.get("trial", {}).get("status", "stopped-before-result"), file=output)
    return 2, str(saved)
