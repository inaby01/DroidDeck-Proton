"""Confirmed fixed-command recheck of one private managed initialization trial.

Old trial history is immutable. FEX's one empty private directory is a separate,
source-reviewed runtime contract, never a general extra-file allowance.
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
    fields,
    input_change,
    require,
    safe_path,
)
from preparation_customization import plan_customizations
from preparation_execution import (
    _aliases,
    _prefix,
    plan_launch,
    require_no_bytecode_cache,
)
from preparation_installation import CAPTURE
from preparation_payload import (
    FEX_RUNTIME_CONTRACT,
    PayloadInventory,
    inspect_archive,
    inspect_archive_from_folder,
    runtime_writes,
    verify_fex_runtime_tree,
)
from preparation_probe import inspect_existing_probe_registration
from preparation_processes import ProcessStopCheck
from preparation_runtime_context import plan_runtime_environment
from preparation_static_placement import (
    reviewed_payload_permissions,
    validate_build_review,
)
from preparation_store import PrivateStore
from preparation_target import pin_registration
from preparation_trial import validate_trial_record

SCOPE = "managed-trial-fixed-command-recheck"


def _require_live(runtime):
    require(runtime.root == Path("/") and runtime.view == "current-root", "live runtime required for recheck")


def _settings(steam, settings):
    result = {}
    for name, path in (("games", settings / "games.json"), ("state", settings / "state.json"),
                       ("config", steam / "config/config.vdf")):
        raw = _raw(path)
        result[name] = None if raw is None else hashlib.sha256(raw).hexdigest()
    return result


def _private_existing(path, anchor):
    path, anchor = safe_path(path), safe_path(anchor)
    require(path != anchor and path.is_relative_to(anchor), "managed path outside private anchor")
    for directory in (path, *path.parents):
        info = safe_path(directory).stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022,
                "unsafe managed recheck ancestor")
        if directory == path:
            require(stat.S_IMODE(info.st_mode) == 0o700, "managed recheck leaf must be private 0700")
        if directory == anchor:
            return
    require(False, "managed anchor not reached")


def _initialized_prefix(compatdata, record, version):
    """A registered-game record vouches only for the directory and version it initialized."""
    from preparation_game_prefix import require_initialized_directories
    require(version == record["prefix_version_sha256"], "game prefix version differs from initialization")
    require_initialized_directories(compatdata, record)


@dataclass(frozen=True)
class RecheckPlan:
    digest: str
    record: dict = field(repr=False)
    record_sha256: str
    store_root: object = field(repr=False)
    probe_store: object = field(repr=False)
    inventory: object = field(repr=False)
    customization: object = field(repr=False)
    runtime: object = field(repr=False)
    target: object = field(repr=False)
    review: dict = field(repr=False)
    settings: object = field(repr=False)
    work: object = field(repr=False)
    private_home: object = field(repr=False)
    compatdata: object = field(repr=False)
    prefix_version: str
    # Journal of the origin record: probe trials, or registered-game new prefixes.
    records: str = "trials"
    # Runtime writes the contract accepted in the tool (DroidDeck redist markers, CPython caches), or None.
    tool_writes: object = None

    def summary(self):
        return {"scope": SCOPE, "input_digest": self.digest, "trial_id": self.record["trial_id"],
                "origin_status": self.record["status"], "app_id": self.record["app_id"],
                "prefix": str(self.compatdata), "command": ["runinprefix", "cmd.exe", "/d", "/c", "exit", "0"],
                "runtime_contract": FEX_RUNTIME_CONTRACT, "tool_runtime_writes": self.tool_writes,
                "prefix_reinitialized": False,
                "old_trial_record_updated": False, "execution_authorized": False,
                "device_namespace_verified": False, "preparation_complete": False, "writes": []}


def read_payload_inventory(config, directory):
    """The verified payload inventory from the asset folder, read once for several registered-game plans."""
    from preparation_selection import _archive
    payload = config["payload"]
    return inspect_archive_from_folder(_archive(safe_path(directory), payload), payload["sha512"], payload["root"], capture=CAPTURE)


def plan_recheck(**kwargs):
    """Read-only managed recheck plan; a failure carries the name of the check that stopped it."""
    progress = ["recheck-trial-record"]
    try:
        return _plan_recheck(progress, **kwargs)
    except (OSError, ValueError, TypeError, KeyError) as error:
        if not hasattr(error, "preparation_check"):
            error.preparation_check = progress[-1]
        raise


def _plan_recheck(progress, *, record, record_sha256, config, directory, renderer, source, games, steam, settings, home,
                  environment, runtime_root, records="trials", inventory=None):
    require(records in ("trials", "game-prefixes"), "unknown managed prefix journal")
    require(inventory is None or records == "game-prefixes", "probe trials read their archive themselves")
    if records == "trials":
        validate_trial_record(record)
        require(record["exit_code"] == 0 and record.get("settings_identity_unchanged") is True,
                "prior fixed-command exit and unchanged settings required")
        require(record["phase"] == "post-checks", "completed command phase required")
        require(record["status"] == "initialized-unverified" or record["status"] == "failed" and
                record.get("error", {}).get("error_class") == "TreeMismatch" and record["phase"] == "post-checks",
                "only initialized or tree-mismatch trial can be rechecked")
        key = record["app_id"]
        require(key in games, "trial registration missing")
    else:
        key = _game_record(record, games)
    steam, settings, home = map(safe_path, (steam, settings, home))
    store_root = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store", home)
    probe_store = safe_path(store_root.parent / "probe-store", home)
    with PrivateStore(store_root) as store:
        require(store.read_record(records, record["trial_id"] + ".json")[1] == record_sha256, "trial record changed")
    proof = None
    if records == "trials":
        progress.append("recheck-registration-pin")
        exe = safe_path(games[key]["exe"])
        target = pin_registration(source, key, exe.parent, steam)
        progress.append("recheck-probe-registration")
        proof = inspect_existing_probe_registration(exe, key, source, steam, probe_store)
    else:
        target, exe = _game_registration(progress, record, source, games, steam)
    progress.append("recheck-build-review")
    payload = config["payload"]
    require(payload.get("tool_slot") == "preparation", "reviewed preparation slot required")
    review = validate_build_review(config["placement_review"])
    require(review["archive_sha512"] == payload["sha512"] and
            (proof is None or proof["source_archive_sha512"] == payload["sha512"]), "recheck source identity differs")
    progress.append("recheck-payload-archive")
    from preparation_selection import _archive
    # Registered-game prefixes read the archive from the operator's asset folder without comparing
    # timestamps (every byte is hashed); probe trials keep the strict read.
    if inventory is None:
        read_archive = inspect_archive if records == "trials" else inspect_archive_from_folder
        inventory = read_archive(_archive(directory, payload), payload["sha512"], payload["root"], capture=CAPTURE)
    else:
        # The status check reads the archive once with read_payload_inventory (operational entry 6.2).
        require(isinstance(inventory, PayloadInventory) and inventory.archive_sha512 == payload["sha512"] and
                inventory.root == payload["root"], "payload inventory differs")
    require(proof is None or proof["source_inventory_digest"] == inventory.digest, "probe source inventory differs")
    progress.append("recheck-runtime-environment")
    runtime = plan_runtime_environment(runtime_root, config["runtime_reference"], environment)
    _require_live(runtime)
    progress.append("recheck-tool-customization")
    custom = plan_customizations(inventory, payload["archive"], payload["mode"], runtime_root / "usr/local/bin/steam-compatibility",
        renderer, label=runtime.label, umask=int(runtime.umask, 8), tool_slot="preparation")
    progress.append("recheck-fex-tool-tree")
    tool = safe_path(steam / "compatibilitytools.d" / custom.directory, steam)
    tool_writes = runtime_writes(verify_fex_runtime_tree(tool, inventory, custom.overlays))
    progress.append("recheck-payload-permissions")
    policy = reviewed_payload_permissions(inventory, steam, review)
    if policy is not None:
        policy.guard()
    compatdata, version = _game_prefix(progress, steam, key, None if records == "trials" else record)
    progress.append("recheck-private-paths")
    work = safe_path(home / ".local/share/droiddeck-preparation-work" / key / "work", home)
    private_home = safe_path(work.parent / "home", home)
    for path in (work, private_home):
        _private_existing(path, home)
        for protected in (steam, settings, exe.parent, store_root):
            require(path != protected and not path.is_relative_to(protected) and not protected.is_relative_to(path),
                    "recheck paths overlap protected data")
    require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
    progress.append("recheck-settings")
    signature = {"version": VERSION, "scope": SCOPE, "records": records, "record": record_sha256, "archive": inventory.archive_sha512,
                 "inventory": inventory.digest, "customization": custom.digest, "runtime": runtime.identity_digest,
                 "target": target.digest, "prefix_version": version, "work": str(work), "home": str(private_home),
                 "contract": FEX_RUNTIME_CONTRACT, "settings": _settings(steam, settings), "tool_runtime_writes": tool_writes}
    return RecheckPlan(digest_json(signature), record, record_sha256, store_root, probe_store, inventory, custom,
                      runtime, target, review, settings, work, private_home, compatdata, version, records, tool_writes)


def _game_record(record, games):
    """A completed game-prefix initialization record whose registration still exists. Returns the app ID."""
    from preparation_game_prefix import ID_PREFIX
    from preparation_game_prefix import SCOPE as GAME_SCOPE
    validate_trial_record(record, GAME_SCOPE, ID_PREFIX)
    require(record["exit_code"] == 0 and record.get("settings_identity_unchanged") is True,
            "prior fixed-command exit and unchanged settings required")
    require(record["phase"] == "post-checks", "completed command phase required")
    require(record["status"] == "initialized-unverified", "only initialized or tree-mismatch trial can be rechecked")
    require(record["app_id"] in games, "trial registration missing")
    return record["app_id"]


def _game_registration(progress, record, source, games, steam):
    """Registration pin, and the registration and game EXE measured at initialization (game prefixes)."""
    from preparation_assets import exe_identity
    from preparation_game_prefix import registration_identity
    key = record["app_id"]
    progress.append("recheck-registration-pin")
    exe = safe_path(games[key]["exe"])
    target = pin_registration(source, key, exe.parent, steam)
    # The game EXE must still be the one measured when the prefix was initialized.
    progress.append("recheck-game-registration")
    require(registration_identity(exe, games[key]["title"]) ==
            {name: record["profile"][name] for name in ("exe_path_sha256", "title_sha256")},
            "game registration path or title changed since initialization")
    progress.append("recheck-game-executable")
    identity = exe_identity(exe)
    require({"sha256": identity["sha256"], "size": identity["size"]} ==
            {key_: record["profile"]["exe_" + key_] for key_ in ("sha256", "size")}, "game executable changed")
    return target, exe


def _game_prefix(progress, steam, key, record):
    """The prefix: private directory, no aliases, its version, and (with ``record``) the initialized layout."""
    progress.append("recheck-prefix")
    compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
    _private_existing(compatdata, steam)
    _aliases(steam, key)
    version = _prefix(compatdata)
    if record is not None:
        _initialized_prefix(compatdata, record, version)
    return compatdata, version


def check_game_identity(*, record, record_sha256, source, games, steam, home):
    """The payload-independent part of a registered-game recheck (design: Proton update 4.8).

    The same checks as ``plan_recheck`` for ``game-prefixes`` (shared functions, same check
    names): the initialization record (completed, unchanged), the registration and the game
    EXE measured at initialization, and the prefix (private directory, no aliases, unchanged
    version, the initialized directories). It reads no payload and does not verify any
    preparation slot, so a revert works while the bundle slot is broken.
    Returns {"target", "compatdata", "prefix_version", "exe"}.
    """
    progress = ["recheck-trial-record"]
    try:
        key = _game_record(record, games)
        steam, home = safe_path(steam), safe_path(home)
        store_root = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store", home)
        with PrivateStore(store_root) as store:
            require(store.read_record("game-prefixes", record["trial_id"] + ".json")[1] == record_sha256,
                    "trial record changed")
        target, exe = _game_registration(progress, record, source, games, steam)
        compatdata, version = _game_prefix(progress, steam, key, record)
        return {"target": target, "compatdata": compatdata, "prefix_version": version, "exe": exe}
    except (OSError, ValueError, TypeError, KeyError) as error:
        if not hasattr(error, "preparation_check"):
            error.preparation_check = progress[-1]
        raise


def validate_recheck_record(record):
    fields(record, ("schema_version", "tool_version", "scope", "recheck_id", "trial_id", "app_id", "input_digest", "status",
                    "exit_code", "prefix_version_sha256", "runtime_contract", "old_trial_record_updated",
                    "runtime_execution_verified", "device_namespace_verified", "preparation_complete"),
           ("error", "stop_observation", "settings_identity_unchanged"))
    require(record["schema_version"] == 1 and type(record["schema_version"]) is int and record["scope"] == SCOPE,
            "unsupported recheck record")
    require(type(record["recheck_id"]) is str and record["recheck_id"].startswith("recheck-") and
            len(record["recheck_id"]) == 40 and all(c in "0123456789abcdef" for c in record["recheck_id"][8:]), "invalid recheck ID")
    require(app_id(record["app_id"]) == record["app_id"] and record["status"] in ("running", "needs-user", "failed", "probe-exited-unverified"),
            "invalid recheck state")
    require(type(record["tool_version"]) is str and 0 < len(record["tool_version"]) <= 64, "invalid recheck version")
    require(type(record["trial_id"]) is str and record["trial_id"].startswith("trial-") and len(record["trial_id"]) == 38 and
            all(c in "0123456789abcdef" for c in record["trial_id"][6:]), "invalid recheck trial origin")
    require(all(type(record[name]) is str and SHA256.fullmatch(record[name]) for name in
                ("input_digest", "prefix_version_sha256")), "invalid recheck digests")
    require(record["runtime_contract"] == FEX_RUNTIME_CONTRACT, "unknown recheck runtime contract")
    require(record["exit_code"] is None or type(record["exit_code"]) is int, "invalid recheck exit code")
    require(all(record[name] is False for name in ("old_trial_record_updated", "runtime_execution_verified",
                                                "device_namespace_verified", "preparation_complete")), "recheck cannot grant full readiness")
    return record


class RecheckSession:
    def __init__(self, plan, store, refresh, confirmation, stop_check):
        require(isinstance(plan, RecheckPlan), "trusted managed recheck plan required")
        self.plan, self.store, self.refresh, self.confirmation = plan, store, refresh, confirmation
        self.stop = stop_check
        self.process, self.hash = None, None
        self.settings_identity = _settings(plan.target.steam, plan.settings)
        self.record = {"schema_version": 1, "tool_version": VERSION, "scope": SCOPE, "recheck_id": "recheck-" + secrets.token_hex(16),
            "trial_id": plan.record["trial_id"], "app_id": plan.record["app_id"], "input_digest": plan.digest,
            "status": "running", "exit_code": None, "prefix_version_sha256": plan.prefix_version,
            "runtime_contract": FEX_RUNTIME_CONTRACT, "old_trial_record_updated": False,
            "runtime_execution_verified": False, "device_namespace_verified": False, "preparation_complete": False}

    def _save(self):
        validate_recheck_record(self.record)
        self.hash = self.store.write_record("rechecks", self.record["recheck_id"] + ".json", self.record, expected_hash=self.hash)
        return dict(self.record)

    def _guard(self):
        p = self.plan
        self.store._guard()
        require(self.store.root == p.store_root and self.store._held_target == hashlib.sha256(str(p.compatdata).encode()).hexdigest(),
                "matching recheck locks required")
        require(isinstance(self.stop, ProcessStopCheck) and self.stop.compatdata == p.compatdata, "matching process observation required")
        require(self.store.read_record(p.records, p.record["trial_id"] + ".json")[1] == p.record_sha256, "original trial changed")
        _require_live(p.runtime)
        p.target.verify()
        p.runtime.verify()
        policy = reviewed_payload_permissions(p.inventory, p.target.steam, p.review)
        if policy is not None:
            policy.guard()
        require(runtime_writes(verify_fex_runtime_tree(safe_path(p.target.steam / "compatibilitytools.d" / p.customization.directory),
                                                       p.inventory, p.customization.overlays)) == p.tool_writes,
                "tool runtime writes changed")
        _private_existing(p.compatdata, p.target.steam)
        _aliases(p.target.steam, p.record["app_id"])
        require(_prefix(p.compatdata) == p.prefix_version, "managed prefix version changed")
        if p.records != "trials":
            _initialized_prefix(p.compatdata, p.record, p.prefix_version)
        require(_settings(p.target.steam, p.settings) == self.settings_identity, "settings changed during recheck")
        require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
        for path in (p.work, p.private_home):
            _private_existing(path, p.work.parents[4])

    def start(self):
        require(self.hash is None and self.process is None and self.confirmation == self.plan.digest, "exact unused confirmation required")
        require(self.refresh().digest == self.plan.digest, "recheck plan changed")
        self._guard()
        require(self.stop.check()["clear_in_view"], "target process view not clear")
        p = self.plan
        entries = {**p.inventory.entries, **p.customization.overlays}
        hashes = {name: entries[name]["sha256"] if name in entries else None for name in ("proton", "version", "user_settings.py")}
        launch = plan_launch(tool=safe_path(p.target.steam / "compatibilitytools.d" / p.customization.directory),
            steam=p.target.steam, registration_id=p.record["app_id"], install=p.target.exe.parent, work=p.work, home=p.private_home,
            runtime_environment=p.runtime.environment, expected_hashes=hashes, payload_inventory=p.inventory,
            payload_overlays=p.customization.overlays, target_pin=p.target, runtime_plan=p.runtime, operation="probe",
            prefix_version_sha256=p.prefix_version, trial_recheck_id=p.record["trial_id"])
        self._save()
        try:
            self._guard()
            require(self.stop.check()["clear_in_view"], "target process view changed")
            require_no_bytecode_cache(launch)
            self.process = subprocess.Popen(launch.argv, cwd=p.work, env=launch.environment, shell=False, close_fds=True,
                start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.record.update(status="failed", error={"check": "recheck-spawn", "error_class": type(error).__name__,
                                                       "errno": getattr(error, "errno", None)})
            self._save()
            raise
        return self

    def wait(self, timeout=30):
        require(type(timeout) is int and 1 <= timeout <= 120 and self.process is not None, "bounded live recheck wait required")
        if self.record["status"] in ("failed", "probe-exited-unverified"):
            return dict(self.record)
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.record["status"] = "needs-user"
            return self._save()
        self.record["exit_code"] = code
        try:
            self.record["settings_identity_unchanged"] = _settings(self.plan.target.steam, self.plan.settings) == self.settings_identity
            observation = self.stop.check()
            deadline = time.monotonic() + min(5, timeout)
            while not observation["clear_in_view"] and time.monotonic() < deadline:
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
                observation = self.stop.check()
            self.record["stop_observation"] = observation
            if not observation["clear_in_view"]:
                self.record["status"] = "needs-user"
            else:
                self._guard()
                self.record["status"] = "probe-exited-unverified" if code == 0 else "failed"
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.record.update(status="failed", error={"check": "recheck-postconditions", "error_class": type(error).__name__,
                                                       "errno": getattr(error, "errno", None)})
            if hasattr(error, "tree_diagnostic"):
                self.record["error"]["tree_diagnostic"] = error.tree_diagnostic
        return self._save()


def interactive_recheck(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                        steam=None, settings=None, home=None, runtime_root=Path("/")):
    import sys

    import preparation_selection as selection
    from preparation_binding import droiddeck_lock

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    protected, session, started = [steam, settings], None, False
    stage = "recheck-plan"
    try:
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True, "trial recheck not enabled")
        with PrivateStore(management) as store:
            records = [item for item in store.inventory()["trials"] if item["status"] != "invalid"]
            require(records, "no private trial records")
            for index, item in enumerate(records, 1):
                print(f"{index}. ID {item['app_id']} / {item['status']} / {item['trial_id']}", file=output)
            print("再照会する管理済み試験記録の番号（qで取消）: ", end="", file=output, flush=True)
            answer = stream.readline(32).strip()
            if answer == "q":
                return 0, None
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(records), "invalid recheck selection")
            record, digest = store.read_record("trials", records[int(answer) - 1]["trial_id"] + ".json")
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())

        def refresh():
            current, _, now = selection.registration_catalog(environment)
            require(current == source, "registration source changed")
            return plan_recheck(record=record, record_sha256=digest, config=config, directory=directory, renderer=renderer,
                source=source, games=now, steam=steam, settings=settings, home=home, environment=environment, runtime_root=runtime_root)

        print("既存prefixとtool全体を再照合し、FEX AppConfigが本人所有0700の空directoryか検査しています。", file=output, flush=True)
        plan = refresh()
        print("対象prefix: " + selection._text(str(plan.compatdata)), file=output)
        print("実行: 準備用Proton runinprefix cmd.exe /d /c exit 0（初期化はしません）", file=output)
        print("変更範囲: この試験prefixの通常起動時の状態、既存の専用work/HOME、新しい再照会記録/lock、結果JSON。", file=output)
        print("旧failed記録・ゲーム・installer・割り当て設定は変更しません。", file=output)
        print("全ゲーム・Wineを終了してください。他namespaceの停止保証はありません。", file=output)
        print("この再照会を実行する場合は1、取消はq: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            return 0, None
        started, stage = True, "recheck-start"
        selection._private_report_directory(home, protected)
        lock = hashlib.sha256(str(plan.compatdata).encode()).hexdigest()
        with PrivateStore(management) as store, store.locked(lock), droiddeck_lock(settings):
            session = RecheckSession(plan, store, refresh, plan.digest, ProcessStopCheck(plan.compatdata))
            session.start()
            stage = "recheck-wait"
            while True:
                outcome = session.wait(30)
                if outcome["status"] != "needs-user":
                    break
                print("未完了です。強制終了していません。1で再待機、qで記録を残して戻る: ", end="", file=output, flush=True)
                if stream.readline(32).strip() != "1":
                    break
            report = {"mode": "managed-trial-recheck-result", "scope": SCOPE, "recheck": outcome,
                      "old_trial_record_unchanged": store.read_record("trials", record["trial_id"] + ".json")[1] == digest,
                      "prefix_reinitialized": False, "binding_written": False, "preparation_complete": False,
                      "writes": [{"scope": "existing-managed-trial-prefix-and-private-work-home"},
                                 {"scope": "new-private-recheck-journal-and-locks"}, {"scope": "cooperative-settings-lock-only"}]}
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "managed-trial-recheck-result", "scope": SCOPE, "stage": stage,
                  "error_class": type(error).__name__, "errno": getattr(error, "errno", None),
                  "reason": {"FEX AppConfig is not empty; configuration not permitted": "fex-appconfig-not-empty",
                             "FEX AppConfig must be owned empty 0700 directory": "fex-appconfig-ownership-or-mode",
                             "private 0700 tool parent required for FEX runtime contract": "tool-parent-not-private-0700"}.get(str(error), "input-rejected"),
                  **input_change(error),
                  "prefix_reinitialized": False, "preparation_complete": False,
                  "writes": [] if not started else [{"scope": "partial-managed-recheck-preserve"}]}
        if hasattr(error, "tree_diagnostic"):
            report["tree_diagnostic"] = error.tree_diagnostic
        if session is not None:
            report["recheck"] = dict(session.record)
        print("再照会は停止しました。既存prefixと旧記録を保全して結果を保存します。", file=output)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録とprefixは削除していません。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    return 2, str(saved)
