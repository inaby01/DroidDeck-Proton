"""Scoped static placement of a new preparation slot, never execution readiness.

A distribution-pinned build review and explicit confirmation authorize copying
only the reviewed tree into a new slot. The full installation/launch readiness
API remains unchanged; no stopped/runtime-execution flags are fabricated here.
"""

import copy
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import digest_json
from preparation_common import (
    VERSION,
    checked,
    fields,
    input_change,
    require,
    safe_path,
)
from preparation_installation import InstallationPlan
from preparation_payload import verify_tree
from preparation_probe import verify_probe_registration
from preparation_tool_writer import _PrivateXaliaModes, _write_installation_tree


def validate_build_review(review):
    fields(review, ("schema_version", "basis", "archive_sha512", "source_commit", "run_id", "artifact_id",
                    "artifact_zip_sha256", "build_info_sha256"), ("private_xalia_files",))
    require(type(review["schema_version"]) is int and review["schema_version"] == 1 and
            review["basis"] == "github-artifact-zip-and-inner-sha512", "unsupported build review")
    for name, length in (("archive_sha512", 128), ("source_commit", 40), ("artifact_zip_sha256", 64), ("build_info_sha256", 64)):
        require(type(review[name]) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", review[name]), "invalid build review digest")
    for name in ("run_id", "artifact_id"):
        require(type(review[name]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", review[name]), "invalid build reference")
    files = review.get("private_xalia_files", [])
    require(type(files) is list and len(files) <= 128 and all(type(name) is str and
            re.fullmatch(r"files/share/xalia/[A-Za-z0-9_.-]+", name) and name.rsplit("/", 1)[-1] not in (".", "..", ".env")
            for name in files) and len(set(files)) == len(files), "invalid reviewed Xalia file list")
    return review


@dataclass(frozen=True)
class StaticPlacementPlan:
    digest: str
    installation: object = field(repr=False)
    review: dict = field(repr=False)
    probe: dict = field(repr=False)
    store_root: object = field(repr=False)
    probe_store_root: object = field(repr=False)
    settings: object = field(repr=False)
    # "probe": a verified registration probe (detailed menu 4); "confirmation": an ordinary registered game,
    # only read, standing in for the probe in the operational entry (design: operational entry 4).
    witness: str = "probe"

    def _witness_key(self):
        return "probe_registration" if self.witness == "probe" else "confirmation_registration"

    def summary(self):
        summary = self.installation.summary()
        return {"mode": "static-preparation-tool-plan", "input_digest": self.digest, "scope": "static-preparation-slot-only",
                "action": summary["action"], "destination": summary["destination"], "capacity": summary["capacity"],
                "review": dict(self.review), self._witness_key(): dict(self.probe),
                "planned_writes": summary["planned_writes"] + ([] if summary["action"] == "reuse-verified-tree" else [
                    {"path": str(self.store_root), "action": "private-installation-journal-and-locks"},
                    {"path": str(self.settings / "lock"), "action": "cooperative-settings-lock-only"}]),
                "private_xalia_context": {"reviewed_files": len(self.review.get("private_xalia_files", [])),
                                          "required_tool_parent_mode": "0700" if self.review.get("private_xalia_files") else None,
                                          "payload_modes_changed": False},
                "execution_authorized": False, "prefix_initialization_authorized": False, "binding_authorized": False,
                "full_preparation_blockers": [x for x in summary["blockers"] if x != "payload-provenance-unreviewed"],
                "preparation_complete": False, "writes": []}


def _signature(installation, review, proof, store_root, probe_store_root, settings, witness="probe"):
    report = installation.summary()
    fixed = {name: report[name] for name in ("action", "destination", "mode", "tool_slot", "prefix")}
    fixed["capacity"] = {name: report["capacity"][name] for name in ("scope", "estimated_additional_bytes", "reserve_bytes")}
    return digest_json({"tool_version": VERSION, "scope": "static-preparation-slot-only", "installation": installation.digest,
                       "fixed_plan": fixed,
                       "review": review, "probe": proof, "store": str(store_root), "probe_store": str(probe_store_root), "settings": str(settings),
                       **({} if witness == "probe" else {"witness": witness})})


def _proof(installation, probe_store_root):
    target = installation.target
    return checked("placement-probe-registration", verify_probe_registration, target.exe, target.registration_id,
                   target.source, target.steam, probe_store_root)


def game_folder_apart(folder, roots):
    """A confirmation game folder may neither contain nor lie inside Steam, the settings or the tool store."""
    folder = safe_path(folder)
    require(not any(root == folder or root.is_relative_to(folder) or folder.is_relative_to(root) for root in map(safe_path, roots)),
            "game folder overlaps tool folders")


def _confirmation(installation, settings, store_root):
    """An ordinary registered game, only read: the registration source and the game EXE the tool sees are the
    ones DroidDeck records (pinned), and exactly one registration points at that EXE. Placement neither reads
    nor writes the game's prefix, so its presence does not matter (design: operational entry 4.2)."""
    from preparation_common import load_json
    from preparation_probe import EXE
    from preparation_target import registrations
    target = installation.target
    require(target.exe.name != EXE, "probe registrations use the detailed placement")
    game_folder_apart(target.exe.parent, (target.steam, settings, store_root))
    target.verify()
    games = registrations(load_json(target.source)[0])
    matches = []
    for game in games.values():
        try:
            if os.path.samefile(safe_path(game["exe"]), target.exe):
                matches.append(game["app_id"])
        except (FileNotFoundError, ValueError):
            continue  # an unrelated stale entry is not this executable
    require(matches == [target.registration_id], "ambiguous confirmation registration")
    return {"kind": "confirmation-registration", "app_id": target.registration_id, "registration_pin": target.digest,
            "source_archive_sha512": installation.inventory.archive_sha512,
            "source_inventory_digest": installation.inventory.digest}


def _witness(plan_or_kind, installation, probe_store_root, settings, store_root):
    kind = plan_or_kind if isinstance(plan_or_kind, str) else plan_or_kind.witness
    return _proof(installation, probe_store_root) if kind == "probe" else _confirmation(installation, settings, store_root)


def _private_xalia_context(installation, review):
    return reviewed_payload_permissions(installation.inventory, installation.target.steam, review)


def reviewed_payload_permissions(inventory, steam, review):
    entries = inventory.entries
    require(not inventory.root_mode & 0o022 and inventory.root_mode & 0o500 == 0o500,
            "unsupported payload root permissions")
    unsupported = {name for name, entry in entries.items() if entry["kind"] in ("file", "directory", "hardlink") and
                   (entry["mode"] & 0o022 or not entry["mode"] & 0o400 or entry["kind"] == "directory" and not entry["mode"] & 0o100)}
    approved = set(review.get("private_xalia_files", []))
    require(unsupported == approved and all(entries[name]["kind"] == "file" and entries[name]["mode"] == 0o666 for name in approved),
            "payload permissions have not been reviewed for this archive")
    if not approved:
        return None
    parent = safe_path(steam / "compatibilitytools.d", steam)
    policy = _PrivateXaliaModes(inventory.digest, frozenset(approved), parent)
    if parent.exists():
        policy.guard()
    return policy


def plan_static_placement(installation, review, store_root, probe_store_root, settings):
    return _plan_placement(installation, review, store_root, probe_store_root, settings, "probe")


def plan_confirmed_placement(installation, review, store_root, settings):
    """Placement for the operational entry: the confirmation registration replaces the probe."""
    return _plan_placement(installation, review, store_root, None, settings, "confirmation")


def _plan_placement(installation, review, store_root, probe_store_root, settings, witness):
    require(isinstance(installation, InstallationPlan), "trusted installation plan required")
    review = copy.deepcopy(validate_build_review(review))
    store_root, settings = safe_path(store_root), safe_path(settings)
    probe_store_root = None if probe_store_root is None else safe_path(probe_store_root)
    report = installation.summary()
    require(report["tool_slot"] == "preparation" and installation.customization.summary()["tool_slot"] == "preparation" and
            installation.inventory.archive_sha512 == review["archive_sha512"] and report["payload"]["archive_sha512"] == review["archive_sha512"],
            "reviewed preparation slot required")
    if witness == "probe":
        # The dedicated probe trial needs a registration without a prefix; placement itself does not.
        require(not report["prefix"]["exists"], "new prefix required")
    require(settings.is_dir(), "existing settings directory required")
    steam = safe_path(installation.target.steam)
    expected_destination = safe_path(steam / "compatibilitytools.d" / installation.customization.directory, steam)
    require(report["destination"] == str(expected_destination), "placement destination differs from generated slot")
    require(steam != settings and not steam.is_relative_to(settings) and not settings.is_relative_to(steam), "settings overlap Steam")
    for root in (steam, settings, installation.target.exe.parent, *([] if probe_store_root is None else [probe_store_root])):
        require(not (store_root == root or store_root.is_relative_to(root) or root.is_relative_to(store_root)), "placement store overlaps inputs")
    if installation.runtime.view != "current-root":
        require(all(path != installation.runtime.root and path.is_relative_to(installation.runtime.root) for path in
                    (steam, settings, store_root, *([] if probe_store_root is None else [probe_store_root]),
                     safe_path(installation.target.source), installation.target.exe)),
                "snapshot placement must remain inside snapshot")
    else:
        require(str(installation.runtime.root) == "/", "live root required")
    _private_xalia_context(installation, review)
    proof = _witness(witness, installation, probe_store_root, settings, store_root)
    require(proof["source_archive_sha512"] == review["archive_sha512"] and
            proof["source_inventory_digest"] == installation.inventory.digest, "probe and placement archive identities differ")
    installation.target.verify()
    installation.runtime.verify()
    digest = _signature(installation, review, proof, store_root, probe_store_root, settings, witness)
    return StaticPlacementPlan(digest, installation, review, proof, store_root, probe_store_root, settings, witness)


def _same_plan(current, expected):
    if not isinstance(current, StaticPlacementPlan):
        return False
    a, b = current.installation, expected.installation
    return (current.digest == expected.digest and current.review == expected.review and current.probe == expected.probe and
            current.store_root == expected.store_root and current.probe_store_root == expected.probe_store_root and
            current.settings == expected.settings and current.witness == expected.witness and a.digest == b.digest and a.target == b.target and
            a.inventory == b.inventory and a.customization == b.customization and a.runtime.identity_digest == b.runtime.identity_digest and
            a.archive == b.archive)


def apply_static_placement(plan, refresh, store, confirmed_digest):
    """Only this narrow operation can omit launch readiness; it cannot launch."""
    require(isinstance(plan, StaticPlacementPlan) and callable(refresh), "trusted static placement plan required")
    store._guard()
    require(confirmed_digest == plan.digest and plan.digest == _signature(plan.installation, plan.review, plan.probe,
            plan.store_root, plan.probe_store_root, plan.settings, plan.witness), "exact placement confirmation required")
    installation = plan.installation
    private_xalia = _private_xalia_context(installation, plan.review)
    compatdata = safe_path(installation.target.steam / "steamapps/compatdata" / installation.target.registration_id,
                          installation.target.steam)
    require(store.root == plan.store_root and store._held_target == hashlib.sha256(str(compatdata).encode()).hexdigest(),
            "matching placement locks required")
    fresh = refresh()
    require(_same_plan(fresh, plan), "static placement plan changed")
    if installation.summary()["action"] == "reuse-verified-tree":
        return {**plan.summary(), "mode": "static-matching-tool-observed", "material_installed_now": False}
    require(fresh.installation.summary()["capacity"]["estimate_fits"], "insufficient static placement capacity")
    require(not os.path.lexists(safe_path(installation.summary()["destination"])), "new slot must be absent")

    def ready(published=False):
        store._guard()
        if private_xalia is not None and private_xalia.parent.exists():
            private_xalia.guard()
        require(_witness(plan, installation, plan.probe_store_root, plan.settings, plan.store_root) == plan.probe,
                "placement probe changed")
        installation.target.verify()
        installation.runtime.verify()
        destination = safe_path(installation.summary()["destination"])
        if published:
            verify_tree(destination, installation.inventory, installation.customization.overlays)
        else:
            require(not os.path.lexists(destination), "static placement destination appeared")

    def current_installation():
        current = refresh()
        require(_same_plan(current, plan), "static placement inputs changed")
        return current.installation

    result = checked("placement-filesystem-transaction", _write_installation_tree, installation, current_installation,
                     store, plan.settings, ready, private_xalia)
    return {"mode": "static-preparation-tool-installed", "scope": "static-preparation-slot-only", "installation": result,
            "destination": installation.summary()["destination"], "review_digest": digest_json(plan.review),
            plan._witness_key(): plan.probe, "material_installed_now": True,
            "private_xalia_context": plan.summary()["private_xalia_context"],
            "writes": [{"path": installation.summary()["destination"], "scope": "new-static-preparation-tool-tree"},
                       {"path": str(store.root), "scope": "private-installation-journal-and-locks"},
                       {"path": str(plan.settings / "lock"), "scope": "cooperative-settings-lock-only"}],
            "prefix_created": False, "binding_written": False, "wine_executed": False,
            "execution_authorized": False, "preparation_complete": False}


def interactive_static_placement(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                                 steam=None, settings=None, home=None, runtime_root=Path("/")):
    import sys

    import preparation_selection as selection
    from preparation_installation import plan_installation
    from preparation_store import PrivateStore

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    directory = safe_path(directory)
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    probe_store = safe_path(home / ".local/state/droiddeck-prefix-preparation/probe-store")
    management = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store")
    protected = [steam, settings]
    stage, started, report = "static-placement-selection", False, None
    try:
        config = selection.validate_selection_config(copy.deepcopy(config))
        require("placement_review" in config, "reviewed build distribution required")
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        candidates = [key for key in games if Path(games[key]["exe"]).name == "prefix-probe.exe"]
        require(candidates, "registered preparation probe required")
        for index, key in enumerate(candidates, 1):
            print(f"{index}. {selection._text(games[key]['title'])}  [ID {key}]", file=output)
        print("対象の検証用登録番号（qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32).strip()
        if not answer or answer.lower() == "q":
            print("取り消しました。", file=output)
            return 0, None
        require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(candidates), "invalid target selection")
        key = candidates[int(answer) - 1]
        exe = safe_path(games[key]["exe"])
        stage = "static-placement-plan"
        payload = config["payload"]
        archive = selection._archive(directory, payload)

        def refresh():
            installation = plan_installation(archive=archive, sha512=payload["sha512"], archive_root=payload["root"],
                mode=payload["mode"], runtime_root=runtime_root, runtime_audit=config["runtime_reference"], registrations=source,
                registration_id=key, exe_root=exe.parent, steam=steam, renderer=renderer, parent_environment=environment,
                tool_slot="preparation")
            return plan_static_placement(installation, config["placement_review"], management, probe_store, settings)

        print("配布物全体・runtime識別・復帰済み登録・prefix不在を検査しています。", file=output, flush=True)
        plan = refresh()
        preview = plan.summary()
        print("配置先: " + selection._text(preview["destination"]), file=output)
        if preview["action"] == "reuse-verified-tree":
            print("既存の準備用toolは期待ツリー全体と一致しています。今回は配置し直しません。", file=output)
            report = {**preview, "mode": "static-matching-tool-observed", "material_installed_now": False}
        else:
            require(preview["capacity"]["estimate_fits"], "insufficient estimated static placement space")
            capacity = preview["capacity"]
            print(f"配置の見積: {capacity['estimated_additional_bytes'] / 1024**3:.2f} GiB / 空き {capacity['available_bytes'] / 1024**3:.1f} GiB", file=output)
            if plan.review.get("private_xalia_files"):
                print(f"Xaliaファイル{len(plan.review['private_xalia_files'])}件は出荷権限を保持し、親のcompatibilitytools.d（0700）が私有のままの場合だけ配置します。", file=output)
            print("来歴: 確認済みGitHub build " + plan.review["run_id"] + " / commit " + plan.review["source_commit"][:12], file=output)
            print("新しい準備用toolのファイル、staging、私有記録／lock、DroidDeck設定lock、結果JSONを書きます。", file=output)
            print("既存Proton・ゲーム・EXE・目印・prefix・割り当て設定は変更しません。Wineも起動しません。", file=output)
            print("この範囲で配置する場合は1、取消はq: ", end="", file=output, flush=True)
            if stream.readline(32).strip() != "1":
                print("取り消しました。", file=output)
                return 0, None
            stage, started = "static-placement-apply", True
            selection._private_report_directory(home, protected)
            compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
            lock = hashlib.sha256(str(compatdata).encode()).hexdigest()
            print("lock下で再検査し、新規toolを展開・全体照合・非上書き配置します。", file=output, flush=True)
            with PrivateStore(management, create=True) as store, store.locked(lock):
                report = apply_static_placement(plan, refresh, store, plan.digest)
            print("新しい準備用Protonを配置し、全体一致を確認しました。まだ起動しません。", file=output)
        stage = "static-placement-followup-plan"
        source_now, digest_now, games_now = selection.registration_catalog(environment)
        print("同じ対象の次の準備計画を保存しています。", file=output, flush=True)
        report["followup_plan"] = selection.selected_plan(directory, config, key, source_now, digest_now, games_now,
            steam, settings, home, renderer, environment, runtime_root)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        failure = {"stage": stage, "check": getattr(error, "preparation_check", stage), "error_class": type(error).__name__,
                   "errno": getattr(error, "errno", None), "reason": {
                       "reviewed Xalia modes require a private 0700 tool parent": "tool-parent-not-owned-private-0700",
                       "payload permissions have not been reviewed for this archive": "payload-mode-review-mismatch",
                       "reviewed preparation slot required": "reviewed-payload-slot-mismatch",
                       "probe and placement archive identities differ": "probe-payload-identity-mismatch",
                       "existing installation differs from approved generated trees": "existing-preparation-tree-differs",
                       "new prefix required": "prefix-already-exists",
                       "insufficient estimated static placement space": "insufficient-static-capacity",
                       "runtime source/library/label changed since audit": "runtime-identity-changed",
                       "archive missing or ambiguous": "archive-missing-or-ambiguous"}.get(str(error), "input-rejected"),
                   **input_change(error)}
        if report is None:
            report = {"mode": "static-placement-stopped", "published_tree_or_staging_may_exist": started,
                      "private_records_may_have_changed": started, "prefix_created": False, "binding_written": False,
                      "wine_executed": False, "writes": [] if not started else [
                          {"scope": "static-placement-outcome-unknown-preserve-and-reinspect", "path": str(steam / "compatibilitytools.d")}]}
        report["error"] = failure
        print("処理停止: " + failure["check"] + " / " + failure["reason"] + " / " + failure["error_class"] + " / errno=" + str(failure["errno"]), file=output)
        print("途中のtoolやstaging、記録は削除せず保持します。結果JSONを確認してください。", file=output)
    report.update(schema_version=1, tool_version=VERSION, preparation_complete=False)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。表示された停止段階を確認してください。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(saved if saved.parent != directory else saved.name), file=output)
    return 2, str(saved) if saved.parent != directory else saved.name


def _confirmation_candidates(games, steam, settings, management):
    """(selectable, excluded) registrations for the operational placement; excluded ones carry a reason."""
    from preparation_probe import EXE
    selectable, excluded = [], []
    base = steam / "steamapps/compatdata"
    # One executable registered twice is ambiguous for the confirmation (the plan would stop); list it as such.
    identities = {}
    for key, game in games.items():
        try:
            info = os.stat(game["exe"])
            identities.setdefault((info.st_dev, info.st_ino), []).append(key)
        except (OSError, ValueError):
            continue
    shared = {key for keys in identities.values() if len(keys) > 1 for key in keys}
    for key, game in games.items():
        exe = Path(game["exe"])
        if exe.name == EXE:
            continue  # probe registrations belong to the detailed menu
        if key in shared:
            excluded.append((key, "ambiguous confirmation registration"))
            continue
        try:
            names = [key] + ([str(int(key) - 2**32)] if int(key) >= 2**31 else [])
            present = [name for name in names if os.path.lexists(base / name)]
            require(len(present) <= 1, "two prefix aliases exist")
            require(not present or not os.path.islink(base / present[0]), "prefix is a symbolic link")
            game_folder_apart(exe.parent, (steam, settings, management))
            selectable.append(key)
        except (OSError, ValueError) as error:
            excluded.append((key, str(error) if isinstance(error, ValueError) else type(error).__name__))
    return selectable, excluded


def interactive_confirmed_placement(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                                    steam=None, settings=None, home=None, runtime_root=Path("/")):
    """Operational entry 3: place the bundle's preparation Proton without a probe (design: operational entry 4)."""
    import sys

    import preparation_selection as selection
    from preparation_installation import plan_installation
    from preparation_store import PrivateStore
    from preparation_target import pin_registration

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    directory = safe_path(directory)
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    management = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store")
    protected = [steam, settings]
    stage, started, report, report_excluded = "confirmed-placement-selection", False, None, []
    try:
        config = selection.validate_selection_config(copy.deepcopy(config))
        require("placement_review" in config, "reviewed build distribution required")
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        print("登録済みのゲームを照合しています（EXEを読みます。変更はしません）。", file=output, flush=True)
        selectable, excluded = _confirmation_candidates(games, steam, settings, management)
        checked_keys = []
        for key in selectable:
            try:
                pin_registration(source, key, Path(games[key]["exe"]).parent, steam)
                checked_keys.append(key)
            except (OSError, ValueError) as error:
                excluded.append((key, str(error) if isinstance(error, ValueError) else type(error).__name__))
        print("新しい準備用Protonを置きます。確認のため、DroidDeckに登録済みのゲームを1つ選んでください。", file=output)
        print("選んだゲームは確認に使うだけで、変更しません（prefix・割り当て・ゲームのファイルには書きません）。", file=output)
        for index, key in enumerate(checked_keys, 1):
            print(f"{index}. {selection._text(games[key]['title'])}  [ID {key}]", file=output)
        report_excluded = [{"app_id": key, "reason": reason} for key, reason in excluded]
        for key, reason in excluded:
            print(f"-  {selection._text(games[key]['title'])}  [ID {key}]（選べません: {selection._text(reason)}）", file=output)
        require(checked_keys, "no registered game can confirm the placement")
        print("確認に使うゲームの番号（qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32).strip()
        if not answer or answer.lower() == "q":
            print("取り消しました。", file=output)
            return 0, None
        require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(checked_keys), "invalid target selection")
        key = checked_keys[int(answer) - 1]
        exe = safe_path(games[key]["exe"])
        stage = "confirmed-placement-plan"
        payload = config["payload"]
        archive = selection._archive(directory, payload)

        def refresh():
            installation = plan_installation(archive=archive, sha512=payload["sha512"], archive_root=payload["root"],
                mode=payload["mode"], runtime_root=runtime_root, runtime_audit=config["runtime_reference"], registrations=source,
                registration_id=key, exe_root=exe.parent, steam=steam, renderer=renderer, parent_environment=environment,
                tool_slot="preparation", archive_from_folder=True)
            return plan_confirmed_placement(installation, config["placement_review"], management, settings)

        print("配布物全体・runtime識別・確認用の登録を検査しています。", file=output, flush=True)
        plan = refresh()
        preview = plan.summary()
        print("配置先: " + selection._text(preview["destination"]), file=output)
        if preview["action"] == "reuse-verified-tree":
            print("この準備用Protonは置き済みで、期待ツリー全体と一致しています。今回は配置し直しません。", file=output)
            report = {**preview, "mode": "static-matching-tool-observed", "material_installed_now": False}
        else:
            require(preview["capacity"]["estimate_fits"], "insufficient estimated static placement space")
            capacity = preview["capacity"]
            print(f"配置の見積: {capacity['estimated_additional_bytes'] / 1024**3:.2f} GiB / 空き {capacity['available_bytes'] / 1024**3:.1f} GiB", file=output)
            if plan.review.get("private_xalia_files"):
                print(f"Xaliaファイル{len(plan.review['private_xalia_files'])}件は出荷権限を保持し、親のcompatibilitytools.d（0700）が私有のままの場合だけ配置します。", file=output)
            print("来歴: 確認済みGitHub build " + plan.review["run_id"] + " / commit " + plan.review["source_commit"][:12], file=output)
            print("新しい準備用toolのファイル、staging、私有記録／lock、DroidDeck設定lock、結果JSONを書きます。", file=output)
            print("既存Proton・ゲーム・EXE・prefix・割り当て設定は変更しません。Wineも起動しません。", file=output)
            print("この範囲で配置する場合は1、取消はq: ", end="", file=output, flush=True)
            if stream.readline(32).strip() != "1":
                print("取り消しました。", file=output)
                return 0, None
            stage, started = "confirmed-placement-apply", True
            selection._private_report_directory(home, protected)
            compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
            lock = hashlib.sha256(str(compatdata).encode()).hexdigest()
            print("lock下で再検査し、新規toolを展開・全体照合・非上書き配置します。", file=output, flush=True)
            with PrivateStore(management, create=True) as store, store.locked(lock):
                report = apply_static_placement(plan, refresh, store, plan.digest)
            print("新しい準備用Protonを配置し、全体一致を確認しました。まだ起動しません。", file=output)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        failure = {"stage": stage, "check": getattr(error, "preparation_check", stage), "error_class": type(error).__name__,
                   "errno": getattr(error, "errno", None), "reason": {
                       "reviewed Xalia modes require a private 0700 tool parent": "tool-parent-not-owned-private-0700",
                       "payload permissions have not been reviewed for this archive": "payload-mode-review-mismatch",
                       "reviewed preparation slot required": "reviewed-payload-slot-mismatch",
                       "ambiguous confirmation registration": "confirmation-registration-ambiguous",
                       "game folder overlaps tool folders": "confirmation-game-folder-overlaps",
                       "registration or executable changed": "confirmation-registration-changed",
                       "no registered game can confirm the placement": "no-confirmation-registration",
                       "no added games": "no-registered-games",
                       "existing installation differs from approved generated trees": "existing-preparation-tree-differs",
                       "insufficient estimated static placement space": "insufficient-static-capacity",
                       "runtime source/library/label changed since audit": "runtime-identity-changed",
                       "archive missing or ambiguous": "archive-missing-or-ambiguous"}.get(str(error), "input-rejected"),
                   **input_change(error)}
        if report is None:
            report = {"mode": "confirmed-placement-stopped", "published_tree_or_staging_may_exist": started,
                      "private_records_may_have_changed": started, "prefix_created": False, "binding_written": False,
                      "wine_executed": False, "writes": [] if not started else [
                          {"scope": "static-placement-outcome-unknown-preserve-and-reinspect", "path": str(steam / "compatibilitytools.d")}]}
        report["error"] = failure
        print("処理停止: " + failure["check"] + " / " + failure["reason"] + " / " + failure["error_class"] + " / errno=" + str(failure["errno"]), file=output)
        if not started:
            print("確認用のゲームの読み取りで止まった場合は、もう一度実行するか、別のゲームを選んでください。", file=output)
        print("途中のtoolやstaging、記録は削除せず保持します。結果JSONを確認してください。", file=output)
    report.update(schema_version=1, tool_version=VERSION, preparation_complete=False,
                  excluded_confirmation_candidates=report_excluded)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。表示された停止段階を確認してください。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(saved if saved.parent != directory else saved.name), file=output)
    return 2, str(saved) if saved.parent != directory else saved.name
