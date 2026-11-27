"""Menu 12: prepare one registered game in one run (initialize, place DLLs, install, bind).

Each step calls the plan, session and writer that menus 10, 8 and 11 use, and plans again
right before it runs. One confirmation covers the fixed values shown before anything is
written; a later plan whose fixed values differ stops the run without asking again. The
SoftDenchi bootstrap runs with its pinned silent arguments. Only when that installs nothing
is the interactive installer offered, under a separate confirmation of its own plan.

The run resumes from the private records of the selected registration, so a stop (for
example a refused SdProxy stop) is continued by running menu 12 again for the same game.
"""

import hashlib
import io
import itertools
import os
from pathlib import Path

from preparation_assets import digest_json, exe_identity, inspect_assets_from_folder
from preparation_common import VERSION, Invalid, require, safe_path
from preparation_game_prefix import (
    NON_ASCII_NOTE,
    PROCESS_BLOCKER,
    RECORDS,
    GamePrefixSession,
    apply_game_binding,
    plan_game_binding,
    plan_game_prefix,
    profile_revision_change,
    registration_identity,
    validate_game_config,
)
from preparation_prefix_dll import (
    DESTINATION,
    PrefixDllSession,
    plan_prefix_dll,
    target_name,
)
from preparation_prefix_dll import HANDLER as PREFIX_DLL
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore

MODE = "one-pass-game-preparation-result"
SCOPE = "registered-game-one-pass-preparation"
SOFTDENCHI = "softdenchi-interactive"
PREFIX_DLL_BLOCKED = ("DLL（{0}）を入れる前の確認で止まりました。理由は結果JSONにあります。上書き・修復・削除はしていません。"
                      "置き先に書きかけの {0} が残っている場合は、結果JSONを戻してください（回復の手順をお知らせします）。")
SOFTDENCHI_STATE_STOP = "ソフト電池の導入記録または状態に確認が要ります。修復はしていません。"
BINDING_BLOCKED = "全依存が検証済みになるまで割り当てません。"
# The plan saw the game or Wine running (design: no-SoftDenchi 4.4); the next run continues from here.
BINDING_RUNNING = ("ゲームかWineが動いているため、割り当てる前に止めました。初期化は済んでいます。"
                   "すべてのゲームとWineを終了してから、もう一度実行すると続きから準備します。")
BINDING_STOP = "割り当ての状態に確認が要ります。設定は変更していません。"
# Records after which a new installation may follow (same rule as retry_blockers), except failures.
RETRYABLE = ("cancelled-absent", "stopped-before-installer", "running", "needs-user")


class Stopped(Exception):
    """A planned stop: nothing more is written; the result explains the next step."""

    def __init__(self, check, reason, next_step=None):
        super().__init__(reason)
        self.check, self.reason, self.next_step = check, reason, next_step


def _registration(games, key):
    """Live identity of the selected registration (path, title and EXE content)."""
    require(key in games, "selected registration absent")
    exe = safe_path(games[key]["exe"])
    return {"app_id": key, **registration_identity(exe, games[key]["title"]), "exe_sha256": exe_identity(exe)["sha256"]}


def _proton(inventory, customization, runtime, tool_writes):
    return {"inventory": inventory.digest, "customization": customization.digest, "directory": customization.directory,
            "runtime": runtime.identity_digest, "tool_runtime_writes": tool_writes}


def _profile(profile, recipes, softdenchi):
    from preparation_softdenchi_recipe import recipe_digest
    return {"profile": digest_json(profile),
            "recipes": digest_json({dep: recipes[dep] for dep in profile["dependencies"]}),
            "softdenchi_recipe": recipe_digest(softdenchi)}


def _asset(config, softdenchi, mode, silent_launch):
    from preparation_installer_log import enabled
    from preparation_softdenchi_recipe import silent_arguments
    arguments = silent_arguments(softdenchi, silent_launch) if mode == "silent" else []
    # The diagnostic installer log is part of what the batch screen confirmed (design: installer log 3.8).
    return {"spec": digest_json(config["dependency_installation"]["asset"]), "mode": mode, "arguments": arguments,
            "installer_log": enabled(config)}


def _dlls(profile, recipes, directory):
    """Each prefix DLL of the profile: its recipe and the measured asset (re-read at every step)."""
    values = []
    for dep in profile["dependencies"]:
        item = recipes[dep]
        if item["handler"] == PREFIX_DLL:
            report = inspect_assets_from_folder({"schema_version": 1, "assets": [item["asset"]]}, directory)[0]
            values.append({"dependency_id": dep, "recipe": digest_json(item), "measured": report["measured"],
                           "blockers": report["blockers"]})
    return values


def _record_log(session, step, output):
    """Fix the diagnostic installer log of this attempt and keep its path-free view in the step."""
    from preparation_installer_log import report_view
    view = report_view(session.finalize_log())
    if view is not None:
        step["installer_log"] = view
        if view["state"] == "final" and view.get("writers_remaining"):
            print(f"導入のログに、まだ書き手が残っています（{view['writers_remaining']}件）。プロセスには何もしていません。",
                  file=output)


def log_views(report):
    """Installer log views and installation statuses of a one-pass report, per install ID."""
    views, statuses = [], {}
    for step in report.get("steps", []):
        view = step.get("installer_log")
        if view:
            views.append(view)
            statuses[view["install_id"]] = (step.get("record") or {}).get("status")
    return views, statuses


def offer_log_copies(report, saved, directory, home, stream, output, text, private=None):
    """After the result is saved: offer each eligible log next to it (design: installer log 3.7)."""
    from preparation_installer_log import offer_shared_copies
    views, statuses = log_views(report)
    if not views:
        return []
    store_root = safe_path(home) / ".local/state/droiddeck-prefix-preparation/tool-store"
    copies = offer_shared_copies(views, statuses, saved=saved, shared_folder=directory, store_root=store_root, home=home,
                                 stream=stream, output=output, text=text)
    if copies:
        from preparation_installer_log import rewrite_result
        report["installer_log_copies"] = copies
        for path in (saved, private):  # The shared result, and its private master when it was exported.
            if path is not None:
                rewrite_result(path, copies)
    return copies


def fixed_values(*, registration, profile, proton, paths, asset, binding, dlls):
    """The values the single confirmation is given for; stage-dependent states are excluded."""
    return {"registration": registration, "profile": profile, "proton": proton, "paths": paths, "asset": asset,
            "binding": binding, "dlls": dlls}


ITEM_TEXT = {"registration": "登録", "profile": "作品", "proton": "Proton", "paths": "場所", "asset": "資材",
             "installer_mode": "導入の方式", "installer_log": "導入のログ", "binding": "割り当て・設定", "dlls": "prefixに入れるDLL"}


def item_digests(values):
    """One digest per fixed item, kept in the result so a stop can name what changed."""
    items = {name: values[name] for name in ("registration", "profile", "proton", "paths", "binding", "dlls")}
    items["asset"] = values["asset"]["spec"]
    items["installer_mode"] = {"mode": values["asset"]["mode"], "arguments": values["asset"]["arguments"]}
    # The diagnostic installer log (design: installer log 3.8); absent in plans of earlier versions.
    items["installer_log"] = values["asset"].get("installer_log", False)
    return {name: digest_json(value) for name, value in sorted(items.items())}


def changed_items(confirmed, current, ignore=()):
    """Names of fixed items that differ; ``ignore`` lists items a separately confirmed step may change."""
    before, after = item_digests(confirmed), item_digests(current)
    return [name for name in before if name not in ignore and before[name] != after[name]]


def menu_ref(config, number):
    # preparation_selection is defined after this module in the bundle, so it is imported here.
    from preparation_selection import menu_ref as ref
    return ref(config, number)


def one_pass_ref(config):
    from preparation_selection import one_pass_ref as ref
    return ref(config)


def redo_ref(config):
    """recovery.sh 7 (1.0.0): prepare the same registration again."""
    return "recovery.sh の7"


def restart_then_one_pass(config):
    return ("DroidDeckを完全に終了して起動し直してから、もう一度 " + one_pass_ref(config) +
            " で同じゲームを選んでください（続きから進めます）。")


def failed_then_menu9(config):
    return ("導入の記録が失敗として残りました。" + one_pass_ref(config) + "をもう一度実行しても、この記録で止まります。" +
            menu_ref(config, 9) + "で導入状態を確認し、結果を戻してください。やり直すときは " + redo_ref(config) + " を使います。")


def release_next_step(record, config):
    """After a stop of the inherited VC record release (design: inherited VC record 4)."""
    from preparation_vc_record import text_reason
    item = record.get("inherited_vc_record") or {}
    head = "ソフト電池は導入していません（受け継いだVC++の記録を外す段で止まりました：" + text_reason(item.get("reason")) + "）。"
    if item.get("retryable") is False:
        return head + "もう一度実行しても進みません。結果JSONを戻してください。やり直すときは " + redo_ref(config) + " を使います。"
    if (item.get("reason") or "").startswith(("wait-timeout", "persistence-unconfirmed")):
        return head + "ゲームとWineをすべて終了し、DroidDeckを起動し直してから、もう一度 " + one_pass_ref(config) + " を実行してください。"
    return head + "もう一度 " + one_pass_ref(config) + " を実行すると、外す段からやり直します。"


def installation_next_step(result, config):
    """What the operator does after an installation that did not end present-verified."""
    if result is not None and result.get("status") == "stopped-before-installer" and \
            (result.get("inherited_vc_record") or {}).get("state") == "failed":
        return release_next_step(result, config)
    if result is None:
        return "ソフト電池は導入していません。導入する場合は、もう一度 " + one_pass_ref(config) + " を実行してください。"
    if result["status"] == "failed":
        return failed_then_menu9(config)
    if result.get("post_state") in (None, "uninspected"):
        return restart_then_one_pass(config)
    return ("ソフト電池の導入は完了していません（" + result["status"] + "）。修復はしていません。" + menu_ref(config, 9) +
            "で状態を確認してください。")


def softdenchi_action(latest, invalid, current):
    """Design 5.1 step 3: history row first, then the current read-only state.

    Returns ("install" | "skip" | "stop", reason, inspected_separately).
    """
    if invalid:
        return "stop", "invalid-installation-record-present", False
    if latest is not None and latest["status"] == "failed":
        return "stop", "previous-installation-failed-review-required", False
    if latest is None or latest["status"] in RETRYABLE:
        if current == "absent":
            return "install", None, False
        if current == "present-verified":
            # No verified post-inspection backs this state; only the read-only inspection of this run does.
            return "skip", None, True
        return "stop", "dependency-state-" + current, False
    if latest["status"] == "present-verified" and latest.get("phase") == "post-inspected":
        if current == "present-verified":
            return "skip", None, False
        return "stop", "dependency-state-" + current + "-after-verified-installation", False
    return "stop", "previous-installation-" + latest["status"] + "-review-required", False


def _game_records(management):
    """Readable game prefix records and the count of unreadable ones.

    An unreadable record cannot be attributed to a registration, so it does not block the
    others: a registration whose prefix exists without a readable record is never offered as
    new (the prefix check), and an existing prefix is never adopted.
    """
    if not os.path.lexists(management):
        return [], 0
    with PrivateStore(management) as store:
        listed = store.inventory()["game_prefixes"]
    invalid = sum(item.get("status") == "invalid" for item in listed)
    return [item for item in listed if item.get("status") != "invalid"], invalid


def binding_history(store, key):
    """Binding records of this registration, from any tool version (only their shape is checked).

    An unreadable record that may belong to this registration stops, since it could hide a
    partial binding; records of other registrations are not interpreted.
    """
    from preparation_binding import validate_binding_record
    history = []
    for item in store.inventory()["bindings"]:
        name = item["binding_id"] + ".json" if "binding_id" in item else item["object"]
        record, _ = store.read_record("bindings", name)
        validate_binding_record(record, any_version=True)
        if record["app_id"] == key:
            history.append({"status": record["status"], "completed_files": list(record["completed_files"])})
    return history


def apply_note(store, key, plan, before=None):
    """``on_binding_id`` of a new assignment: its supplementary record (design: Proton update 4.3).

    ``before(run_id)`` runs first (the batch run's progress record)."""
    from preparation_proton_update import note, write_note

    def write(run_id):
        if before is not None:
            before(run_id)
        write_note(store, note(run_id, key, "apply", plan.base.customization.directory, None, plan.binding))
    return write


def confirmed_targets(key, targets):
    """``under_lock`` of the batch run's binding: the target's items must be the confirmed ones (Proton update 3.5)."""
    from preparation_proton_update import target_items

    def check(fresh):
        require(target_items(fresh.before, key) == targets, "confirmed target items changed")
    return check


def previous_roots(common):
    """Other preparation slots this tool placed, for read-only judgements of moved games (Proton update 4.4)."""
    from preparation_proton_update import bundle_directory, placed_roots
    management = safe_path(common["home"]) / ".local/state/droiddeck-prefix-preparation/tool-store"
    if not os.path.lexists(management):
        return ()
    try:
        with PrivateStore(management) as store:
            return placed_roots(store, common["steam"], bundle_directory(common["config"]))[0]
    except (OSError, ValueError, TypeError, KeyError):
        return ()


def binding_action(binding, history):
    """Design 5.2: decided by the current three files, never by a past record alone.

    All files bound: already bound. Some bound: stop (a partial state is never completed
    automatically). None bound: bind, unless a past binding wrote files (it was verified, or
    it failed after writing) and the files have changed since.
    """
    from preparation_binding import FILES
    from preparation_proton_update import bound_files
    # Compared by meaning, not bytes: a DroidDeck screen choice with the tool ID as ``name`` is bound (Proton update 4.6).
    meaning = (bound_files(binding.before, binding.registration_id, binding.directory, binding.tool)
               if hasattr(binding, "registration_id") else [])
    bound = [name for name in FILES if binding.before[name] == binding.after[name] or name in meaning]
    if len(bound) == len(FILES):
        return "already-bound", None
    if bound:
        return "stop", "binding-partially-applied"
    if any(item["status"] == "binding-verified" for item in history):
        return "stop", "binding-changed-after-verified-binding"
    if any(item["completed_files"] for item in history):
        return "stop", "previous-binding-wrote-files"
    return "apply", None


# A process appeared or the view was not clear while reading: the game or Wine is running (or changing).
UNCLEAR = ("concurrent-process-observed", "target-process-view-not-clear", "dependency-state-uninspected")


def action_text(action, recipes):
    if action.startswith("prefix-dll:"):
        return "DLL（" + target_name(recipes[action.split(":", 1)[1]]) + "）を入れる"
    return {"softdenchi-silent": "ソフト電池を画面なしで入れる", "binding": "準備用Protonに割り当てる"}[action]


def current_tool(steam, settings, key):
    """The tool name config.vdf maps this registration to, for the selection list (read-only)."""
    from preparation_status import _current  # defined after this module in the bundle
    try:
        return _current(steam, settings, key)["config"] or "なし"
    except (OSError, ValueError, TypeError, KeyError):
        return "読めません"


def _dll_asset_stop(items, reasons):
    """The stop for prefix DLL assets missing or different in the asset folder."""
    return ("one-pass-precheck", ",".join(sorted(reasons)),
            "prefixに入れるDLL（" + "、".join(item["asset"]["filename"] for item in items) +
            "）がprepare.sh と同じフォルダーにないか、内容が違います。何も変更していません。")


def pre_write_stops(*, profile, recipes, directory, record=None, softdenchi=None, installer=None):
    """Stops that menu 1 (one-pass) makes before anything is written: (stage, reason, next step) or None.

    ``installer`` is the SoftDenchi asset spec when a new prefix will need it. Shared by
    menu 1 and the status check (design: operational entry 6.3); read-only, no locks.
    The prefix DLL assets are checked here only for a new prefix (every DLL will be placed);
    for an initialized game ``evaluate_resume`` requires an asset only for a DLL it would
    place, so a game with nothing left to do does not need the asset files.
    """
    from preparation_softdenchi_recipe import bind_asset
    if record is not None:
        try:
            profile_revision_change(profile, record["profile"])
        except Invalid as error:
            return "profile-selection", str(error), "初期化したときの作品プロファイルから内容が変わっています。何も変更していません。"
    stage = "one-pass-precheck"
    blocked = [dep for dep in profile["dependencies"] if recipes[dep]["status"] != "ready"]
    if blocked:
        return stage, "dependency-blocked:" + ",".join(blocked), "この作品には未対応の依存があるため、割り当てまで進めません。何も変更していません。"
    if installer is not None:
        # A new prefix always needs the installer: check it before anything is written.
        checked = inspect_assets_from_folder({"schema_version": 1, "assets": [installer]}, directory)[0]
        problems = ["asset:" + reason for reason in checked["blockers"]]
        try:
            bind_asset(softdenchi, installer, checked["measured"])
        except Invalid:
            problems.append("asset-not-recipe-bootstrap")
        if problems:
            return stage, ",".join(sorted(problems)), ("インストーラー（" + installer["filename"] +
                                                      "）がprepare.sh と同じフォルダーにないか、内容が違います。何も変更していません。")
    if record is not None:
        return None
    dll_items = [recipes[dep] for dep in profile["dependencies"] if recipes[dep]["handler"] == PREFIX_DLL]
    problems = {"dll-asset:" + item["dependency_id"] + ":" + reason
                for item, value in zip(dll_items, _dlls(profile, recipes, directory)) for reason in value["blockers"]}
    return _dll_asset_stop(dll_items, problems) if problems else None


def blockers_left(blockers, pending):
    """Binding blockers that the steps before binding will not clear.

    The steps before binding make only the pending dependencies verified, so only their own
    "not verified" blockers may be dropped. Any other form stays, also when its text after
    the colon equals a pending dependency id (design: no-SoftDenchi 4.3).
    """
    return [blocker for blocker in blockers
            if not (blocker.startswith("dependency-not-verified:") and blocker.split(":", 1)[1] in pending)]


def evaluate_resume(*, record, record_digest, profile, recipes, softdenchi, source, games, common, stop_check,
                    silent_launch=None, inventory=None):
    """Read-only evaluation of what menu 1 does next for an initialized game (no locks, no writes).

    Uses the plans and decision functions of menu 1's steps in the same order (pre-write stops,
    binding records, prefix DLL plans, ``softdenchi_action`` with the installation plan, the
    binding plan with ``binding_action``). Returns ``{"next": "stop", "stage", "reason",
    "next_step"}`` with menu 1's stage and reason, ``{"next": "continue", "actions"}``, or
    ``{"next": "ready"}`` (every dependency verified and the game bound). A stop that menu 1
    would only reach after writing (a binding that cannot follow) is reported before any write.
    Menu 1 still plans again under its locks before each write. ``inventory`` (the verified
    payload inventory) lets the status check read the archive once for every game.
    """
    from preparation_dependency_install import (
        _capacity,
        _installations,
        plan_dependency_install,
    )
    from preparation_dependency_install import capacity_needs as installer_needs
    from preparation_dependency_state import inspect_dependency_state
    from preparation_prefix_dll import capacity_needs as dll_needs
    from preparation_recheck import plan_recheck
    key, actions, steps, stage = record["app_id"], [], [], ["one-pass-precheck"]
    roots = previous_roots(common)
    extra = {} if inventory is None else {"inventory": inventory}

    def stopped(at, reason, next_step=None):
        return {"next": "stop", "stage": at, "reason": reason, "next_step": next_step, "actions": actions, "steps": steps}

    try:
        uses_softdenchi = any(recipes[dep]["handler"] == SOFTDENCHI for dep in profile["dependencies"])
        found = pre_write_stops(profile=profile, recipes=recipes, directory=common["directory"], record=record)
        if found:
            return stopped(*found)
        stage.append("binding-history")
        management = safe_path(common["home"]) / ".local/state/droiddeck-prefix-preparation/tool-store"
        history = []
        if os.path.lexists(management):
            with PrivateStore(management) as store:
                history = binding_history(store, key)
        pending = set()
        # Bytes the earlier steps of this run write, per path: each later step's space check counts them,
        # as its plan in the run would see the space after those writes.
        consumed = []
        missing_items, missing = [], []  # DLLs to place whose asset file is missing or differs (all are shown).
        for item in [recipes[dep] for dep in profile["dependencies"] if recipes[dep]["handler"] == PREFIX_DLL]:
            stage.append("prefix-dll")
            plan = plan_prefix_dll(record=record, record_sha256=record_digest, item=item, source=source, games=games,
                                   stop_check=stop_check, previous_slots=roots, **common, **extra)
            steps.append({"step": "prefix-dll", "evaluated": True, "plan": plan.summary()})
            if plan.action == "skip":
                continue  # Already in the prefix: the asset file is not needed.
            asset = sorted(blocker.removeprefix("asset:") for blocker in plan.blockers if blocker.startswith("asset:"))
            if asset and plan.action != "stop":
                # Only a DLL this step would place needs its asset; reported after every DLL is looked at.
                missing_items.append(item)
                missing.extend("dll-asset:" + item["dependency_id"] + ":" + reason for reason in asset)
                continue
            # A DLL that is not placed for another reason (a running game, a changed layout...) shows that reason.
            blockers = [blocker for blocker in plan.blockers if not blocker.startswith("asset:")]
            if not blockers:
                joint = _capacity(consumed + list(dll_needs(plan.recheck, item["asset"])))
                steps[-1]["capacity_after_earlier_steps"] = joint
                if not joint["sufficient"]:
                    blockers = ["insufficient-capacity"]
            if blockers:
                return stopped("prefix-dll", "prefix-dll-blocked:" + ",".join(blockers), PREFIX_DLL_BLOCKED.format(target_name(item)))
            consumed.append((plan.recheck.compatdata, item["asset"]["expected_size"] or 0))
            pending.add(item["dependency_id"])
            actions.append("prefix-dll:" + item["dependency_id"])
        if missing:
            return stopped(*_dll_asset_stop(missing_items, missing))
        if uses_softdenchi:
            stage.append("softdenchi-state")
            base = plan_recheck(record=record, record_sha256=record_digest, source=source, games=games, records=RECORDS,
                                **common, **extra)
            previous, invalid = _installations(base.store_root, key)
            from preparation_dependency_install import vc_latest
            from preparation_vc_record import text_reason
            vc, vc_stop = vc_latest(base.store_root, record["trial_id"])
            if vc is not None:
                steps.append({"step": "inherited-vc-record", "latest": vc})
            if vc_stop is not None:
                # Running again cannot clear this stop (design: inherited VC record, Fable L4).
                return stopped("softdenchi-state", "inherited-vc-record-" + vc_stop.split(":", 1)[0],
                               "ソフト電池の導入前に止まりました：" + text_reason(vc_stop) + "。もう一度実行しても進みません。"
                               "やり直すときは " + redo_ref(common["config"]) + " を使います。")
            clear = stop_check.check()["clear_in_view"]
            state = inspect_dependency_state(base.compatdata, softdenchi)["state"] if clear else "uninspected"
            if clear and not stop_check.check()["clear_in_view"]:
                state = "uninspected"
            action, reason, _ = softdenchi_action(previous[-1] if previous else None, invalid, state)
            steps.append({"step": "softdenchi-state", "evaluated": True, "latest_installation": previous and {
                name: previous[-1].get(name) for name in ("install_id", "status", "phase")}, "current_state": state,
                "action": action, "reason": reason})
            if action == "stop":
                return stopped("softdenchi-state", reason, SOFTDENCHI_STATE_STOP)
            if action == "install":
                stage.append("softdenchi-silent")
                plan = plan_dependency_install(record=record, record_sha256=record_digest, source=source, games=games,
                                               recipe=softdenchi, installer_mode="silent", silent_launch=silent_launch,
                                               **common, **extra)
                steps.append({"step": "softdenchi-silent", "evaluated": True, "plan": plan.summary()})
                blockers = list(plan.blockers)
                needs = installer_needs(plan.recheck, common["config"]["dependency_installation"]["asset"], common["home"],
                                        plan.installer_log)
                if not blockers:
                    joint = _capacity(consumed + list(needs))
                    steps[-1]["capacity_after_earlier_steps"] = joint
                    if not joint["sufficient"]:
                        blockers = ["insufficient-capacity"]
                if blockers:
                    return stopped("softdenchi-silent", "dependency-plan-blocked:" + ",".join(blockers))
                # One installation satisfies every dependency handled by SoftDenchi.
                pending.update(dep for dep in profile["dependencies"] if recipes[dep]["handler"] == SOFTDENCHI)
                actions.append("softdenchi-silent")
        stage.append("binding")
        bplan = plan_game_binding(record=record, record_sha256=record_digest, source=source, games=games,
                                  stop_check=stop_check, recipe=softdenchi, **common, **extra)
        action, reason = binding_action(bplan.binding, history)
        if action == "already-bound" and roots:
            # A moved game before its first launch: its layout may still link into the previous slot.
            bplan = plan_game_binding(record=record, record_sha256=record_digest, source=source, games=games,
                                      stop_check=stop_check, recipe=softdenchi, previous_slots=roots, **common, **extra)
        steps.append({"step": "binding-plan", "evaluated": True, "plan": bplan.summary(), "action": action, "reason": reason})
        remaining = blockers_left(bplan.blockers, pending)
        if remaining:
            return stopped("binding", "binding-blocked:" + ",".join(remaining), BINDING_BLOCKED)
        if action == "stop":
            return stopped("binding", reason, BINDING_STOP)
        if action == "apply":
            actions.append("binding")
        return {"next": "continue" if actions else "ready", "actions": actions, "steps": steps}
    except (OSError, ValueError, TypeError, KeyError) as error:
        if not hasattr(error, "preparation_check"):
            error.preparation_check = stage[-1]
        raise


def interactive_one_pass(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                         steam=None, settings=None, home=None, runtime_root=Path("/"), recipe=None, silent_launch=None,
                         select=None, mode="interactive", expected=None, journal=None, targets=None, inventory=None):
    """Menu 1 (one-pass preparation). The batch run (design: Proton update 3.5, 6) uses the same code.

    ``select=(app_id, profile_id or None)`` skips the game and profile questions. ``mode="plan"``
    returns ``(0, plan)`` right before the confirmation (read-only, nothing saved) or
    ``(0, report)`` when it stops before that. ``mode="run"`` skips the confirmation (given on
    the batch screen), stops before writing when the confirmed values (``expected``, a plan of
    ``mode="plan"``) changed, except the whole-file binding digest, or when more actions are
    needed than confirmed, and returns ``(status, report)`` without saving the result JSON.
    ``journal(store, step, ids)`` is called with the locked private store as soon as a step's
    record ID is chosen and before that step writes anything (design: Proton update 6).
    ``targets`` (the batch run's confirmed items of this game in the three files) is compared
    under the private lock, before every step writes and before the binding (design 3.5).
    ``inventory`` (``mode="plan"`` only) is the payload the batch list read once (design 3.1).
    In ``mode="run"`` the kind (new or resume) must be the confirmed one, and each step that
    would write must be one of the confirmed actions.
    """

    def check_targets():
        if targets is None:
            return
        from preparation_proton_update import current_files, target_items
        if target_items(current_files(steam, settings), key) != targets:
            raise Stopped("batch-confirmation", "confirmed-target-items-changed",
                          "確認したときから、このゲームの割り当ての設定が変わりました。何も変更していません。")

    def noted(store, step, ids):
        check_targets()
        if journal is not None:
            journal(store, step, ids)
    import sys

    import preparation_selection as selection
    from preparation_binding import droiddeck_lock, plan_binding
    from preparation_dependency_install import (
        INSTALLER_QUIET_WAIT,
        DependencyInstallSession,
        _installations,
        _offer_session_proxy_stop,
        _wait_loop,
        describe_error,
        inspect_managed_dependency,
        plan_dependency_install,
    )
    from preparation_probe import EXE
    from preparation_recheck import plan_recheck
    from preparation_softdenchi_recipe import (
        softdenchi_recipe,
        validate_recipe,
    )

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    softdenchi = None
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    text = selection._text
    protected, stage, started = [steam, settings], "one-pass-config", False
    report = {"mode": MODE, "scope": SCOPE, "tool_version": VERSION, "steps": [], "binding_written": False,
              "game_launched": False, "authentication_performed": False, "preparation_complete": False}
    live = {}  # the step whose session is running, so an exception still saves its record

    common = {"config": config, "directory": directory, "renderer": renderer, "steam": steam, "settings": settings,
              "home": home, "environment": environment, "runtime_root": runtime_root}

    def catalog():
        current, _, games = selection.registration_catalog(environment)
        require(current == source, "registration source changed")
        return games

    def base_plan(record, digest):
        return plan_recheck(record=record, record_sha256=digest, source=source, games=catalog(), records=RECORDS,
                            inventory=inventory, **common)

    def confirmed(action):
        """In a batch run, a step writes only when the batch screen confirmed it (design 3.5)."""
        if mode == "run" and action not in expected["actions"]:
            raise Stopped("batch-confirmation", "more-actions-than-confirmed:" + action,
                          "確認したときの内容から変わりました。何も変更していません。もう一度 prepare.sh を実行してください。")

    def from_base(base, asset, binding_digest):
        return fixed_values(registration=_registration(catalog(), key), profile=_profile(profile, recipes, softdenchi),
                            proton=_proton(base.inventory, base.customization, base.runtime, base.tool_writes),
                            paths=[str(base.compatdata), str(base.work), str(base.private_home)], asset=asset,
                            binding=binding_digest, dlls=_dlls(profile, recipes, directory))

    def check_fixed(current, ignore=(), where=None):
        changed = changed_items(fixed, current, ignore)
        if changed:
            report.setdefault("fixed_value_changes", []).append({"stage": where or stage, "items": changed})
            raise Stopped(where or stage, "fixed-values-changed:" + ",".join(changed),
                          "確認したときの内容（" + "・".join(ITEM_TEXT[name] for name in changed) + "）が変わりました。"
                          "もう一度 " + one_pass_ref(config) + " を実行して、内容を確認し直してください。")

    def interactive_fallback(record, record_digest):
        """Silent run installed nothing: offer the interactive installer under its own confirmation."""
        nonlocal stage
        stage = "softdenchi-interactive"
        def refresh():
            return plan_dependency_install(record=record, record_sha256=record_digest, source=source, games=catalog(),
                                           recipe=softdenchi, installer_mode="interactive", **common)

        plan = refresh()
        interactive_asset = {**asset, "mode": "interactive", "arguments": []}
        current = from_base(plan.recheck, interactive_asset, plan_binding(steam, settings, key, proton["directory"]).digest)
        check_fixed(current, ("installer_mode",))
        if plan.blockers:
            raise Stopped(stage, "dependency-plan-blocked:" + ",".join(plan.blockers))
        print("画面なしの導入のあと、ソフト電池の検査対象は入っていませんでした。", file=output)
        from preparation_vc_record import RELEASE_TEXT
        print(RELEASE_TEXT, file=output)
        print("画面ありで導入する場合は1、やめる場合はq（画面が出るかをwinverで確かめてから、インストーラーを起動します）: ",
              end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            report["steps"].append({"step": "softdenchi-interactive", "declined": True})
            return None
        report["steps"].append({"step": "softdenchi-interactive", "plan": plan.summary(), "confirmed_plan": plan.digest})
        with droiddeck_lock(settings):
            session = DependencyInstallSession(plan, store, refresh, plan.digest, stop)
            noted(store, "softdenchi-interactive", {"install_id": session.record["install_id"]})
            live.update(step=report["steps"][-1], session=session)
            session.start_gui_check()
            print("winverの画面が出たら、内容を確認して閉じてください。", file=output, flush=True)
            outcome = _wait_loop(session.wait_gui_check, stream, output, "gui_check")
            if outcome["phase"] == "gui-check-stopped":
                print("winverの画面が表示され、閉じられましたか？ 表示された場合は1、表示されなかった場合はq: ", end="", file=output, flush=True)
                if session.confirm_display(stream.readline(32).strip() == "1")["phase"] == "gui-check-stopped":
                    session.start_installer()
                    if session.release_stopped is not None:
                        print(release_next_step(session.record, config), file=output)
                    else:
                        print("インストーラーの画面で操作してください。完了を待っています"
                              f"（最初の{INSTALLER_QUIET_WAIT // 60}分は確認なしで待ちます）。", file=output, flush=True)
                        try:
                            _wait_loop(session.wait_installer, stream, output, "installer", INSTALLER_QUIET_WAIT)
                            if session.record["installer"]["status"] == "exited-processes-remain":
                                _offer_session_proxy_stop(session, stream, output, text, preapproved=True, next_step=None)
                        except Exception:
                            _record_log(session, report["steps"][-1], output)
                            raise
                        _record_log(session, report["steps"][-1], output)
        result = dict(session.record)
        report["steps"][-1]["record"] = result
        live.clear()
        return result

    require(mode in ("interactive", "plan", "run") and (mode == "interactive" or select is not None) and
            (mode != "run" or expected is not None) and (inventory is None or mode == "plan"), "invalid one-pass mode")
    real_output = output  # Restored on every stop: the run mode swaps the confirmation text out.
    try:
        softdenchi = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True and "placement_review" in config and
                "game_preparation" in config and "dependency_installation" in config, "one-pass preparation not enabled")
        profiles, recipes = validate_game_config(config.get("game_preparation"))
        stage = "registration-selection"
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        records = {}
        readable, unreadable = _game_records(management)
        for item in readable:
            records.setdefault(item["app_id"], []).append(item)
        if unreadable:
            report["unreadable_game_prefix_records"] = unreadable
            print(f"読めない初期化記録が{unreadable}件あります（どの登録のものか分からないため、一覧の判定には使いません）。", file=output)
        base_dir = steam / "steamapps/compatdata"
        candidates = []
        for key_, game in games.items():
            if Path(game["exe"]).name == EXE:
                continue
            if key_ in records:
                candidates.append((key_, "続きから"))
            elif not os.path.lexists(base_dir / key_) and not (int(key_) >= 2**31 and
                                                               os.path.lexists(base_dir / str(int(key_) - 2**32))):
                candidates.append((key_, "新規"))
        require(candidates, "no registered game to prepare")
        if select is not None:
            labels = dict(candidates)
            if select[0] not in labels:
                raise Stopped("registration-selection", "not-a-candidate",
                              "このゲームは今は準備の対象ではありません。何も変更していません。")
            key, label = select[0], labels[select[0]]
        else:
            for number, (key_, label) in enumerate(candidates, 1):
                print(f"{number}. [{label}] {text(games[key_]['title'])} [ID {key_}]", file=output)
                print("   " + text(games[key_]["exe"]), file=output)
                if label == "続きから":
                    print("   今の割り当て: " + text(current_tool(steam, settings, key_)), file=output)
            print("準備するゲームの番号（qで取消）: ", end="", file=output, flush=True)
            answer = stream.readline(32).strip()
            if answer == "q":
                return 0, None
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(candidates), "invalid game selection")
            key, label = candidates[int(answer) - 1]
        report["app_id"] = key
        exe = safe_path(games[key]["exe"])
        stage = "profile-selection"
        init_plan, record, record_digest = None, None, None
        if label == "新規" and select is not None and select[1] is not None:
            require(select[1] in profiles, "unknown game profile")
            profile_id = select[1]
        elif label == "新規":
            measured = exe_identity(exe)["sha256"]
            matches = sorted(pid for pid, item in profiles.items() if item["exe_sha256"] == measured)
            if len(matches) == 1:
                profile_id = matches[0]
                print("作品プロファイル: " + text(profiles[profile_id]["title"]) + "（EXEハッシュ一致で自動選択）", file=output)
            else:
                ids = sorted(profiles)
                for number, pid in enumerate(ids, 1):
                    print(f"{number}. {text(profiles[pid]['title'])} / {pid} / {text(profiles[pid]['edition'])}", file=output)
                print("この登録に対応する作品プロファイルの番号（qで取消）: ", end="", file=output, flush=True)
                answer = stream.readline(32).strip()
                if answer == "q":
                    return 0, None
                if answer in profiles:
                    profile_id = answer
                else:
                    require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(ids), "invalid profile selection")
                    profile_id = ids[int(answer) - 1]
        else:
            listed = records[key]
            require(len(listed) == 1, "several game prefix records for this registration")
            if listed[0]["status"] != "initialized-unverified":
                raise Stopped("resume-state", "initialization-" + listed[0]["status"],
                              "初期化が完了していない記録があります。作成物は削除せずに残しています。")
            with PrivateStore(management) as store:
                record, record_digest = store.read_record(RECORDS, listed[0]["trial_id"] + ".json")
            profile_id = record["profile"]["profile_id"]
            require(profile_id in profiles, "game profile changed since initialization")
        profile = profiles[profile_id]
        report["profile_id"] = profile_id
        uses_softdenchi = any(recipes[dep]["handler"] == SOFTDENCHI for dep in profile["dependencies"])
        asset = (_asset(config, softdenchi, "silent", silent_launch) if uses_softdenchi else
                 {"spec": None, "mode": "none", "arguments": []})
        spec = config["dependency_installation"]["asset"] if uses_softdenchi else None
        dll_items = [recipes[dep] for dep in profile["dependencies"] if recipes[dep]["handler"] == PREFIX_DLL]
        stage = "one-pass-precheck"
        # The same read-only checks as the status check (operational entry 6.3), before anything is written.
        found = pre_write_stops(profile=profile, recipes=recipes, directory=directory, record=record, softdenchi=softdenchi,
                                installer=spec if label == "新規" else None)
        if found:
            raise Stopped(*found)

        def refresh_init():
            return plan_game_prefix(source=source, games=catalog(), key=key, profile_id=profile_id, inventory=inventory,
                                    **common)

        stage = "one-pass-plan"
        print("配布物・準備用tool・登録EXE・prefix・設定をWineを起動せず照合しています。", file=output, flush=True)
        if label == "新規":
            init_plan = refresh_init()
            installation = init_plan.trial.placement.installation
            proton = _proton(installation.inventory, installation.customization, installation.runtime,
                             installation.summary().get("tool_runtime_writes"))
            paths = [str(init_plan.compatdata), str(init_plan.trial.work), str(init_plan.trial.private_home)]
            compatdata = init_plan.compatdata
        else:
            base = base_plan(record, record_digest)
            proton = _proton(base.inventory, base.customization, base.runtime, base.tool_writes)
            paths = [str(base.compatdata), str(base.work), str(base.private_home)]
            compatdata = base.compatdata
        binding = plan_binding(steam, settings, key, proton["directory"])
        stage = "binding-history"
        if os.path.lexists(management):
            # Read before anything is written: an unreadable binding record stops here, not after installation.
            with PrivateStore(management) as store:
                binding_history(store, key)
        stage = "one-pass-plan"
        fixed = fixed_values(registration=_registration(games, key), profile=_profile(profile, recipes, softdenchi),
                             proton=proton, paths=paths, asset=asset, binding=binding.digest,
                             dlls=_dlls(profile, recipes, directory))
        report["confirmed_fixed_values"] = {"digest": digest_json(fixed), "items": item_digests(fixed)}
        evaluation = None
        if label != "新規":
            # The status check's evaluation: a stop that a later step would make is reported before any write.
            stage = "one-pass-evaluation"
            evaluation = evaluate_resume(record=record, record_digest=record_digest, profile=profile, recipes=recipes,
                                         softdenchi=softdenchi, source=source, games=catalog(), common=common,
                                         stop_check=ProcessStopCheck(compatdata), silent_launch=silent_launch,
                                         inventory=base.inventory)
            report["evaluation"] = {"next": evaluation["next"], "actions": evaluation["actions"]}
            if evaluation["next"] == "stop":
                report["steps"].extend(evaluation["steps"])
                next_step = evaluation["next_step"]
                if any(mark in evaluation["reason"] for mark in UNCLEAR):
                    next_step = ("ゲームまたはWineが動いているため確認できませんでした。何も変更していません。"
                                 "すべてのゲームとWineを終了してから、もう一度 " + one_pass_ref(config) + " を実行してください。")
                raise Stopped(evaluation["stage"], evaluation["reason"], next_step)
            stage = "one-pass-plan"
        actions = (evaluation["actions"] if evaluation is not None else
                   [*("prefix-dll:" + item["dependency_id"] for item in dll_items),
                    *(["softdenchi-silent"] if uses_softdenchi else []), "binding"])
        if mode == "plan":
            return 0, {"app_id": key, "label": label, "profile_id": profile_id, "fixed": fixed, "actions": actions,
                       "uses_softdenchi": uses_softdenchi, "asset": asset, "proton": proton["directory"],
                       "exe_path_ascii": init_plan.exe_path_ascii if init_plan is not None else True}
        if mode == "run":
            stage = "batch-confirmation"
            changed = changed_items(expected["fixed"], fixed, ("binding",))
            if label != expected.get("label"):
                changed.append("kind")
            more = sorted(set(actions) - set(expected["actions"]))
            if changed or more:
                report["fixed_value_changes"] = [{"stage": stage, "items": changed, "more_actions": more}]
                raise Stopped(stage, "confirmed-values-changed:" + ",".join(changed + more),
                              "確認したときの内容から変わりました。何も変更していません。もう一度 prepare.sh を実行してください。")
            print("準備しています: " + text(games[key]["title"]) + f" [ID {key}]", file=output, flush=True)
            output = io.StringIO()  # The batch screen showed and confirmed the details.
        print("ゲーム: " + text(games[key]["title"]) + f" [ID {key}]", file=output)
        print("作品プロファイル: " + text(profile["title"]) + f"（改訂{profile['revision']}）/ 依存 " +
              text(", ".join(profile["dependencies"]) or "なし"), file=output)
        print("prefix: " + text(str(compatdata)) + ("（新規作成）" if label == "新規" else "（初期化済み・続きから）"), file=output)
        print("準備用Proton: " + text(proton["directory"]), file=output)
        if label == "新規":
            print("専用work/HOME（新規）: " + text(paths[1]) + " / " + text(paths[2]), file=output)
        if label == "新規" and not init_plan.exe_path_ascii:
            print(NON_ASCII_NOTE, file=output)
        print("行うこと:", file=output)
        steps = itertools.count(1)
        if label == "新規":
            print(f"  {next(steps)}) prefixを初期化（準備用Protonで cmd.exe /d /c exit 0。ゲームは起動しません）", file=output)
        for item in dll_items:
            print(f"  {next(steps)}) prefixの" + DESTINATION + "に " + text(target_name(item)) + " が入っていなければ入れる（資材 " +
                  text(item["asset"]["filename"]) + "、SHA-256 " + item["asset"]["expected_sha256"][:16] +
                  "…）。既存のファイルは上書きせず、レジストリ・DLLの上書き設定は変えません", file=output)
        if uses_softdenchi:
            print(f"  {next(steps)}) ソフト電池が入っていなければ、インストーラー（" + text(spec["filename"]) + "、SHA-256 " +
                  spec["expected_sha256"][:16] + "…）を画面なしで実行（" + " ".join(asset["arguments"]) + "）", file=output)
            print("     インストーラーに同梱された使用許諾に同意したうえで導入します。この確認の1は、その同意を含みます。", file=output)
            print("     使用許諾を画面で読んでから導入したい場合は、ここでqを選び、" + menu_ref(config, 8) + "を使ってください。",
                  file=output)
            print("     導入後にSdProxyが残った場合は、" + menu_ref(config, 8) +
                  "と同じ条件を満たすものだけにSIGTERMを送ります（強制終了はしません）。", file=output)
            from preparation_vc_record import RELEASE_TEXT
            print("     " + RELEASE_TEXT, file=output)
        print(f"  {next(steps)}) ゲームフォルダーのファイルなど、ほかの依存は読み取りで照合（配置はしません）", file=output)
        print(f"  {next(steps)}) 依存がすべて検証済みなら、このゲームだけを準備用Protonへ割り当て（" +
              text(", ".join(binding.summary()["planned_files"]) or "変更なし") + "）", file=output)
        if evaluation is not None:
            print("今の状態から見込まれること: " + ("・".join(text(action_text(action, recipes)) for action in evaluation["actions"])
                                             or "入れるもの・割り当ての変更はありません（照合だけ）"), file=output)
        inside = [*(["DLL"] if dll_items else []), *(["ソフト電池", "受け継いだVC++の記録を外す"] if uses_softdenchi else [])]
        print("書くもの: 新規prefix・専用work/HOME・" + ("prefix内（" + "・".join(inside) + "）・" if inside else "") +
              "このゲームの設定項目・私有記録/lock・結果JSON。"
              "既存の他prefix・ゲームフォルダー・認証・セーブは変更しません。", file=output)
        print("すべてのゲーム・Wineを終了してから続行してください。", file=output)
        print("この内容で準備する場合は1、取消はq: ", end="", file=output, flush=True)
        if mode == "interactive" and stream.readline(32).strip() != "1":
            return 0, None
        output = real_output
        selection._private_report_directory(home, protected)
        lock = hashlib.sha256(str(compatdata).encode()).hexdigest()
        stop = ProcessStopCheck(compatdata)
        with PrivateStore(management, create=True) as store, store.locked(lock):
            # Writes of this game may exist from here; a lock held elsewhere stops before any write.
            started = True
            check_targets()
            # The private lock is held from here to the last step; the plans are compared again under it.
            if label == "新規":
                stage = "initialize"
                plan = refresh_init()
                installation = plan.trial.placement.installation
                check_fixed(fixed_values(registration=_registration(catalog(), key), profile=_profile(profile, recipes, softdenchi),
                    proton=_proton(installation.inventory, installation.customization, installation.runtime,
                                   installation.summary().get("tool_runtime_writes")),
                    paths=[str(plan.compatdata), str(plan.trial.work), str(plan.trial.private_home)], asset=asset,
                    binding=plan_binding(steam, settings, key, proton["directory"]).digest,
                    dlls=_dlls(profile, recipes, directory)))
                print("prefixを初期化しています。", file=output, flush=True)
                with droiddeck_lock(settings):
                    session = GamePrefixSession(plan, store, refresh_init, plan.digest, stop)
                    noted(store, "initialize", {"trial_id": session.record["trial_id"]})
                    report["steps"].append({"step": "initialize", "plan": plan.summary()})
                    live.update(step=report["steps"][-1], session=session)
                    session.start()
                    while True:
                        outcome = session.wait(30)
                        if outcome["status"] != "needs-user":
                            break
                        print("未完了です。強制終了していません。さらに待つ場合は1、記録を残して戻る場合はq: ", end="", file=output, flush=True)
                        if stream.readline(32).strip() != "1":
                            break
                report["steps"][-1]["record"] = outcome
                live.clear()
                if outcome["status"] != "initialized-unverified":
                    raise Stopped(stage, "initialization-" + outcome["status"], "初期化が完了しませんでした。作成物は削除せずに残しています。")
                record, record_digest = store.read_record(RECORDS, outcome["trial_id"] + ".json")
            else:
                stage = "resume-record"
                _, current_digest = store.read_record(RECORDS, record["trial_id"] + ".json")
                require(current_digest == record_digest, "game prefix record changed")
            for item in dll_items:
                stage = "prefix-dll"

                def refresh_dll(item=item):
                    return plan_prefix_dll(record=record, record_sha256=record_digest, item=item, source=source,
                                           games=catalog(), stop_check=stop, previous_slots=previous_roots(common), **common)

                dll_plan = refresh_dll()
                check_fixed(from_base(dll_plan.recheck, asset, plan_binding(steam, settings, key, proton["directory"]).digest))
                report["steps"].append({"step": "prefix-dll", "plan": dll_plan.summary()})
                if dll_plan.action == "skip":
                    continue
                confirmed("prefix-dll:" + item["dependency_id"])
                if dll_plan.blockers:
                    raise Stopped(stage, "prefix-dll-blocked:" + ",".join(dll_plan.blockers),
                                  PREFIX_DLL_BLOCKED.format(target_name(item)))
                print("prefixに " + text(target_name(item)) + " を入れています。", file=output, flush=True)
                with droiddeck_lock(settings):
                    session = PrefixDllSession(dll_plan, store, refresh_dll, dll_plan.digest, stop)
                    # One key per DLL, so a second DLL's ID does not replace the first one's (design 6).
                    noted(store, "prefix-dll:" + item["dependency_id"], {"record_id": session.record["record_id"]})
                    live.update(step=report["steps"][-1], session=session)
                    result = session.apply()
                report["steps"][-1]["record"] = result
                live.clear()
                if result["phase"] != "present-verified":
                    step = text(str((result.get("error") or {}).get("check")))
                    if result["phase"] == "failed":
                        hint = "DLLのファイルは作っていません。原因を取り除いてから、もう一度 " + one_pass_ref(config) + " を実行してください。"
                    elif result["phase"] == "planned":
                        hint = ("DLLのファイルを作った直後に止まりました。空のファイルが残っている可能性があります（削除していません）。"
                                "結果JSONを戻してください（回復の手順をお知らせします）。")
                    else:
                        hint = ("作ったDLLのファイル（書きかけの可能性があります）は削除していません。"
                                "結果JSONを戻してください（回復の手順をお知らせします）。")
                    raise Stopped(stage, "prefix-dll-" + result["phase"], "DLLを入れられませんでした（段階: " + step + "）。" + hint)
            if uses_softdenchi:
                stage = "softdenchi-state"
                base = base_plan(record, record_digest)
                check_fixed(from_base(base, asset, plan_binding(steam, settings, key, proton["directory"]).digest))
                previous, invalid = _installations(base.store_root, key)
                latest = previous[-1] if previous else None
                from preparation_dependency_install import vc_latest
                from preparation_vc_record import text_reason
                vc_stop = vc_latest(base.store_root, record["trial_id"])[1]
                if vc_stop is not None:
                    raise Stopped(stage, "inherited-vc-record-" + vc_stop.split(":", 1)[0],
                                  "ソフト電池の導入前に止まりました：" + text_reason(vc_stop) + "。もう一度実行しても進みません。"
                               "やり直すときは " + redo_ref(config) + " を使います。")
                state = inspect_managed_dependency(base, store, stop, softdenchi)
                action, reason, separately = softdenchi_action(latest, invalid, state["state"])
                step = {"step": "softdenchi-state", "latest_installation": latest and {k: latest.get(k) for k in
                        ("install_id", "status", "phase")}, "current_state": state["state"], "action": action, "reason": reason}
                if separately:
                    step["note"] = "current-state-confirmed-by-separate-read-only-inspection"
                report["steps"].append(step)
                if action == "stop":
                    raise Stopped(stage, reason, SOFTDENCHI_STATE_STOP)
                if action == "install":
                    confirmed("softdenchi-silent")
                    stage = "softdenchi-silent"

                    def refresh_silent():
                        return plan_dependency_install(record=record, record_sha256=record_digest, source=source, games=catalog(),
                                                       recipe=softdenchi, installer_mode="silent", silent_launch=silent_launch,
                                                       **common)

                    dplan = refresh_silent()
                    check_fixed(from_base(dplan.recheck, asset, plan_binding(steam, settings, key, proton["directory"]).digest))
                    if dplan.blockers:
                        raise Stopped(stage, "dependency-plan-blocked:" + ",".join(dplan.blockers))
                    print("ソフト電池を画面なしで導入しています（最初の10分は確認なしで待ちます）。", file=output, flush=True)
                    with droiddeck_lock(settings):
                        session = DependencyInstallSession(dplan, store, refresh_silent, dplan.digest, stop)
                        noted(store, "softdenchi-silent", {"install_id": session.record["install_id"]})
                        report["steps"].append({"step": "softdenchi-silent", "plan": dplan.summary()})
                        live.update(step=report["steps"][-1], session=session)
                        session.start_silent_installer()
                        if session.release_stopped is None:
                            try:
                                _wait_loop(session.wait_installer, stream, output, "installer", INSTALLER_QUIET_WAIT)
                                if session.record["installer"]["status"] == "exited-processes-remain":
                                    _offer_session_proxy_stop(session, stream, output, text, preapproved=True, next_step=None)
                            except Exception:
                                # Also when the wait or the stop raised (not Ctrl+C: a run left before its end stays open).
                                _record_log(session, report["steps"][-1], output)
                                raise
                            _record_log(session, report["steps"][-1], output)
                    result = dict(session.record)
                    report["steps"][-1]["record"] = result
                    live.clear()
                    if session.release_stopped is not None:
                        raise Stopped(stage, "inherited-vc-record-" + session.release_stopped.split(":", 1)[0],
                                      release_next_step(session.record, config))
                    if result["status"] == "cancelled-absent":
                        result = interactive_fallback(record, record_digest)
                    if result is None or result["status"] != "present-verified":
                        raise Stopped(stage, "installation-" + ("declined" if result is None else result["status"]),
                                      installation_next_step(result, config))
            stage = "binding"
            bplan = plan_game_binding(record=record, record_sha256=record_digest, source=source, games=catalog(), stop_check=stop,
                                      recipe=softdenchi, **common)
            if binding_action(bplan.binding, binding_history(store, key))[0] == "already-bound" and previous_roots(common):
                # Judgement only (nothing is written for an already bound game): a moved game before its first launch.
                bplan = plan_game_binding(record=record, record_sha256=record_digest, source=source, games=catalog(),
                                          stop_check=stop, recipe=softdenchi, previous_slots=previous_roots(common), **common)
            check_fixed(from_base(bplan.base, asset, bplan.binding.digest))
            summary = bplan.summary()
            for item in summary["dependencies"]:
                print("  依存: " + text(item["dependency_id"] + " / " + item["state"]), file=output)
            action, reason = binding_action(bplan.binding, binding_history(store, key))
            report["steps"].append({"step": "binding-plan", "plan": summary, "action": action, "reason": reason})
            # Dependencies first (design 5.1 step 4 before 5): an already bound game is not "ready" while one is unverified.
            if bplan.blockers:
                raise Stopped(stage, "binding-blocked:" + ",".join(bplan.blockers),
                              BINDING_RUNNING if PROCESS_BLOCKER in bplan.blockers else BINDING_BLOCKED)
            if action == "already-bound":
                print("このゲームはすでに準備用Protonに割り当て済みです。設定は変更しません。", file=output)
            elif action == "stop":
                raise Stopped(stage, reason, BINDING_STOP)
            else:
                confirmed("binding")
                result = apply_game_binding(bplan, store, lambda: plan_game_binding(
                    record=record, record_sha256=record_digest, source=source, games=catalog(), stop_check=stop,
                    recipe=softdenchi, **common), bplan.digest, stop, softdenchi,
                    on_binding_id=apply_note(store, key, bplan, lambda run_id: noted(store, "binding", {"binding_id": run_id})),
                    under_lock=None if targets is None else confirmed_targets(key, targets))
                report["steps"].append({"step": "binding", "result": result})
                report["binding_written"] = result["status"] == "binding-verified"
                if result["status"] != "binding-verified":
                    raise Stopped(stage, "binding-" + result["status"], "割り当てが完了しませんでした。設定のバックアップは私有記録にあります。")
        report["status"] = "ready-to-launch"
        print("準備が終わりました。DroidDeckからこのゲームを起動" + ("し、ソフト電池の認証を行ってください。" if uses_softdenchi
                                                                   else "してください。"), file=output)
    except Stopped as stopped:
        output = real_output
        report.update(status="stopped", stage=stopped.check, reason=stopped.reason, next_step=stopped.next_step)
        print("停止: " + text(stopped.check) + " / " + text(stopped.reason), file=output)
        if stopped.next_step:
            print(stopped.next_step, file=output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        output = real_output
        report.update(status="stopped", stage=stage, **describe_error(error, stage),
                      writes_may_exist=started)
        if live:
            # As in menus 8 and 10, the record of the interrupted step is kept in the result.
            live["step"].update(record=dict(live["session"].record), interrupted=True)
        print("検査停止: " + text(report["check"]) + " / " + text(report["reason"] or report["error_class"]), file=output)
        print("作成物・記録は削除していません。", file=output)
    if mode != "interactive":
        return (0 if mode == "plan" else 2), report
    try:
        saved, private = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録と作成物は保持しています。", file=output)
        return 1, None
    print("結果を保存しました: " + text(str(saved)), file=output)
    offer_log_copies(report, saved, directory, home, stream, output, text, private)
    return 2, str(saved)
