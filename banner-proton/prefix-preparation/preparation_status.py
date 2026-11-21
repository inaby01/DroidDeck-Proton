"""Operational entry 2: the state of each game this tool prepared, read-only.

No locks (neither the private store locks nor the DroidDeck settings lock), no store
creation, no Wine, no SdProxy stop offer; only the result JSON is written, by the usual
rule for results. The next step comes from the evaluation menu 1 uses before it writes
(``evaluate_resume``), so the two cannot disagree. A problem of one game is shown and the
next game follows (design: operational entry 6).
"""

import os
from pathlib import Path

from preparation_binding import (
    FILES,
    STEAM_PATH,
    _games_document,
    _json,
    _raw,
    plan_binding,
    registered_tool,
)
from preparation_common import MAX_JSON, VERSION, require, safe_path
from preparation_dependency_install import describe_error
from preparation_game_prefix import RECORDS, validate_game_config
from preparation_one_pass import _game_records, action_text, evaluate_resume
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore
from preparation_vdf import Document

MODE = "game-status-result"
SCOPE = "read-only-game-status"
# A process appeared or the view was not clear while reading (design 6.1: shown as running or changing).
UNCLEAR = ("concurrent-process-observed", "target-process-view-not-clear", "dependency-state-uninspected")
FILE_NAMES = {"games": "games.json", "config": "config.vdf", "state": "state.json"}


def _current(steam, settings, key):
    """The current assignment items of one registration in the three files (None when absent)."""
    raw = _raw(safe_path(steam / "config/config.vdf", steam))
    require(raw is not None, "existing config required")
    node = Document(raw, value_limit=MAX_JSON).node(STEAM_PATH).value
    require(type(node) is dict, "invalid Steam block")
    mapping = node.get("CompatToolMapping")
    entry = mapping.value.get(key) if mapping is not None and type(mapping.value) is dict else None
    name = entry.value.get("name") if entry is not None and type(entry.value) is dict else None
    games = _games_document(_raw(safe_path(settings / "games.json", settings)))["games"].get(key)
    state = _json(_raw(safe_path(settings / "state.json", settings)), {})
    applied = state.get("games_applied")
    return {"config": None if name is None else str(name.value), "games": games,
            "state": applied.get(key) if type(applied) is dict else None}


def _tool_id(steam, directory):
    """The tool ID declared by an installed custom tool directory, or None when it cannot be read."""
    try:
        root = safe_path(steam / "compatibilitytools.d" / directory, steam)
        tools = Document(_raw(root / "compatibilitytool.vdf")).node(("compatibilitytools", "compat_tools")).value
        return next(iter(tools)) if type(tools) is dict and len(tools) == 1 else None
    except (OSError, ValueError, TypeError, KeyError, StopIteration):
        return None


def assignment(steam, settings, key, slot):
    """Classify the assignment from the three files (design 6.3).

    ``slot`` is this bundle's preparation slot directory when it is placed and verified. The
    comparison with the slot is the one menu 1 makes (``plan_binding`` before/after, which
    covers ``state.json``); the current tool name comes from ``config.vdf``.
    """
    current = _current(steam, settings, key)
    result = {"current_tool": current["config"], "games_dir": (current["games"] or {}).get("dir"),
              "applied_dir": (current["state"] or {}).get("dir")}
    if slot is not None:
        plan = plan_binding(steam, settings, key, slot)
        bound = [name for name in FILES if plan.before[name] == plan.after[name]]
        if len(bound) == len(FILES):
            return {**result, "kind": "this-slot"}
        if bound:
            return {**result, "kind": "partial", "differing_files": [FILE_NAMES[name] for name in FILES if name not in bound]}
        if slot in (result["games_dir"], result["applied_dir"]) or current["config"] == plan.tool:
            return {**result, "kind": "partial", "differing_files": [FILE_NAMES[name] for name in FILES]}
    if current["config"] is None and current["games"] is None and current["state"] is None:
        return {**result, "kind": "none"}
    consistent = (current["config"] is not None and current["games"] is not None and current["state"] == current["games"]
                  and (current["games"].get("valve") or _tool_id(steam, current["games"]["dir"]) in (None, current["config"])))
    if consistent:
        return {**result, "kind": "other"}
    return {**result, "kind": "other-disagreeing", "differing_files": [
        FILE_NAMES[name] for name, value in current.items() if value is None] or ["games.json", "config.vdf", "state.json"]}


ASSIGNMENT_TEXT = {"this-slot": "このバンドルの準備用Proton", "none": "なし"}


def _assignment_text(found, text):
    if found["kind"] in ASSIGNMENT_TEXT:
        return ASSIGNMENT_TEXT[found["kind"]]
    if found["kind"] == "other":
        return "別のProton（" + text(found["current_tool"]) + "）"
    files = "・".join(found["differing_files"])
    if found["kind"] == "partial":
        return "一部だけ（このバンドルの準備用Protonと食い違うファイル: " + files + "）"
    return "別のProtonへの割り当てが3つのファイルで食い違っています（" + files + "。今の名前: " + text(str(found["current_tool"])) + "）"


def _slot(config, directory, renderer, steam, environment, runtime_root):
    """Global check, once: the payload in the asset folder, the runtime, and the placed slot (design 6.2)."""
    from preparation_customization import plan_customizations
    from preparation_payload import verify_fex_runtime_tree
    from preparation_recheck import _require_live, read_payload_inventory
    from preparation_runtime_context import plan_runtime_environment
    result = {"payload": "unverified", "slot": "unverified", "directory": None}
    inventory = read_payload_inventory(config, directory)
    result["payload"] = "verified"
    runtime = plan_runtime_environment(runtime_root, config["runtime_reference"], environment)
    _require_live(runtime)
    payload = config["payload"]
    custom = plan_customizations(inventory, payload["archive"], payload["mode"], runtime_root / "usr/local/bin/steam-compatibility",
                                 renderer, label=runtime.label, umask=int(runtime.umask, 8), tool_slot="preparation")
    result["directory"] = custom.directory
    tool = safe_path(steam / "compatibilitytools.d" / custom.directory, steam)
    if not os.path.lexists(tool):
        result["slot"] = "absent"
        return result, inventory
    verify_fex_runtime_tree(tool, inventory, custom.overlays)
    registered_tool(steam, custom.directory)
    result["slot"] = "verified"
    return result, inventory


def _describe_steps(steps):
    for step in steps:
        if step["step"] == "binding-plan":
            return [{"dependency_id": item["dependency_id"], "state": item["state"]} for item in step["plan"]["dependencies"]]
    return None


def interactive_status(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                       steam=None, settings=None, home=None, runtime_root=Path("/"), recipe=None, silent_launch=None):
    import sys

    import preparation_selection as selection

    # Looked up at call time, as menu 1 does, so both use the same recipe.
    from preparation_softdenchi_recipe import softdenchi_recipe, validate_recipe

    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    text = selection._text
    protected = [steam, settings]
    report = {"mode": MODE, "scope": SCOPE, "tool_version": VERSION, "games": [], "writes_other_than_result": False,
              "locks_taken": False, "wine_executed": False}
    stage = "status-config"
    print("ゲームの状態を確認します（何も変更しません。ロックも取りません）。", file=output, flush=True)
    try:
        softdenchi = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True and "placement_review" in config and
                "game_preparation" in config and "dependency_installation" in config, "one-pass preparation not enabled")
        profiles, recipes = validate_game_config(config.get("game_preparation"))
        stage = "status-registrations"
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        stage = "status-records"
        if not os.path.lexists(management):
            report["status"] = "no-prepared-games"
            print("準備したゲームはありません。", file=output)
            records, unreadable = [], 0
        else:
            records, unreadable = _game_records(management)
        report["unreadable_game_prefix_records"] = unreadable
        if unreadable:
            print(f"読めない初期化記録が{unreadable}件あります（どの登録のものか分からないため、表示に使いません）。", file=output)
        inventory, slot = None, {"payload": "unverified", "slot": "unverified", "directory": None}
        if records:
            stage = "status-payload-and-slot"
            print("配布物・runtime・準備用Protonを照合しています。", file=output, flush=True)
            try:
                slot, inventory = _slot(config, directory, renderer, steam, environment, runtime_root)
            except (OSError, ValueError, TypeError, KeyError) as error:
                slot["error"] = describe_error(error, stage)
            report["global"] = slot
            if slot["payload"] != "verified":
                print("このバンドルのProtonの配布物を照合できません（" + text(str(slot["error"]["reason"] or slot["error"]["error_class"])) +
                      "）。依存は判定できません。", file=output)
            elif slot["slot"] == "absent":
                print("このバンドルの準備用Protonはまだ置かれていません（先に3）。依存は判定できません。", file=output)
            elif slot["slot"] != "verified":
                print("このバンドルの準備用Protonを照合できません（" + text(str(slot["error"]["reason"] or slot["error"]["error_class"])) +
                      "）。依存は判定できません。", file=output)
            else:
                print("準備用Proton: " + text(slot["directory"]) + "（配布物と一致）", file=output)
        by_key = {}
        for item in records:
            by_key.setdefault(item["app_id"], []).append(item)
        common = {"config": config, "directory": directory, "renderer": renderer, "steam": steam, "settings": settings,
                  "home": home, "environment": environment, "runtime_root": runtime_root}
        for key in sorted(by_key, key=int):
            entry = {"app_id": key}
            report["games"].append(entry)
            title = games[key]["title"] if key in games else None
            print(file=output)
            print("- " + (text(title) if title is not None else "（登録が見つかりません）") + f" [ID {key}]", file=output)
            context = {"games": games, "profiles": profiles, "recipes": recipes, "softdenchi": softdenchi, "source": source,
                       "common": common, "slot": slot, "inventory": inventory, "management": management,
                       "silent_launch": silent_launch, "output": output, "text": text}
            entry.update(_game(key, by_key[key], title, context))
        report.setdefault("status", "reported")
    except (OSError, ValueError, TypeError, KeyError) as error:
        report.update(status="stopped", stage=stage, **describe_error(error, stage))
        print("検査停止: " + text(report["check"]) + " / " + text(str(report["reason"] or report["error_class"])), file=output)
    report.update(schema_version=1, preparation_complete=False)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。", file=output)
        return 1, None
    print(file=output)
    print("結果を保存しました: " + text(str(saved)), file=output)
    return 2, str(saved)


def _game(key, listed, title, context):
    """One game's lines and result entry; every failure is shown and the next game follows."""
    output, text, slot, recipes = context["output"], context["text"], context["slot"], context["recipes"]
    steam, settings = context["common"]["steam"], context["common"]["settings"]
    entry = {}
    stage = "status-record"
    try:
        if len(listed) != 1:
            entry.update(record="several", next={"next": "stop", "stage": "registration-selection",
                                                  "reason": "several game prefix records for this registration"})
            print("  初期化の記録: 同じIDの記録が複数あります。1（新しいゲームを準備）はこのゲームで止まります。", file=output)
            return entry
        item = listed[0]
        entry["record"] = item["status"]
        if item["status"] != "initialized-unverified":
            entry["next"] = {"next": "stop", "stage": "resume-state", "reason": "initialization-" + item["status"]}
            print("  初期化の記録: 完了していません（" + text(item["status"]) + "）。1（新しいゲームを準備）はこのゲームで止まります"
                  "（作成物は削除せずに残しています）。", file=output)
            return entry
        print("  初期化の記録: 初期化済み / prefix: " + text(str(steam / "steamapps/compatdata" / key)), file=output)
        if title is None:
            entry["next"] = {"next": "not-listed", "reason": "registration-missing"}
            print("  DroidDeckの登録が見つからないため、1（新しいゲームを準備）の一覧に出ません。", file=output)
            return entry
        with PrivateStore(context["management"]) as store:
            record, record_digest = store.read_record(RECORDS, item["trial_id"] + ".json")
        profile = context["profiles"].get(record["profile"]["profile_id"])
        require(profile is not None, "game profile changed since initialization")
        entry["profile_id"] = profile["profile_id"]
        print("  作品プロファイル: " + text(profile["title"]) + f"（改訂{profile['revision']}）", file=output)
        stage = "status-assignment"
        found = assignment(steam, settings, key, slot["directory"] if slot["slot"] == "verified" else None)
        entry["assignment"] = found
        print("  割り当て: " + _assignment_text(found, text), file=output)
        if found["kind"] == "other":
            entry["next"] = {"next": "out-of-scope"}
            print("  このバンドルの対象外です（別のProtonに割り当て済み）。依存と次にすることは表示しません。", file=output)
            return entry
        if slot["slot"] != "verified":
            entry["next"] = {"next": "undetermined", "reason": "slot-" + slot["slot"]}
            print("  依存・次にすること: 判定できません（このバンドルの準備用Protonを照合できないため）。", file=output)
            return entry
        stage = "status-evaluation"
        compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
        stop_check = ProcessStopCheck(compatdata)
        if not stop_check.check()["clear_in_view"]:
            entry["next"] = {"next": "undetermined", "reason": "game-running"}
            print("  確認できません（動作中または変化中）。ゲームとWineを終了してから、もう一度2を実行してください。", file=output)
            return entry
        evaluation = evaluate_resume(record=record, record_digest=record_digest, profile=profile, recipes=recipes,
                                     softdenchi=context["softdenchi"], source=context["source"], games=context["games"],
                                     common=context["common"], stop_check=stop_check, silent_launch=context["silent_launch"],
                                     inventory=context["inventory"])
        entry["next"] = {name: evaluation[name] for name in ("next", "stage", "reason", "actions") if name in evaluation}
        entry["evaluated_steps"] = evaluation["steps"]
        dependencies = _describe_steps(evaluation["steps"])
        if dependencies is not None:
            entry["dependencies"] = dependencies
            print("  依存: " + "、".join(text(item["dependency_id"] + " / " + item["state"]) for item in dependencies), file=output)
        if evaluation["next"] == "ready":
            print("  次にすること: 起動できます（依存はすべて検証済みで、準備用Protonに割り当て済み）。", file=output)
        elif evaluation["next"] == "continue":
            print("  次にすること: 1で続きから進めます（" + "・".join(text(action_text(action, recipes))
                                                       for action in evaluation["actions"]) + "）。", file=output)
        elif any(mark in evaluation["reason"] for mark in UNCLEAR):
            print("  確認できません（動作中または変化中）。ゲームとWineを終了してから、もう一度2を実行してください。", file=output)
        else:
            print("  次にすること: 1（新しいゲームを準備）はここで止まります（" + text(evaluation["stage"] + " / " + evaluation["reason"]) + "）。", file=output)
            if evaluation.get("next_step"):
                print("  " + evaluation["next_step"], file=output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        entry["error"] = describe_error(error, stage)
        changing = str(error) == "input changed during read"
        entry["next"] = {"next": "undetermined", "reason": "changing" if changing else "unreadable"}
        if changing:
            print("  確認できません（動作中または変化中）。ゲームとWineを終了してから、もう一度2を実行してください。", file=output)
        else:
            print("  照合できません: " + text(entry["error"]["check"]) + " / " +
                  text(str(entry["error"]["reason"] or entry["error"]["error_class"])), file=output)
    return entry

