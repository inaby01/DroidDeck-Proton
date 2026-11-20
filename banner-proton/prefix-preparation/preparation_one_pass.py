"""Menu 12: prepare one registered game in one run (initialize, install, bind).

Each step calls the plan, session and writer that menus 10, 8 and 11 use, and plans again
right before it runs. One confirmation covers the fixed values shown before anything is
written; a later plan whose fixed values differ stops the run without asking again. The
SoftDenchi bootstrap runs with its pinned silent arguments. Only when that installs nothing
is the interactive installer offered, under a separate confirmation of its own plan.

The run resumes from the private records of the selected registration, so a stop (for
example a refused SdProxy stop) is continued by running menu 12 again for the same game.
"""

import hashlib
import os
from pathlib import Path

from preparation_assets import digest_json, exe_identity
from preparation_common import VERSION, require, safe_path
from preparation_game_prefix import (
    NON_ASCII_NOTE,
    RECORDS,
    GamePrefixSession,
    apply_game_binding,
    plan_game_binding,
    plan_game_prefix,
    registration_identity,
    validate_game_config,
)
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore

MODE = "one-pass-game-preparation-result"
SCOPE = "registered-game-one-pass-preparation"
SOFTDENCHI = "softdenchi-interactive"
RESTART_THEN_12 = "DroidDeckを完全に終了して起動し直してから、もう一度 12 で同じゲームを選んでください（続きから進めます）。"
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
    from preparation_softdenchi_recipe import silent_arguments
    arguments = silent_arguments(softdenchi, silent_launch) if mode == "silent" else []
    return {"spec": digest_json(config["dependency_installation"]["asset"]), "mode": mode, "arguments": arguments}


def fixed_values(*, registration, profile, proton, paths, asset, binding):
    """The values the single confirmation is given for; stage-dependent states are excluded."""
    return {"registration": registration, "profile": profile, "proton": proton, "paths": paths, "asset": asset,
            "binding": binding}


def without_mode(values):
    """Fixed values minus the installer mode and arguments (the interactive fallback changes only these)."""
    result = dict(values)
    result["asset"] = {key: value for key, value in values["asset"].items() if key not in ("mode", "arguments")}
    return result


def softdenchi_action(latest, invalid, current):
    """Design 5.1 step 3: history row first, then the current read-only state.

    Returns ("install" | "skip" | "stop", reason, inspected_separately).
    """
    if invalid:
        return "stop", "invalid-installation-record-present", False
    if latest is not None and latest["status"] == "failed":
        return "stop", "previous-installation-failed-review-required", False
    separately = latest is not None and latest.get("phase") != "post-inspected"
    if latest is None or latest["status"] in RETRYABLE:
        if current == "absent":
            return "install", None, False
        if current == "present-verified":
            return "skip", None, separately
        return "stop", "dependency-state-" + current, False
    if latest["status"] == "present-verified" and latest.get("phase") == "post-inspected":
        if current == "present-verified":
            return "skip", None, False
        return "stop", "dependency-state-" + current + "-after-verified-installation", False
    return "stop", "previous-installation-" + latest["status"] + "-review-required", False


def _game_records(management, key=None):
    if not os.path.lexists(management):
        return []
    with PrivateStore(management) as store:
        listed = store.inventory()["game_prefixes"]
    require(not any(item.get("status") == "invalid" for item in listed), "invalid game prefix record present")
    return [item for item in listed if key is None or item["app_id"] == key]


def _binding_history(store, key):
    history = []
    for item in store.inventory()["bindings"]:
        require(item.get("status") != "invalid", "invalid binding record present")
        record, _ = store.read_record("bindings", item["binding_id"] + ".json")
        if record["app_id"] == key:
            history.append(record["status"])
    return history


def binding_action(binding, history):
    """Design 5.2: decided by the current three files, never by a past record alone."""
    from preparation_binding import FILES
    bound = [name for name in FILES if binding.before[name] == binding.after[name]]
    if len(bound) == len(FILES):
        return "already-bound", None
    if any(status != "binding-verified" for status in history):
        return "stop", "previous-binding-incomplete"
    if history:
        return "stop", "binding-changed-after-verified-binding"
    return "apply", None


def interactive_one_pass(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                         steam=None, settings=None, home=None, runtime_root=Path("/"), recipe=None, silent_launch=None,
                         sender=None):
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
    from preparation_softdenchi_recipe import softdenchi_recipe, validate_recipe

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    softdenchi = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    text = selection._text
    protected, stage, started = [steam, settings], "one-pass-config", False
    report = {"mode": MODE, "scope": SCOPE, "tool_version": VERSION, "steps": [], "binding_written": False,
              "game_launched": False, "authentication_performed": False, "preparation_complete": False}
    common = {"config": config, "directory": directory, "renderer": renderer, "steam": steam, "settings": settings,
              "home": home, "environment": environment, "runtime_root": runtime_root}

    def catalog():
        current, _, games = selection.registration_catalog(environment)
        require(current == source, "registration source changed")
        return games

    def base_plan(record, digest):
        return plan_recheck(record=record, record_sha256=digest, source=source, games=catalog(), records=RECORDS, **common)

    def from_base(base, asset, binding_digest):
        return fixed_values(registration=_registration(catalog(), key), profile=_profile(profile, recipes, softdenchi),
                            proton=_proton(base.inventory, base.customization, base.runtime, base.tool_writes),
                            paths=[str(base.compatdata), str(base.work), str(base.private_home)], asset=asset,
                            binding=binding_digest)

    def check_fixed(current, compare=None):
        if (compare or (lambda v: v))(current) != (compare or (lambda v: v))(fixed):
            raise Stopped(stage, "fixed-values-changed", "確認したときの内容（登録・作品・資材・Proton・設定）が変わりました。"
                          "もう一度 12 を実行して、内容を確認し直してください。")

    def interactive_fallback(record, record_digest):
        """Silent run installed nothing: offer the interactive installer under its own confirmation."""
        def refresh():
            return plan_dependency_install(record=record, record_sha256=record_digest, source=source, games=catalog(),
                                           recipe=softdenchi, installer_mode="interactive", **common)

        plan = refresh()
        interactive_asset = {**asset, "mode": "interactive", "arguments": []}
        current = from_base(plan.recheck, interactive_asset, plan_binding(steam, settings, key, proton["directory"]).digest)
        if without_mode(current) != without_mode(fixed):
            raise Stopped("softdenchi-interactive", "fixed-values-changed",
                          "確認したときの内容が変わったため、画面ありの導入に切り替えません。")
        if plan.blockers:
            raise Stopped("softdenchi-interactive", "dependency-plan-blocked:" + ",".join(plan.blockers))
        print("画面なしの導入では、ソフト電池は入りませんでした（何も変更されていません）。", file=output)
        print("画面ありで導入する場合は1、やめる場合はq（画面が出るかをwinverで確かめてから、インストーラーを起動します）: ",
              end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            report["steps"].append({"step": "softdenchi-interactive", "declined": True})
            return None
        report["steps"].append({"step": "softdenchi-interactive", "confirmed_plan": plan.digest})
        with droiddeck_lock(settings):
            session = DependencyInstallSession(plan, store, refresh, plan.digest, stop)
            session.start_gui_check()
            print("winverの画面が出たら、内容を確認して閉じてください。", file=output, flush=True)
            outcome = _wait_loop(session.wait_gui_check, stream, output, "gui_check")
            if outcome["phase"] == "gui-check-stopped":
                print("winverの画面が表示され、閉じられましたか？ 表示された場合は1、表示されなかった場合はq: ", end="", file=output, flush=True)
                if session.confirm_display(stream.readline(32).strip() == "1")["phase"] == "gui-check-stopped":
                    session.start_installer()
                    print("インストーラーの画面で操作してください。完了を待っています"
                          f"（最初の{INSTALLER_QUIET_WAIT // 60}分は確認なしで待ちます）。", file=output, flush=True)
                    _wait_loop(session.wait_installer, stream, output, "installer", INSTALLER_QUIET_WAIT)
                    if session.record["installer"]["status"] == "exited-processes-remain":
                        _offer_session_proxy_stop(session, stream, output, text, preapproved=True, next_step=RESTART_THEN_12)
        result = dict(session.record)
        report["steps"][-1]["record"] = result
        return result

    try:
        selection.validate_selection_config(config)
        require(config.get("initialization_trial") is True and "placement_review" in config and
                "game_preparation" in config and "dependency_installation" in config, "one-pass preparation not enabled")
        profiles, recipes = validate_game_config(config.get("game_preparation"))
        stage = "registration-selection"
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        records = {}
        for item in _game_records(management):
            records.setdefault(item["app_id"], []).append(item)
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
        for number, (key_, label) in enumerate(candidates, 1):
            print(f"{number}. [{label}] {text(games[key_]['title'])} [ID {key_}]", file=output)
            print("   " + text(games[key_]["exe"]), file=output)
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
        if label == "新規":
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

        def refresh_init():
            return plan_game_prefix(source=source, games=catalog(), key=key, profile_id=profile_id, **common)

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
        fixed = fixed_values(registration=_registration(games, key), profile=_profile(profile, recipes, softdenchi),
                             proton=proton, paths=paths, asset=asset, binding=binding.digest)
        report["confirmed_fixed_values"] = digest_json(fixed)
        print("ゲーム: " + text(games[key]["title"]) + f" [ID {key}]", file=output)
        print("作品プロファイル: " + text(profile["title"]) + f"（改訂{profile['revision']}）/ 依存 " +
              text(", ".join(profile["dependencies"])), file=output)
        print("prefix: " + text(str(compatdata)) + ("（新規作成）" if label == "新規" else "（初期化済み・続きから）"), file=output)
        print("準備用Proton: " + text(proton["directory"]), file=output)
        if label == "新規" and not init_plan.exe_path_ascii:
            print(NON_ASCII_NOTE, file=output)
        print("行うこと:", file=output)
        if label == "新規":
            print("  1) prefixを初期化（準備用Protonで cmd.exe /d /c exit 0。ゲームは起動しません）", file=output)
        if uses_softdenchi:
            print("  2) ソフト電池が入っていなければ、インストーラー（" + text(config["dependency_installation"]["asset"]["filename"]) +
                  "）を画面なしで実行（" + " ".join(asset["arguments"]) + "）", file=output)
            print("     インストーラーに同梱された使用許諾に同意したうえで導入します。この確認の1は、その同意を含みます。", file=output)
            print("     使用許諾を画面で読んでから導入したい場合は、ここでqを選び、メニュー8を使ってください。", file=output)
            print("     導入後にSdProxyが残った場合は、メニュー8と同じ条件を満たすものだけにSIGTERMを送ります（強制終了はしません）。",
                  file=output)
        print("  3) ゲームフォルダーのファイルなど、ほかの依存は読み取りで照合（配置はしません）", file=output)
        print("  4) 依存がすべて検証済みなら、このゲームだけを準備用Protonへ割り当て（" +
              text(", ".join(binding.summary()["planned_files"]) or "変更なし") + "）", file=output)
        print("書くもの: 新規prefix・専用work/HOME・prefix内（ソフト電池）・このゲームの設定項目・私有記録/lock・結果JSON。"
              "既存の他prefix・ゲームフォルダー・認証・セーブは変更しません。", file=output)
        print("すべてのゲーム・Wineを終了してから続行してください。", file=output)
        print("この内容で準備する場合は1、取消はq: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            return 0, None
        started = True
        selection._private_report_directory(home, protected)
        lock = hashlib.sha256(str(compatdata).encode()).hexdigest()
        stop = ProcessStopCheck(compatdata)
        with PrivateStore(management, create=True) as store, store.locked(lock):
            # The private lock is held from here to the last step; the plans are compared again under it.
            if label == "新規":
                stage = "initialize"
                plan = refresh_init()
                installation = plan.trial.placement.installation
                check_fixed(fixed_values(registration=_registration(catalog(), key), profile=_profile(profile, recipes, softdenchi),
                    proton=_proton(installation.inventory, installation.customization, installation.runtime,
                                   installation.summary().get("tool_runtime_writes")),
                    paths=[str(plan.compatdata), str(plan.trial.work), str(plan.trial.private_home)], asset=asset,
                    binding=plan_binding(steam, settings, key, proton["directory"]).digest))
                print("prefixを初期化しています。", file=output, flush=True)
                with droiddeck_lock(settings):
                    session = GamePrefixSession(plan, store, refresh_init, plan.digest, stop)
                    session.start()
                    while True:
                        outcome = session.wait(30)
                        if outcome["status"] != "needs-user":
                            break
                        print("未完了です。強制終了していません。さらに待つ場合は1、記録を残して戻る場合はq: ", end="", file=output, flush=True)
                        if stream.readline(32).strip() != "1":
                            break
                report["steps"].append({"step": "initialize", "record": outcome})
                if outcome["status"] != "initialized-unverified":
                    raise Stopped(stage, "initialization-" + outcome["status"], "初期化が完了しませんでした。作成物は削除せずに残しています。")
                record, record_digest = store.read_record(RECORDS, outcome["trial_id"] + ".json")
            else:
                stage = "resume-record"
                _, current_digest = store.read_record(RECORDS, record["trial_id"] + ".json")
                require(current_digest == record_digest, "game prefix record changed")
            if uses_softdenchi:
                stage = "softdenchi-state"
                base = base_plan(record, record_digest)
                check_fixed(from_base(base, asset, plan_binding(steam, settings, key, proton["directory"]).digest))
                previous, invalid = _installations(base.store_root, key)
                latest = previous[-1] if previous else None
                state = inspect_managed_dependency(base, store, stop, softdenchi)
                action, reason, separately = softdenchi_action(latest, invalid, state["state"])
                step = {"step": "softdenchi-state", "latest_installation": latest and {k: latest.get(k) for k in
                        ("install_id", "status", "phase")}, "current_state": state["state"], "action": action, "reason": reason}
                if separately:
                    step["note"] = "current-state-confirmed-by-separate-read-only-inspection"
                report["steps"].append(step)
                if action == "stop":
                    raise Stopped(stage, reason, "ソフト電池の導入記録または状態に確認が要ります。修復はしていません。")
                if action == "install":
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
                        session.start_silent_installer()
                        _wait_loop(session.wait_installer, stream, output, "installer", INSTALLER_QUIET_WAIT)
                        if session.record["installer"]["status"] == "exited-processes-remain":
                            _offer_session_proxy_stop(session, stream, output, text, preapproved=True, next_step=RESTART_THEN_12)
                    result = dict(session.record)
                    report["steps"].append({"step": "softdenchi-silent", "record": result})
                    if result["status"] == "cancelled-absent":
                        result = interactive_fallback(record, record_digest)
                    if result is None or result["status"] != "present-verified":
                        status = "declined" if result is None else result["status"]
                        raise Stopped(stage, "installation-" + status,
                                      RESTART_THEN_12 if result is not None and result.get("post_state") in (None, "uninspected")
                                      else "ソフト電池の導入は完了していません。")
            stage = "binding"
            bplan = plan_game_binding(record=record, record_sha256=record_digest, source=source, games=catalog(), stop_check=stop,
                                      recipe=softdenchi, **common)
            check_fixed(from_base(bplan.base, asset, bplan.binding.digest))
            summary = bplan.summary()
            for item in summary["dependencies"]:
                print("  依存: " + text(item["dependency_id"] + " / " + item["state"]), file=output)
            action, reason = binding_action(bplan.binding, _binding_history(store, key))
            report["steps"].append({"step": "binding-plan", "plan": summary, "action": action, "reason": reason})
            if action == "already-bound":
                print("このゲームはすでに準備用Protonに割り当て済みです。設定は変更しません。", file=output)
            elif action == "stop":
                raise Stopped(stage, reason, "割り当ての状態に確認が要ります。設定は変更していません。")
            elif bplan.blockers:
                raise Stopped(stage, "binding-blocked:" + ",".join(bplan.blockers), "全依存が検証済みになるまで割り当てません。")
            else:
                result = apply_game_binding(bplan, store, lambda: plan_game_binding(
                    record=record, record_sha256=record_digest, source=source, games=catalog(), stop_check=stop,
                    recipe=softdenchi, **common), bplan.digest, stop)
                report["steps"].append({"step": "binding", "result": result})
                report["binding_written"] = result["status"] == "binding-verified"
                if result["status"] != "binding-verified":
                    raise Stopped(stage, "binding-" + result["status"], "割り当てが完了しませんでした。設定のバックアップは私有記録にあります。")
        report["status"] = "ready-to-launch"
        print("準備が終わりました。DroidDeckからこのゲームを起動し、ソフト電池の認証を行ってください。", file=output)
    except Stopped as stopped:
        report.update(status="stopped", stage=stopped.check, reason=stopped.reason, next_step=stopped.next_step)
        print("停止: " + text(stopped.check) + " / " + text(stopped.reason), file=output)
        if stopped.next_step:
            print(stopped.next_step, file=output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report.update(status="stopped", stage=stage, **describe_error(error, stage),
                      writes_may_exist=started)
        print("検査停止: " + text(report["check"]) + " / " + text(report["reason"] or report["error_class"]), file=output)
        print("作成物・記録は削除していません。", file=output)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録と作成物は保持しています。", file=output)
        return 1, None
    print("結果を保存しました: " + text(str(saved)), file=output)
    return 2, str(saved)

