"""recovery.sh 7 (1.0.0): prepare one game again under the same registration.

A registration whose prefix was never assigned by this tool (no binding record at all) and is not
assigned to a preparation slot can have its prefix removed after one confirmation. The tool's
records of that ID move to the private ``retired`` folder (never deleted), so the next prepare.sh
lists the game as new. A game that was assigned once (it reached "ready" and may hold the
SoftDenchi authentication) is never offered. Design: 1.0.0, 7.2.
"""

import hashlib
import os
import re
import secrets
import shutil
import stat
import time
from pathlib import Path

from preparation_common import VERSION, Invalid, require, safe_path

MODE = "game-redo-result"
REDOS = "redos"
BINDINGS = "bindings"
RETIRED = ("game-prefixes", "dependency-installs", "prefix-dlls", "installer-logs", "binding-notes")
REMOVING = ".prefix-preparation-removing-"
WORK_ROOT = ".local/share/droiddeck-preparation-work"  # The per-game private work folder (preparation_installer_log).
FAILURES = (OSError, Invalid, ValueError, TypeError, KeyError, UnicodeError)

REASON_TEXT = {
    "prepared-before": "一度準備を終えています（認証やセーブがありうるため、やり直しません）",
    "binding-started": "設定の書き換えを始めた記録があります（書き換えが途中で止まった可能性があるため、やり直しません。"
                       "status.sh で確かめてください）",
    "assigned-to-softdenchi-proton": "ソフト電池用のProtonが選ばれています（認証済みの可能性があるため、やり直しません）",
    "softdenchi-in-unprepared-prefix": "ツールが入れた記録のないソフト電池がprefixに入っています（手作業で準備した可能性があるため、やり直しません）",
    "settings-unreadable": "DroidDeckの設定を読めません",
    "records-unreadable": "読めない記録があり、このゲームのものか判断できません",
    "not-a-directory": "prefixの場所がフォルダーではありません",
    "several-prefixes": "このゲームのprefixが、IDの書き方違いで2つあります（どちらのものか判断できないため、やり直しません）",
    "work-folder-unexpected": "このゲームの作業用フォルダーが想定外の形です",
    "game-or-wine-running": "このゲームかWineが動いています。終了してからもう一度実行してください",
    "changed-since-confirmation": "確認したあとで、このゲームのprefixが変わりました（起動したなど）。もう一度 recovery.sh の7を実行してください",
    "prefix-unreadable": "prefixの中を読めません（ソフト電池が入っているか確かめられないため、やり直しません）",
}


def _records_of(store, directory, key):
    """Names of the readable records of ``key`` in one private directory, and the unreadable count."""
    try:
        with store.directory((directory,)) as fd:
            listing = sorted(store._names(fd))
    except FileNotFoundError:
        return [], 0
    names, unreadable = [], 0
    for name in listing:
        if name.startswith("tmp-") or not name.endswith(".json"):
            continue
        try:
            record, _ = store.read_record(directory, name)
        except FAILURES:
            unreadable += 1
            continue
        if type(record) is dict and record.get("app_id") == key:
            names.append(name)
    return names, unreadable


def _softdenchi_choice(files, key):
    """The SoftDenchi Proton a registration is set to in any of DroidDeck's three files, or None.

    A preparation slot (``SoftDenchi-Prep-Proton``) or a hand-installed ``SoftDenchi-Proton`` may have been
    used to authenticate; such a game is never offered (1.0.0, 7.2)."""
    from preparation_proton_update import current_selection
    selection = current_selection(files, key)
    names = [selection["config"]] + [choice.get(field) for choice in (selection["games"], selection["applied"])
                                     if type(choice) is dict and choice.get("valve") is False for field in ("dir", "name")]
    return next((name for name in names if type(name) is str and "softdenchi" in name.casefold()), None)


# Where SoftDenchi's installer leaves files in a prefix (preparation_softdenchi_recipe).
SOFTDENCHI_TRACES = (("pfx", "drive_c", "Program Files (x86)", "SoftDenchi"),
                     ("pfx", "drive_c", "Program Files", "SoftDenchi"),
                     ("pfx", "drive_c", "windows", "ucharge"))


def _has_softdenchi(compatdata):
    """Whether any of SoftDenchi's folders exists in a prefix (read-only, no links followed); None when a
    folder on the way cannot be read or is a link or a file (the caller refuses: never treated as absent)."""
    found = False
    for trace in SOFTDENCHI_TRACES:
        folder = compatdata
        for part in trace:
            try:
                with os.scandir(folder) as entries:
                    match = next((entry for entry in entries if entry.name.casefold() == part.casefold()), None)
            except FileNotFoundError:
                match = None
            except OSError:
                return None
            if match is None:
                break
            if not match.is_dir(follow_symlinks=False):
                return None  # A link (also a dangling one) or a file under that name.
            folder = folder / match.name
        else:
            found = True
    return found


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prefix_names(key):
    """The folder names a registration's prefix can have: its ID, and for a large ID also the signed form."""
    number = int(key)
    return [key] + ([str(number - 2**32)] if number >= 2**31 else [])


def _own_directory(path):
    info = os.lstat(path)
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()


def candidate(ctx, key, title, files):
    """Whether one registration can be prepared again: {app_id, title, eligible, reason, records}.

    A registration qualifies with a prefix, tool records or a private work folder of its ID, and no
    binding record (it never reached "ready"). Reasons are checked in order of importance."""
    from preparation_store import PrivateStore
    item = {"app_id": key, "title": title, "eligible": False, "reason": None, "records": {}, "prefix": False}
    base = ctx.steam / "steamapps/compatdata"
    existing = [name for name in prefix_names(key) if os.path.lexists(base / name)]
    if len(existing) > 1:
        item["reason"] = "several-prefixes"
        return item
    compatdata = base / (existing[0] if existing else key)
    if existing:
        if not _own_directory(compatdata):
            item["reason"] = "not-a-directory"
            return item
        item.update(prefix=True, prefix_name=existing[0])
    work = ctx.home / WORK_ROOT / key
    if os.path.lexists(work) and not _own_directory(work):
        item["reason"] = "work-folder-unexpected"
        return item
    unreadable, installer_ran, identities = 0, False, []
    if os.path.lexists(ctx.management):
        with PrivateStore(ctx.management) as store:
            bindings, unreadable = _records_of(store, BINDINGS, key)
            if bindings:
                verified = False
                for name in bindings:
                    try:
                        verified |= store.read_record(BINDINGS, name)[0].get("status") == "binding-verified"
                    except FAILURES:
                        pass
                item["reason"] = "prepared-before" if verified else "binding-started"
                return item
            for directory in RETIRED:
                names, more = _records_of(store, directory, key)
                unreadable += more
                if names:
                    item["records"][directory] = len(names)
                if directory == "game-prefixes":
                    for name in names:
                        try:
                            identities.append(store.read_record(directory, name)[0].get("prefix_identity"))
                        except FAILURES:
                            unreadable += 1
                if directory == "dependency-installs":
                    for name in names:
                        try:
                            installer = store.read_record(directory, name)[0]["installer"]["status"]
                        except FAILURES:
                            unreadable += 1
                            continue
                        # "running" is saved before the installer is spawned (preparation_dependency_install).
                        installer_ran |= installer not in ("not-started", "staged")
    if unreadable:
        item["reason"] = "records-unreadable"
        return item
    if files is None:
        item["reason"] = "settings-unreadable"
        return item
    tool = _softdenchi_choice(files, key)
    if tool is not None:
        item.update(reason="assigned-to-softdenchi-proton", tool=tool)
        return item
    if item["prefix"]:
        from preparation_game_prefix import prefix_identity
        # The installer record explains SoftDenchi only in the prefix the tool created (not one made again).
        installer_ran = installer_ran and prefix_identity(compatdata) in identities
    if item["prefix"] and not installer_ran:
        # SoftDenchi that no run of the tool's installer explains may have been set up (and authenticated)
        # by hand, also in a prefix the tool initialized or a tool install that stopped before its installer.
        found = _has_softdenchi(compatdata)
        if found is None:
            item["reason"] = "prefix-unreadable"
            return item
        if found:
            item["reason"] = "softdenchi-in-unprepared-prefix"
            return item
    item["eligible"] = True
    return item


def candidates(ctx):
    """Every registration with a prefix, tool records or a work folder of its ID, eligible or with its reason
    (read-only)."""
    import preparation_selection as selection
    from preparation_proton_update import current_files
    from preparation_store import PrivateStore
    _, _, games = selection.registration_catalog(ctx.environment)
    try:
        files = current_files(ctx.steam, ctx.settings)
    except FAILURES:
        files = None
    recorded = set()
    if os.path.lexists(ctx.management):
        with PrivateStore(ctx.management) as store:
            for key in games:
                if any(_records_of(store, directory, key)[0] for directory in RETIRED):
                    recorded.add(key)
    found = []
    for key in sorted(games, key=int):
        if not (any(os.path.lexists(ctx.steam / "steamapps/compatdata" / name) for name in prefix_names(key)) or
                key in recorded or
                os.path.lexists(ctx.home / WORK_ROOT / key)):
            continue
        try:
            found.append(candidate(ctx, key, games[key]["title"], files))
        except FAILURES:
            found.append({"app_id": key, "title": games[key]["title"], "eligible": False, "reason": "settings-unreadable",
                          "records": {}, "prefix": False})
    return found


def _remove_tree(path):
    """Delete a directory tree without following links. A directory of our own missing write or search
    permission is given it once so its entries can go. Returns whether the tree is gone."""
    def onexc(function, failed, error):
        if function in (os.unlink, os.rmdir, os.remove, os.open, os.scandir, os.lstat):
            for target in (failed, os.path.dirname(failed)):
                try:
                    info = os.lstat(target)
                    if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and \
                            (info.st_mode & 0o700) != 0o700:
                        os.chmod(target, stat.S_IMODE(info.st_mode) | 0o700)
                        raise _Retry
                except OSError:
                    continue
        raise error

    class _Retry(Exception):
        pass

    require(not os.path.islink(path) and os.path.isdir(path), "removal target must be a directory")
    for _ in range(64):  # Each retry opened at least one more of our own directories.
        try:
            shutil.rmtree(path, onexc=onexc)
            break
        except _Retry:
            continue
        except OSError:
            return False
    return not os.path.lexists(path)


def _moving_name(redo_id):
    require(type(redo_id) is str and re.fullmatch(r"redo-[0-9a-f]{32}", redo_id) is not None, "redo ID unexpected")
    return REMOVING + redo_id.removeprefix("redo-")


def remove_leftovers(ctx):
    """Prefixes an earlier redo renamed out of view but did not remove (power loss, a failure, a game still
    running, an incomplete removal). Only the hidden folder named after a ``redos`` record's ID is removed,
    under that game's lock and when no game or Wine of that prefix runs. Returns (removed, remaining) names."""
    from preparation_processes import ProcessStopCheck
    from preparation_store import PrivateStore
    parent = safe_path(ctx.steam / "steamapps/compatdata", ctx.steam)
    removed, remaining = [], []
    if not os.path.lexists(ctx.management):
        return removed, remaining
    with PrivateStore(ctx.management) as store:
        try:
            with store.directory((REDOS,)) as fd:
                names = sorted(store._names(fd))
        except FileNotFoundError:
            return removed, remaining
        for name in names:
            if name.startswith("tmp-") or not name.endswith(".json"):
                continue
            try:
                key = store.read_record(REDOS, name)[0]["app_id"]
                require(type(key) is str and key.isdigit(), "redo record unexpected")
            except FAILURES:
                continue
            moving = None
            try:
                with store.locked(hashlib.sha256(str(parent / key).encode()).hexdigest()):
                    record, digest = store.read_record(REDOS, name)
                    moving = _moving_name(record["redo_id"])
                    require(record["app_id"] == key, "redo record changed")
                    if record.get("status") == "stopped" or record.get("prefix") in ("removed", "absent") or \
                            not os.path.lexists(parent / moving):
                        continue
                    path = parent / moving
                    prefix = record.get("prefix_name", key)
                    require(prefix in prefix_names(key), "redo record unexpected")
                    # A game started from the old prefix right before the rename still runs under its old path.
                    if not _own_directory(path) or not ProcessStopCheck(parent / prefix).check()["clear_in_view"] or \
                            not _remove_tree(path):
                        remaining.append(moving)
                        continue
                    record["prefix"] = "removed"
                    record.pop("leftover", None)
                    store.write_record(REDOS, name, record, digest)
                    removed.append(moving)
            except FAILURES:
                if moving is not None and os.path.lexists(parent / moving):
                    remaining.append(moving)
    return removed, remaining


def redo(ctx, key, confirmed_prefix):
    """Under the game's lock: check again, move the prefix out of view, retire the records and the work
    folder, then remove the prefix. ``confirmed_prefix`` is the prefix name the user confirmed (None for
    none); a different one now stops before any write.

    Returns the report; after the first write it always names the redo ID and how far it got."""
    from preparation_processes import ProcessStopCheck
    from preparation_proton_update import current_files
    from preparation_store import PrivateStore
    import preparation_selection as selection
    _, _, games = selection.registration_catalog(ctx.environment)
    require(key in games, "registration missing")
    parent = safe_path(ctx.steam / "steamapps/compatdata", ctx.steam)
    compatdata = parent / key  # The lock of the game's prefix, as every writer takes it (the unsigned ID).
    report = {"mode": MODE, "tool_version": VERSION, "app_id": key, "title": games[key]["title"],
              "preparation_complete": False, "status": "stopped"}
    with PrivateStore(ctx.management, create=True) as store, \
            store.locked(hashlib.sha256(str(compatdata).encode()).hexdigest()):
        again = candidate(ctx, key, games[key]["title"], current_files(ctx.steam, ctx.settings))
        if not again["eligible"]:
            report.update(reason=again["reason"])
            return report
        if again.get("prefix_name") != confirmed_prefix:
            report.update(reason="changed-since-confirmation")
            return report
        redo_id = "redo-" + secrets.token_hex(16)
        moving = parent / _moving_name(redo_id)
        record = {"schema_version": 1, "tool_version": VERSION, "redo_id": redo_id, "app_id": key,
                  "created_ns": time.time_ns(), "status": "running", "retired": {},
                  "prefix": "present" if again["prefix"] else "absent",
                  **({"prefix_name": again["prefix_name"]} if again["prefix"] else {})}
        # Written before the process check, so nothing but the check stands between it and the rename.
        digest = store.write_record(REDOS, redo_id + ".json", record)
        if again["prefix"]:
            prefix = parent / again["prefix_name"]  # The ID or, for a large ID, its signed form.
            if not ProcessStopCheck(prefix).check()["clear_in_view"]:
                record.update(status="stopped", reason="game-or-wine-running")
                try:
                    store.write_record(REDOS, redo_id + ".json", record, digest)
                except FAILURES:
                    pass
                report.update(reason="game-or-wine-running")
                return report
        try:
            # The prefix first, right after the process check: a game started later gets no prefix of the old
            # setup, and an interruption leaves the records and a hidden folder this record names (the next
            # opening of 7 removes the folder, and the records alone can be redone).
            if again["prefix"]:
                os.rename(prefix, moving)
                record["prefix"] = "moved"  # Before the sync: a failed sync still reports the hidden folder.
                _fsync_directory(parent)  # Before the records move: a rolled-back rename would leave them gone.
                digest = store.write_record(REDOS, redo_id + ".json", record, digest)
            for directory in RETIRED:
                names, _ = _records_of(store, directory, key)
                for name in names:
                    store.retire_record(directory, name, redo_id)
                    record["retired"][directory] = record["retired"].get(directory, 0) + 1
            # The private work folder of this ID (its private home, logs and installer inputs) is kept, renamed:
            # a new initialization requires it absent (preparation_game_prefix).
            work = safe_path(ctx.home / WORK_ROOT, ctx.home) / key
            if os.path.lexists(work):
                kept = "retired-" + redo_id.removeprefix("redo-")
                os.rename(work, work.parent / kept)
                _fsync_directory(work.parent)
                record["work"] = kept
            record["records"] = "retired"  # Every record and the work folder of this ID are out of the way.
            digest = store.write_record(REDOS, redo_id + ".json", record, digest)
            if again["prefix"] and not ProcessStopCheck(prefix).check()["clear_in_view"]:
                # Started right before the rename: it keeps running from the hidden folder, removed later.
                record.update(prefix="in-use", leftover=moving.name)
            elif again["prefix"]:
                gone = _remove_tree(moving)
                record["prefix"] = "removed" if gone else "removal-incomplete"
                if not gone:
                    record["leftover"] = moving.name
            record["status"] = "done" if record["prefix"] in ("removed", "absent") else "partial"
        except FAILURES as error:
            record.update(status="partial", error_class=type(error).__name__)
        try:
            store.write_record(REDOS, redo_id + ".json", record, digest)
        except FAILURES:
            pass  # The report below still says how far it got.
    report.update(status=record["status"], redo_id=redo_id, retired=record["retired"], prefix=record["prefix"],
                  work=record.get("work"), records=record.get("records", "kept"), **({"error_class": record["error_class"]} if "error_class" in record else {}),
                  **({"leftover": str(moving)} if record["prefix"] in ("moved", "removal-incomplete", "in-use") else {}))
    return report


def interactive_redo(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                     steam=None, settings=None, home=None, runtime_root=Path("/")):
    import sys

    import preparation_selection as selection
    from preparation_batch import Context, confirm
    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    home = safe_path(home if home is not None else Path.home())
    ctx = Context(directory, renderer, config, input_stream=stream, output_stream=output,
                  environment=os.environ if environment is None else environment,
                  steam=steam if steam is not None else home / ".local/share/Steam",
                  settings=settings if settings is not None else home / ".local/share/droiddeck-compat", home=home,
                  runtime_root=runtime_root)
    text = selection._text
    print("準備をやり直すゲームを選びます。同じ登録のまま、今のprefixを消して、新しく準備し直せるようにします。", file=output)
    try:
        removed, remaining = remove_leftovers(ctx)
        if removed:
            print(f"前回消しきれなかったprefixを消しました（{len(removed)}件）。", file=output)
        if remaining:
            print("前回消しきれなかったprefixが残っています: " + text("、".join(remaining)), file=output)
        found = candidates(ctx)
    except FAILURES as error:
        print("一覧を作れませんでした（" + type(error).__name__ + "）。何も変更していません。", file=output)
        return 1, None
    eligible = [item for item in found if item["eligible"]]
    for item in found:
        if not item["eligible"]:
            print("  やり直さないゲーム: " + text(item["title"]) + f" [ID {item['app_id']}]（" +
                  REASON_TEXT.get(item["reason"], item["reason"]) + "）", file=output)
    if not eligible:
        print("やり直せるゲームはありません。", file=output)
        return 0, None
    for number, item in enumerate(eligible, 1):
        print(f"{number}. " + text(item["title"]) + f" [ID {item['app_id']}]", file=output)
    print("q. 取消", file=output)
    answer = stream.readline(32).strip()
    if not answer.isdigit() or not 1 <= int(answer) <= len(eligible):
        print("取り消しました。", file=output)
        return 0, None
    chosen = eligible[int(answer) - 1]
    compatdata = ctx.steam / "steamapps/compatdata" / chosen.get("prefix_name", chosen["app_id"])
    if chosen["prefix"]:
        print(text(chosen["title"]) + f" [ID {chosen['app_id']}] のprefixを消します: " + text(str(compatdata)), file=output)
        print("  prefixの中のもの（ソフト電池の認証、prefixの中に保存されたもの）は戻せません。ゲームのフォルダーは消しません。",
              file=output)
    else:
        print(text(chosen["title"]) + f" [ID {chosen['app_id']}] にはprefixがありません。ツールの記録だけを片付けます。",
              file=output)
    print("  このゲームのツールの記録は私有の場所の retired に移し、作業用のフォルダーも名前を変えて残します（消しません）。",
          file=output)
    if not confirm(stream, output, "消して、準備をやり直せるようにしますか？"):
        print("取り消しました。", file=output)
        return 0, None
    protected = [ctx.steam, ctx.settings]
    try:
        report = redo(ctx, chosen["app_id"], chosen.get("prefix_name"))
    except FAILURES as error:
        from preparation_dependency_install import describe_error
        report = {"mode": MODE, "tool_version": VERSION, "app_id": chosen["app_id"], "status": "stopped",
                  "preparation_complete": False, **describe_error(error, "redo")}
    if report["status"] == "done":
        print("消しました。prepare.sh を実行すると、このゲームが新しく準備するゲームとして一覧に出ます"
              "（自動で準備できないゲームは、「しないこと」に理由と準備のしかたが出ます）。起動は準備のあとで。", file=output)
    elif report["status"] == "partial" and report.get("prefix") == "in-use":
        print("ツールの記録は移しましたが、prefixを移す直前にゲームかWineが起動していたため、まだ消していません。"
              "残った場所: " + text(report["leftover"]), file=output)
        print("DroidDeckからは見えない名前に変えてあるので、prepare.sh で新しく準備できます。"
              "ゲームを終了してから recovery.sh の7を開くと、残りを消します。", file=output)
    elif report["status"] == "partial" and report.get("records") == "retired" and report.get("leftover"):
        print("ツールの記録は移しましたが、prefixを消しきれませんでした。残った場所: " + text(report["leftover"]), file=output)
        print("DroidDeckからは見えない名前に変えてあるので、prepare.sh で新しく準備できます。"
              "残りは、次に recovery.sh の7を開いたときにもう一度消します。", file=output)
    elif report["status"] == "partial" and report.get("records") == "retired":
        print("ツールの記録は片付けましたが、やり直しの記録を保存できませんでした（" +
              text(str(report.get("error_class"))) + "）。prepare.sh で新しく準備できます。", file=output)
    elif report["status"] == "partial":
        # The records (and the work folder) are not all moved yet: 7 continues with them (1.0.0, 7.5).
        if report.get("leftover"):
            head = "prefixはDroidDeckから見えない名前に移しましたが、ツールの記録を移す途中で止まりました（"
        else:
            head = "ツールの記録を移す途中で止まりました（"
        print(head + text(str(report.get("error_class"))) + "）。" +
              ("prefixはそのままです。" if report.get("prefix") == "present" else "") +
              "もう一度 recovery.sh の7を実行して、このゲームを選び直してください"
              "（残ったフォルダーは、そのときに消します）。", file=output)
    else:
        reason = str(report.get("reason") or report.get("error_class"))
        if reason in REASON_TEXT:
            print("やり直しませんでした（" + text(REASON_TEXT[reason]) + "）。", file=output)
        else:
            print("想定外の状態で止まり、やり直しませんでした（" + text(reason) + "）。何も変更していません。"
                  "結果JSONを置いてください。", file=output)
    try:
        saved, _ = selection.save_selection_result(ctx.directory, ctx.home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。", file=output)
        return 1, None
    print("結果を保存しました: " + text(str(saved)), file=output)
    return 2, str(saved)
