"""Post-trial read-only audit. Never retries, repairs or promotes a trial."""

import os
import stat
from pathlib import Path

from preparation_common import VERSION, checked, require, safe_path, unchanged
from preparation_customization import plan_customizations
from preparation_execution import _aliases, _prefix, inspect_prelaunch_context
from preparation_installation import CAPTURE
from preparation_payload import (
    MAX_MEMBERS,
    inspect_archive,
    inspect_tree_differences,
    verify_tree,
)
from preparation_processes import ProcessStopCheck
from preparation_runtime_context import plan_runtime_environment
from preparation_store import PrivateStore
from preparation_target import pin_registration
from preparation_trial import validate_trial_record


def measure_prefix(root):
    """Count metadata only, without following Wine's drive or user symlinks."""
    root = safe_path(root)
    result = {"entries": 0, "regular_files": 0, "symlinks_not_followed": 0,
              "logical_file_bytes": 0, "allocated_file_bytes": 0, "contents_read": False}
    seen = set()

    def walk(fd):
        before = os.fstat(fd)
        with os.scandir(fd) as children:
            for child in children:
                result["entries"] += 1
                require(result["entries"] <= MAX_MEMBERS, "prefix measurement limit exceeded")
                info = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    result["symlinks_not_followed"] += 1
                elif stat.S_ISREG(info.st_mode):
                    result["regular_files"] += 1
                    identity = (info.st_dev, info.st_ino)
                    if identity not in seen:
                        seen.add(identity)
                        result["logical_file_bytes"] += info.st_size
                        result["allocated_file_bytes"] += info.st_blocks * 512
                elif stat.S_ISDIR(info.st_mode):
                    nested = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        unchanged(info, os.fstat(nested))
                        walk(nested)
                    finally:
                        os.close(nested)
        unchanged(before, os.fstat(fd))

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        walk(fd)
        unchanged(before, safe_path(root).stat())
    finally:
        os.close(fd)
    return result


def audit_trial(*, record, record_sha256, directory, config, renderer, source, games,
                steam, settings, home, environment, runtime_root):
    """Inspect current state; an old journal/report is never execution authority."""
    validate_trial_record(record)
    key = record["app_id"]
    steam, settings, home, directory, runtime_root = map(safe_path, (steam, settings, home, directory, runtime_root))
    result = {"schema_version": 1, "tool_version": VERSION, "mode": "read-only-post-trial-audit",
              "trial_id": record["trial_id"], "app_id": key, "origin_status": record["status"],
              "origin_exit_code": record["exit_code"], "trial_record_sha256": record_sha256,
              "origin_settings_identity_unchanged": record.get("settings_identity_unchanged"),
              "status_promoted": False, "execution_authorized": False, "preparation_complete": False,
              "writes": [], "checks": {}}

    def inspect(name, function):
        try:
            value = checked(name, function)
            result["checks"][name] = {"status": "accepted", **(value if type(value) is dict else {})}
            return value
        except (OSError, ValueError, TypeError, KeyError) as error:
            detail = {"status": "rejected", "check": getattr(error, "preparation_check", name),
                      "error_class": type(error).__name__, "errno": getattr(error, "errno", None)}
            if hasattr(error, "tree_diagnostic"):
                detail["tree_diagnostic"] = error.tree_diagnostic
            result["checks"][name] = detail
            return None

    def registration():
        require(key in games, "trial registration not present")
        exe = safe_path(games[key]["exe"])
        pin = pin_registration(source, key, exe.parent, steam)
        return {"current_registration_pinned": pin.verify(), "same_as_original_digest_proven": False}

    inspect("current-registration", registration)
    compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
    inspect("prefix-aliases", lambda: _aliases(steam, key))
    inspect("prefix-structure", lambda: {"version_sha256": _prefix(compatdata), "registry_values_collected": False})
    inspect("prefix-size", lambda: measure_prefix(compatdata))
    inspect("process-observation", lambda: ProcessStopCheck(compatdata).check())
    result["prelaunch_context"] = inspect_prelaunch_context(steam=steam, settings=settings, home=home,
        environment=environment, runtime_root=runtime_root)

    runtime = inspect("runtime-identity", lambda: plan_runtime_environment(runtime_root, config["runtime_reference"], environment))
    if runtime is not None:
        result["checks"]["runtime-identity"].update(runtime.summary())
    from preparation_selection import _archive
    payload = config["payload"]
    inventory = inspect("source-archive", lambda: inspect_archive(_archive(directory, payload), payload["sha512"], payload["root"], capture=CAPTURE))
    if inventory is not None:
        result["checks"]["source-archive"].update(inventory.summary())
    if inventory is not None and runtime is not None:
        custom = inspect("expected-customization", lambda: plan_customizations(inventory, payload["archive"], payload["mode"],
            runtime_root / "usr/local/bin/steam-compatibility", renderer, label=runtime.label,
            umask=int(runtime.umask, 8), tool_slot=payload.get("tool_slot", "legacy")))
        if custom is not None:
            tool = safe_path(steam / "compatibilitytools.d" / custom.directory, steam)
            result["tool_directory"] = custom.directory
            inspect("strict-tool-identity", lambda: verify_tree(tool, inventory, custom.overlays))
            inspect("tool-differences", lambda: inspect_tree_differences(tool, inventory, custom.overlays))
    else:
        result["dependent_checks_not_run"] = ["expected-customization", "strict-tool-identity", "tool-differences"]
    return result


def interactive_trial_audit(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                            steam=None, settings=None, home=None, runtime_root=Path("/")):
    import sys

    import preparation_selection as selection

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    protected = [steam, settings]
    stage, report = "trial-audit-records", None
    try:
        selection.validate_selection_config(config)
        management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
        with PrivateStore(management) as store:
            records = [item for item in store.inventory()["trials"] if item["status"] != "invalid"]
            require(records, "no private trial records")
            print("既存の試験記録とprefixを読み取り検査します。再実行・修復・記録更新はしません。", file=output)
            for number, item in enumerate(records, 1):
                print(f"{number}. ID {item['app_id']} / {item['status']} / {item['trial_id']}", file=output)
            print("検査する記録の番号（qで取消）: ", end="", file=output, flush=True)
            answer = stream.readline(32).strip()
            if answer == "q":
                return 0, None
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(records), "invalid audit selection")
            name = records[int(answer) - 1]["trial_id"] + ".json"
            record, digest = store.read_record("trials", name)
            source, _, games = selection.registration_catalog(environment)
            protected.extend(Path(game["exe"]).parent for game in games.values())
            stage = "trial-audit-current-state"
            report = audit_trial(record=record, record_sha256=digest, directory=directory, config=config,
                renderer=renderer, source=source, games=games, steam=steam, settings=settings, home=home,
                environment=environment, runtime_root=runtime_root)
            report["trial_record_unchanged"] = store.read_record("trials", name)[1] == digest
        rejected = [name for name, value in report["checks"].items() if value["status"] == "rejected"]
        print("読み取り検査の拒否項目: " + (", ".join(rejected) if rejected else "なし"), file=output)
        differences = report["checks"].get("tool-differences", {})
        if "difference_count" in differences:
            print(f"tool差分 {differences['difference_count']}件（最大128件を記録、追加物の中身は読まない）", file=output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "read-only-post-trial-audit", "stage": stage, "error_class": type(error).__name__,
                  "errno": getattr(error, "errno", None), "status_promoted": False,
                  "execution_authorized": False, "preparation_complete": False, "writes": []}
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。既存の記録と作成物は変更していません。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    return 2, str(saved)
