"""The first screen of 0.31.0: what this bundle would do, run after one confirmation.

Design: Proton update 3 and 6. The list is built read-only (no locks, nothing written),
with the same parts as the status check and menu 1. Running it plans every step again
under that step's own locks; a game whose confirmed items changed is skipped before it
writes anything, and a stop after a game started writing ends the run.
"""

import hashlib
import io
import json
import os
import secrets
import time
from pathlib import Path

from preparation_common import VERSION, Invalid, require, safe_path

MODE = "batch-result"
RUNS = "batch-runs"
OUTCOMES = {"done": "完了", "not-started": "未着手", "skipped": "書き込み前に中止", "partial": "一部適用・要確認"}
SKIP_TEXT = {
    "no-record-prefix-exists": "ツールの記録がなく、prefixがあります",
    "non-ascii-path": "EXEのパスに日本語などが含まれます（まとめての実行では準備しません。個別の操作の1で準備できます）",
    "profile-not-automatic": "自動で選べる作品プロファイルがありません（個別の操作の1で選んでください）",
    "not-superseded-by-this-bundle": "このバンドルが置き換える版ではありません（個別の操作の5で移せます）",
    "returned-from-this-slot": "このProtonから戻してあります（個別の操作の5で移せます）",
    "binding-note-missing": "割り当ての補足の記録が欠けています（個別の操作の5で、理由を確かめてから移せます）",
    "screen-chose-another-proton": "DroidDeckの画面で別のProtonを選択中です",
    "bound-needs-more": "割り当て済みのゲームで、移す以外のことが要ります（個別の操作の1で確かめてください）",
    "several-records": "このゲームの初期化の記録が複数あります",
}


def _text(value):
    import preparation_selection as selection
    return selection._text(value)


class Context:
    """Paths and inputs shared by the list and the run."""

    def __init__(self, directory, renderer, config, *, input_stream, output_stream, environment, steam, settings, home,
                 runtime_root, recipe=None, silent_launch=None):
        self.directory = safe_path(directory)
        self.renderer, self.config = renderer, config
        self.stream, self.output = input_stream, output_stream
        self.environment = environment
        self.home = safe_path(home)
        self.steam, self.settings = safe_path(steam), safe_path(settings)
        self.runtime_root = runtime_root
        self.recipe, self.silent_launch = recipe, silent_launch
        self.management = self.home / ".local/state/droiddeck-prefix-preparation/tool-store"

    def options(self, stream=None, output=None):
        return {"input_stream": self.stream if stream is None else stream,
                "output_stream": self.output if output is None else output, "environment": self.environment,
                "steam": self.steam, "settings": self.settings, "home": self.home, "runtime_root": self.runtime_root}

    def one_pass(self, **extra):
        from preparation_one_pass import interactive_one_pass
        sink = io.StringIO()
        return interactive_one_pass(self.directory, self.renderer, self.config, recipe=self.recipe,
                                    silent_launch=self.silent_launch, **self.options(output=extra.pop("output", sink)),
                                    **extra)


# ---- the list --------------------------------------------------------------------------------

def build(ctx):
    """Read-only list: {"global", "manifest", "items", "skipped", "groups", "consent"} (design 3.1-3.3)."""
    import preparation_selection as selection
    from preparation_assets import exe_identity
    from preparation_one_pass import _game_records
    from preparation_probe import EXE
    from preparation_proton_update import (
        bundle_directory,
        classify,
        current_files,
        history,
        placed_roots,
        target_items,
    )
    from preparation_slot_manifest import state as manifest_state
    from preparation_status import _slot
    from preparation_store import PrivateStore
    config = ctx.config
    bundle = bundle_directory(config)
    result = {"global": {"payload": "unverified", "slot": "unverified", "directory": None}, "manifest": None,
              "items": [], "skipped": [], "groups": {}, "consent": None, "bundle": bundle}
    slot = result["global"]
    try:
        _slot(slot, config, ctx.directory, ctx.renderer, ctx.steam, ctx.environment, ctx.runtime_root)
    except (OSError, ValueError, TypeError, KeyError) as error:
        from preparation_dependency_install import describe_error
        slot["error"] = describe_error(error, "batch-payload-and-slot")
    result["inventory"] = slot.pop("inventory", None)
    result["customization"] = slot.pop("customization", None)
    if slot["payload"] != "verified":
        return result
    if slot["slot"] == "absent":
        result["items"].append({"kind": "place"})
        return result
    if slot["slot"] != "verified":
        return result
    source, _, games = selection.registration_catalog(ctx.environment)
    result["source"] = source
    if os.path.lexists(ctx.management):
        with PrivateStore(ctx.management) as store:
            result["manifest"], _ = manifest_state(store, bundle)
    else:
        result["manifest"] = "missing"
    if result["manifest"] == "missing":
        result["items"].append({"kind": "save-manifest"})
    records, unreadable = _game_records(ctx.management) if os.path.lexists(ctx.management) else ([], 0)
    result["unreadable_records"] = unreadable
    by_key = {}
    for item in records:
        by_key.setdefault(item["app_id"], []).append(item)
    profiles = config["game_preparation"]["profiles"]
    automatic = [item["profile_id"] for item in profiles if item["exe_sha256"] is None]
    moves, resumes, new = [], [], []
    roots, placed = (), {}
    if os.path.lexists(ctx.management):
        with PrivateStore(ctx.management) as store:
            roots, placed = placed_roots(store, ctx.steam, bundle)
    base_dir = ctx.steam / "steamapps/compatdata"
    for key in sorted(games, key=int):
        game = games[key]
        if Path(game["exe"]).name == EXE:
            continue
        entry = {"app_id": key, "title": game["title"]}
        try:
            entry["targets"] = target_items(current_files(ctx.steam, ctx.settings), key)
        except (OSError, Invalid, TypeError, KeyError, ValueError) as error:
            result["skipped"].append({**entry, "reason": "unreadable:" + type(error).__name__})
            continue
        listed = by_key.get(key, [])
        if len(listed) > 1:
            result["skipped"].append({**entry, "reason": "several-records"})
            continue
        if listed:
            try:
                with PrivateStore(ctx.management) as store:
                    items, _ = history(store, key)
                decision = classify(current_files(ctx.steam, ctx.settings), key, bundle, placed, ctx.steam,
                                    tuple(config.get("supersedes", ())), items)
            except (OSError, Invalid, TypeError, KeyError, ValueError) as error:
                result["skipped"].append({**entry, "reason": "unreadable:" + type(error).__name__})
                continue
            verified = any(item["status"] == "binding-verified" for item in items)
            if decision["kind"] in ("move", "align"):
                if not decision["batch"]:
                    result["skipped"].append({**entry, "reason": decision["reason"]})
                    continue
                moves.append({**entry, "kind": decision["kind"], "decision": decision, "trial_id": listed[0]["trial_id"]})
                continue
            if decision["kind"] == "screen-other":
                result["skipped"].append({**entry, "reason": decision["reason"]})
                continue
            if decision["kind"] == "other" and verified:
                result["skipped"].append({**entry, "reason": decision["reason"]})
                continue
            _, plan = ctx.one_pass(select=(key, None), mode="plan")
            if "fixed" not in plan:
                result["skipped"].append({**entry, "reason": plan.get("reason") or plan.get("error_class") or "stopped"})
                continue
            meaningful = [action for action in plan["actions"] if action != "binding" or decision["kind"] != "bound"]
            if decision["kind"] == "bound" and not meaningful:
                continue  # Ready to launch: nothing to do.
            if verified and [action for action in plan["actions"] if action != "binding"]:
                result["skipped"].append({**entry, "reason": "bound-needs-more"})
                continue
            resumes.append({**entry, "kind": "resume", "plan": plan})
            continue
        prefix_exists = os.path.lexists(base_dir / key) or (int(key) >= 2**31 and os.path.lexists(base_dir / str(int(key) - 2**32)))
        if prefix_exists:
            result["groups"].setdefault("no-record-prefix-exists", []).append(entry)
            continue
        if not str(game["exe"]).isascii():
            result["skipped"].append({**entry, "reason": "non-ascii-path"})
            continue
        if len(automatic) != 1:
            result["skipped"].append({**entry, "reason": "profile-not-automatic"})
            continue
        _, plan = ctx.one_pass(select=(key, automatic[0]), mode="plan")
        if "fixed" not in plan:
            result["skipped"].append({**entry, "reason": plan.get("reason") or plan.get("error_class") or "stopped"})
            continue
        try:
            measured = exe_identity(safe_path(game["exe"]))["sha256"]
            entry["also_matches"] = [item["title"] for item in profiles
                                     if item["exe_sha256"] == measured and item["profile_id"] != automatic[0]]
        except (OSError, Invalid, ValueError):
            entry["also_matches"] = []
        new.append({**entry, "kind": "new", "plan": plan})
    for item in moves:
        item.update(roots=[str(root) for root in roots])
    result["items"].extend(moves + resumes + new)
    installs = [item for item in resumes + new if "softdenchi-silent" in item["plan"]["actions"]]
    if installs:
        result["consent"] = {"games": [item["title"] for item in installs], "asset": installs[0]["plan"]["asset"]}
    return result


def show(ctx, listing):
    """Print the list (design 3.1). Returns whether "1" is offered."""
    output, config = ctx.output, ctx.config
    slot = listing["global"]
    print("このバンドルのProton: " + _text(listing["bundle"]) +
          ("（置き済み）" if slot["slot"] == "verified" else "（まだ置かれていません）" if slot["slot"] == "absent" else ""),
          file=output)
    if slot["payload"] != "verified":
        error = slot.get("error") or {}
        print("このバンドルのProtonの配布物を照合できません（" + _text(str(error.get("reason") or error.get("error_class"))) +
              "）。NASのフォルダーの中身を、prepare.shと同じフォルダーへコピーしてください。", file=output)
        return False
    if slot["slot"] not in ("verified", "absent"):
        error = slot.get("error") or {}
        print("置いてある準備用Protonが配布物と一致しません（" + _text(str(error.get("reason") or error.get("error_class"))) +
              "）。", file=output)
        return False
    print(file=output)
    items = listing["items"]
    if items:
        print("すること", file=output)
    for number, item in enumerate(items, 1):
        if item["kind"] == "place":
            print(f"  {number}) 新しいProtonを準備用slotに置く（確認に登録済みのゲームを1つ読むだけ）", file=output)
            print("     置いたあと、移すゲーム・新しく準備するゲームを出して、もう一度確認します。", file=output)
        elif item["kind"] == "save-manifest":
            print(f"  {number}) このProtonの照合情報を保存する（あとでこのProtonへ戻せるようにするため）", file=output)
        elif item["kind"] in ("move", "align"):
            verb = "移す" if item["kind"] == "move" else "DroidDeckの画面で選んだ内容にそろえる"
            print(f"  {number}) " + _text(item["title"]) + f" [ID {item['app_id']}] を " + _text(listing["bundle"]) +
                  f" へ{verb}（今: " + _text(item["decision"]["source"]) + "）", file=output)
            print("     切り替えたあとの最初の起動は、prefixの更新で長くなることがあります。", file=output)
        elif item["kind"] == "resume":
            print(f"  {number}) " + _text(item["title"]) + f" [ID {item['app_id']}] の準備を続きから進める", file=output)
        else:
            profile = next(p for p in config["game_preparation"]["profiles"] if p["profile_id"] == item["plan"]["profile_id"])
            print(f"  {number}) " + _text(item["title"]) + f" [ID {item['app_id']}] を新しく準備する（" +
                  _text(profile["title"]) + "）", file=output)
            print("     準備が終わったら起動して、ソフト電池の認証をしてください。", file=output)
            for title in item.get("also_matches", []):
                print("     このゲームは" + _text(title) + "のプロファイルとも一致します。" + _text(profile["title"]) +
                      "のプロファイルで準備します（ほかのプロファイルは個別の操作の1で選べます）。", file=output)
    if listing["consent"]:
        spec = config["dependency_installation"]["asset"]
        consent = listing["consent"]
        print(file=output)
        print(f"ソフト電池を入れるゲーム: {len(consent['games'])}本（" + _text("、".join(consent["games"])) + "）", file=output)
        print("  インストーラー " + _text(spec["filename"]) + "（SHA-256 " + spec["expected_sha256"][:16] + "…）を画面なしで実行（" +
              " ".join(consent["asset"]["arguments"]) + "）", file=output)
        print("  インストーラーに同梱された使用許諾に同意したうえで導入します。下の1は、その同意を含みます。", file=output)
        print("  使用許諾を画面で読んでから導入したい場合は、qを選んで、個別の操作の1を使ってください。", file=output)
    skipped, groups = listing["skipped"], listing["groups"]
    if skipped or groups:
        print(file=output)
        print("しないこと", file=output)
        for item in skipped:
            print("  - " + _text(item["title"]) + f" [ID {item['app_id']}]: " + _text(SKIP_TEXT.get(item["reason"], item["reason"])),
                  file=output)
        others = groups.get("no-record-prefix-exists", [])
        if others:
            print(f"  - ツールの記録がなく、prefixがあるゲーム（{len(others)}本）: " +
                  _text("、".join(item["title"] for item in others)), file=output)
            print("    ツールは既にあるprefixに書きません。準備したいゲームがあれば、名前を変えて登録し直し、"
                  "起動せずにもう一度 prepare.sh を実行してください。", file=output)
    if not items:
        print("することはありません。", file=output)
    print("DroidDeckに登録したゲームは、起動する前に prepare.sh を実行してください。", file=output)
    return bool(items)


# ---- running -----------------------------------------------------------------------------------

class Journal:
    """Progress of one run in the private store (design 6), written between steps."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.run_id = "batch-" + secrets.token_hex(16)
        self.record = {"schema_version": 1, "kind": "batch-run", "tool_version": VERSION, "run_id": self.run_id,
                       "created_ns": time.time_ns(), "status": "running", "games": []}
        self.hash = None

    def save(self):
        from preparation_store import PrivateStore
        with PrivateStore(self.ctx.management, create=True) as store, \
                store.locked(hashlib.sha256(self.run_id.encode()).hexdigest()):
            self.hash = store.write_record(RUNS, self.run_id + ".json", self.record, self.hash)

    def ids(self, store, app_id, step, ids):
        """Record a step's ID with the locked store of that step, before the step writes (design 6)."""
        found = next((item for item in self.record["games"] if item["app_id"] == app_id), None)
        require(found is not None, "progress record of the game missing")
        found.setdefault("ids", {}).setdefault(step, {}).update(ids)
        self.hash = store.write_record(RUNS, self.run_id + ".json", self.record, self.hash)

    def step(self, app_id, step, outcome=None, **extra):
        found = next((item for item in self.record["games"] if item["app_id"] == app_id and item["step"] == step), None)
        if found is None:
            found = {"app_id": app_id, "step": step, "started_ns": time.time_ns(), "outcome": None}
            self.record["games"].append(found)
        found.update(outcome=outcome, **extra)
        self.save()


ID_RECORDS = {"trial_id": "game-prefixes", "record_id": "prefix-dlls", "install_id": "dependency-installs",
              "binding_id": "bindings"}


def _record_or_none(store, directory, name):
    """A private record, None when it does not exist, {} when it exists but cannot be read."""
    try:
        found, _ = store.read_record(directory, name)
        return found if type(found) is dict else {}
    except FileNotFoundError:
        return None
    except Invalid as error:
        return None if str(error) == "managed record missing" else {}
    except (OSError, ValueError):
        return {}


def reconcile(store, record):
    """Outcome of each game of an interrupted run, from its journaled IDs and the private records (design 6).

    "done" when the game's binding record is verified; "partial" when any record (or the
    supplementary note of a binding) of a journaled ID exists; "skipped" when the game
    started but nothing with its IDs was written; journaled outcomes are kept as they are.
    """
    from preparation_proton_update import NOTES
    result = {}
    for item in record.get("games", []):
        if item.get("outcome") in OUTCOMES:
            result[item["app_id"]] = item["outcome"]
            continue
        evidence, done = False, False
        for ids in item.get("ids", {}).values():
            for name, value in ids.items():
                directory = ID_RECORDS.get(name)
                if directory is None or type(value) is not str:
                    continue
                found = _record_or_none(store, directory, value + ".json")
                if found is not None:
                    evidence = True
                    done = done or (name == "binding_id" and found.get("status") == "binding-verified")
                elif name == "binding_id" and _record_or_none(store, NOTES, value + ".json") is not None:
                    evidence = True
        result[item["app_id"]] = "done" if done else "partial" if evidence else "skipped"
    return result


def close_runs(ctx, records):
    """Mark interrupted runs as reviewed once a new run starts (the operator has seen them)."""
    from preparation_store import PrivateStore
    for record in records:
        with PrivateStore(ctx.management) as store, \
                store.locked(hashlib.sha256(record["run_id"].encode()).hexdigest()):
            current, digest = store.read_record(RUNS, record["run_id"] + ".json")
            current["status"] = "reviewed"
            store.write_record(RUNS, record["run_id"] + ".json", current, digest)


def interrupted_runs(ctx):
    """Earlier runs that did not finish (shown on the first screen)."""
    from preparation_store import PrivateStore
    found = []
    if not os.path.lexists(ctx.management):
        return found
    with PrivateStore(ctx.management) as store:
        try:
            with store.directory((RUNS,)) as fd:
                names = sorted(store._names(fd))
        except FileNotFoundError:
            return found
        for name in names:
            if name.startswith("tmp-"):
                continue
            try:
                record, _ = store.read_record(RUNS, name)
            except (OSError, Invalid, ValueError):
                continue
            if record.get("status") == "running":
                found.append(record)
    return found


def _write_private(ctx, protected, name, report):
    """Atomic private copy of the result, rewritten after each step (design 6)."""
    import preparation_selection as selection
    folder = selection._private_report_directory(ctx.home, protected)
    temporary = folder / (name + "." + secrets.token_hex(8) + ".tmp")
    raw = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, folder / name)
    return folder / name


def _save_manifest(ctx, listing):
    from preparation_payload import verify_fex_runtime_tree
    from preparation_slot_manifest import build as build_manifest
    from preparation_slot_manifest import save
    from preparation_store import PrivateStore
    bundle = listing["bundle"]
    tool = safe_path(ctx.steam / "compatibilitytools.d" / bundle, ctx.steam)
    inventory, custom = listing["inventory"], listing["customization"]
    with PrivateStore(ctx.management, create=True) as store, \
            store.locked(hashlib.sha256(str(tool).encode()).hexdigest()):
        verify_fex_runtime_tree(tool, inventory, custom.overlays)
        version = inventory.captured["version"].decode("utf-8").strip()
        return save(store, bundle, build_manifest(bundle, bundle.replace(" ", "-", 1), inventory, custom.overlays, version))


def _run_move(ctx, item, listing, journal):
    """Move or align one game (design 4.2-4.6) with the code of operation 5; returns (outcome, detail)."""
    import preparation_selection as selection
    from preparation_game_prefix import RECORDS
    from preparation_processes import ProcessStopCheck
    from preparation_proton_update import apply_move, plan_move
    from preparation_store import PrivateStore
    key, decision = item["app_id"], item["decision"]
    started = False
    try:
        with PrivateStore(ctx.management) as store:
            record, digest = store.read_record(RECORDS, item["trial_id"] + ".json")
        source, _, _ = selection.registration_catalog(ctx.environment)
        stop = ProcessStopCheck(safe_path(ctx.steam / "steamapps/compatdata" / key, ctx.steam))
        plan, refresh, blockers = plan_move(
            record=record, digest=digest, decision=decision, roots=tuple(Path(root) for root in item["roots"]),
            config=ctx.config, directory=ctx.directory, renderer=ctx.renderer, steam=ctx.steam, settings=ctx.settings,
            home=ctx.home, environment=ctx.environment, runtime_root=ctx.runtime_root, source=source, stop=stop)
        if blockers:
            return "skipped", {"blockers": blockers}
        lock = hashlib.sha256(str(plan.base.compatdata).encode()).hexdigest()
        with PrivateStore(ctx.management) as store, store.locked(lock):
            def before(run_id):
                nonlocal started
                journal.ids(store, key, "binding", {"binding_id": run_id})
                started = True
            result = apply_move(store, plan, refresh, stop, key=key, decision=decision, config=ctx.config,
                                steam=ctx.steam, targets=item["targets"], before=before)
        return ("done" if result["status"] == "binding-verified" else "partial"), {"binding": result}
    except (OSError, ValueError, TypeError, KeyError) as error:
        from preparation_dependency_install import describe_error
        return ("partial" if started else "skipped"), {"error": describe_error(error, "batch-move")}


def _run_one_pass(ctx, item, journal):
    def noted(store, step, ids):
        journal.ids(store, item["app_id"], step, ids)
    _, report = ctx.one_pass(select=(item["app_id"], item["plan"]["profile_id"] if item["kind"] == "new" else None),
                             mode="run", expected=item["plan"], output=ctx.output, journal=noted)
    if report.get("status") == "ready-to-launch":
        return "done", {"report": report}
    wrote = bool(report.get("writes_may_exist")) or any(step.get("record") or step.get("result") or step.get("step") == "initialize"
                                                        for step in report.get("steps", []))
    return ("partial" if wrote else "skipped"), {"report": report}


def _targets_now(ctx, key):
    from preparation_proton_update import current_files, target_items
    return target_items(current_files(ctx.steam, ctx.settings), key)


def run(ctx, listing, protected):
    """Run the confirmed items in order (design 6). Returns the result report.

    Before a game starts, its items in the three files must be the confirmed ones (3.5);
    other games' entries may have changed (earlier steps write them). The result is written
    after every step: privately, and to the shared copy once it exists.
    """
    journal = Journal(ctx)
    report = {"mode": MODE, "tool_version": VERSION, "run_id": journal.run_id, "bundle": listing["bundle"],
              "items": [{"kind": item["kind"], "app_id": item.get("app_id"), "outcome": "not-started"}
                        for item in listing["items"]],
              "skipped_before": listing["skipped"], "preparation_complete": False}
    name = journal.run_id + ".json"
    journal.save()
    shared = None
    stopped = False
    for index, item in enumerate(listing["items"]):
        entry = report["items"][index]
        if stopped:
            break
        app = item.get("app_id") or "-"
        journal.step(app, item["kind"], "running")
        if item["kind"] == "save-manifest":
            state = _save_manifest(ctx, listing)
            entry.update(outcome="done" if state in ("created", "same") else "skipped", state=state)
        else:
            try:
                same = _targets_now(ctx, item["app_id"]) == item["targets"]
            except (OSError, Invalid, TypeError, KeyError, ValueError):
                same = False
            if not same:
                entry.update(outcome="skipped", reason="confirmed-target-items-changed")
            elif item["kind"] in ("move", "align"):
                outcome, detail = _run_move(ctx, item, listing, journal)
                entry.update(outcome=outcome, **detail)
            else:
                outcome, detail = _run_one_pass(ctx, item, journal)
                entry.update(outcome=outcome, status=detail["report"].get("status"),
                             reason=detail["report"].get("reason"), stage=detail["report"].get("stage"))
        journal.step(app, item["kind"], entry["outcome"])
        _write_private(ctx, protected, name, report)
        shared = _update_shared(ctx, protected, report, shared)
        if entry["outcome"] == "partial":
            stopped = True  # A stop after writing ends the run (design 6).
    journal.record["status"] = "finished"
    journal.save()
    report["shared_result"] = None if shared is None else str(shared)
    return report


def _update_shared(ctx, protected, report, path):
    """Create the shared result once, then replace it atomically after each step (design 6)."""
    import preparation_selection as selection
    try:
        if path is None:
            saved, _ = selection.save_selection_result(ctx.directory, ctx.home, report, protected)
            return Path(saved)
        raw = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
        temporary = path.parent / (path.name + "." + secrets.token_hex(8) + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        return path
    except (OSError, ValueError):
        return path  # The private copy is kept either way.


def show_outcomes(ctx, report, listing):
    output = ctx.output
    print(file=output)
    print("結果", file=output)
    for item, entry in zip(listing["items"], report["items"], strict=True):
        label = {"place": "Protonを置く", "save-manifest": "照合情報の保存"}.get(item["kind"]) or \
            (_text(item["title"]) + f" [ID {item['app_id']}]")
        reason = entry.get("reason") or (entry.get("error") or {}).get("reason") or \
            ",".join(entry.get("blockers", []))
        print("  " + label + ": " + OUTCOMES[entry["outcome"]] + (f"（{_text(str(reason))}）" if reason else ""), file=output)
        if entry["outcome"] == "partial":
            print("    再実行では飛ばされます。設定のバックアップは私有記録（backups/binding-…）にあります。"
                  "個別の操作の2（状態の確認）で確かめてください。", file=output)
    ready = [item for item, entry in zip(listing["items"], report["items"], strict=True)
             if entry["outcome"] == "done" and item["kind"] in ("move", "align", "new", "resume")]
    if ready:
        print("起動してよいゲーム: " + _text("、".join(item["title"] for item in ready)), file=output)
        if any(item["kind"] == "new" for item in ready):
            print("新しく準備したゲームは、起動したらソフト電池の認証をしてください。", file=output)
        if any(item["kind"] in ("move", "align") for item in ready):
            print("移したゲームは、切り替えたあとの最初の起動が長くなることがあります。", file=output)


def place_automatically(ctx, preferred=()):
    """Place the bundle slot with an automatically chosen confirmation registration (design 3.6)."""
    import preparation_selection as selection
    from preparation_installation import plan_installation
    from preparation_static_placement import (
        _confirmation_candidates,
        _same_plan,
        apply_static_placement,
        plan_confirmed_placement,
    )
    from preparation_store import PrivateStore
    from preparation_target import pin_registration
    config = ctx.config
    source, _, games = selection.registration_catalog(ctx.environment)
    selectable, excluded = _confirmation_candidates(games, ctx.steam, ctx.settings, ctx.management)
    order = sorted(selectable, key=lambda key: (key not in preferred, int(key)))
    skipped = []
    payload = config["payload"]
    archive = selection._archive(ctx.directory, payload)
    for key in order:
        exe = safe_path(games[key]["exe"])
        try:
            pin_registration(source, key, exe.parent, ctx.steam)
        except (OSError, ValueError) as error:
            skipped.append({"app_id": key, "reason": str(error) if isinstance(error, ValueError) else type(error).__name__})
            continue

        def refresh(key=key, exe=exe):
            installation = plan_installation(archive=archive, sha512=payload["sha512"], archive_root=payload["root"],
                mode=payload["mode"], runtime_root=ctx.runtime_root, runtime_audit=config["runtime_reference"],
                registrations=source, registration_id=key, exe_root=exe.parent, steam=ctx.steam, renderer=ctx.renderer,
                parent_environment=ctx.environment, tool_slot="preparation", archive_from_folder=True)
            return plan_confirmed_placement(installation, config["placement_review"], ctx.management, ctx.settings)
        try:
            plan = refresh()
        except (OSError, ValueError) as error:
            if getattr(error, "preparation_check", None) == "target-registration-exe":
                skipped.append({"app_id": key, "reason": str(error) if isinstance(error, ValueError) else type(error).__name__})
                continue
            raise  # Common to every registration (payload, runtime, capacity): stop once.
        compatdata = safe_path(ctx.steam / "steamapps/compatdata" / key, ctx.steam)
        with PrivateStore(ctx.management, create=True) as store, \
                store.locked(hashlib.sha256(str(compatdata).encode()).hexdigest()):
            require(_same_plan(refresh(), plan), "static placement plan changed")
            result = apply_static_placement(plan, refresh, store, plan.digest)
        return {"confirmation": key, "skipped_candidates": skipped, "excluded": [list(item) for item in excluded],
                "result": result}
    raise Invalid("no registered game can confirm the placement")


def interactive_batch(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                      steam=None, settings=None, home=None, runtime_root=Path("/"), recipe=None, silent_launch=None):
    """The first screen (design 3.1). "1" runs everything listed; 2 is the status; 3 the individual operations."""
    import sys

    from preparation_dependency_install import describe_error
    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    ctx = Context(directory, renderer, config, input_stream=stream, output_stream=output, environment=environment,
                  steam=steam if steam is not None else home / ".local/share/Steam",
                  settings=settings if settings is not None else home / ".local/share/droiddeck-compat", home=home,
                  runtime_root=runtime_root, recipe=recipe, silent_launch=silent_launch)
    protected = [ctx.steam, ctx.settings]
    listing, offered, earlier = None, False, []
    try:
        earlier = interrupted_runs(ctx)
        if earlier:
            from preparation_store import PrivateStore
            with PrivateStore(ctx.management) as store:
                for record in earlier:
                    outcomes = reconcile(store, record)
                    print("前回のまとめての実行が途中で終わっています（" + record["run_id"][:14] + "…）:", file=output)
                    for app, outcome in outcomes.items():
                        print("  ID " + _text(str(app)) + ": " + OUTCOMES[outcome] +
                              ("（個別の操作の2（状態の確認）で確かめてください）" if outcome == "partial" else ""), file=output)
        print("配布物・準備用Proton・登録済みのゲームを照合しています（何も変更しません）。", file=output, flush=True)
        listing = build(ctx)
        offered = show(ctx, listing)
    except (OSError, ValueError, TypeError, KeyError) as error:
        detail = describe_error(error, "batch-list")
        print("一覧を作れませんでした（" + _text(str(detail.get("reason") or detail.get("error_class"))) + "）。", file=output)
    print(file=output)
    if offered:
        print("1. すべて実行する", file=output)
    print("2. ゲームの状態を詳しく見る（何も変更しません）", file=output)
    print("3. 個別の操作（新しいゲーム・Protonを置く・ゲームを移す・前のProtonへ戻す・詳細メニュー）", file=output)
    print("q. 取消", file=output)
    answer = stream.readline(32).strip()
    if answer == "2":
        from preparation_status import interactive_status
        return interactive_status(directory, renderer, config, **ctx.options(), recipe=recipe, silent_launch=silent_launch)
    if answer == "3":
        return individual(directory, renderer, config, ctx)
    if answer != "1" or not offered:
        print("取り消しました。", file=output)
        return 0, None
    report = {"mode": MODE, "tool_version": VERSION, "preparation_complete": False}
    try:
        close_runs(ctx, earlier)
        if listing["items"] and listing["items"][0]["kind"] == "place":
            print("新しいProtonを置いています。", file=output, flush=True)
            report["placement"] = place_automatically(ctx, _assigned_to_slots(ctx))
            print("新しいProtonを置きました。移すゲーム・新しく準備するゲームを確かめています。", file=output, flush=True)
            listing = build(ctx)
            if not show(ctx, listing):
                return _finish(ctx, protected, report)
            print("この内容で実行する場合は1、取消はq: ", end="", file=output, flush=True)
            if stream.readline(32).strip() != "1":
                print("取り消しました（新しいProtonは置いたままです）。", file=output)
                return _finish(ctx, protected, report)
        print("実行しています。操作が終わるまで、ゲームを起動しないでください。", file=output, flush=True)
        report.update(run(ctx, listing, protected))
        show_outcomes(ctx, report, listing)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report.update(status="stopped", **describe_error(error, "batch-run"))
        print("停止: " + _text(str(report.get("reason") or report.get("error_class"))), file=output)
    return _finish(ctx, protected, report)


def _assigned_to_slots(ctx):
    """Registrations assigned to a preparation slot: preferred confirmation registrations (design 3.6)."""
    import preparation_selection as selection
    from preparation_proton_update import current_files, current_selection
    preferred = set()
    try:
        _, _, games = selection.registration_catalog(ctx.environment)
        files = current_files(ctx.steam, ctx.settings)
        for key in games:
            name = current_selection(files, key)["config"]
            if name is not None and name.startswith("SoftDenchi-Prep-Proton-"):
                preferred.add(key)
    except (OSError, Invalid, TypeError, KeyError, ValueError):
        pass
    return preferred


def _finish(ctx, protected, report):
    import preparation_selection as selection
    if report.get("shared_result"):
        path = _update_shared(ctx, protected, report, Path(report["shared_result"]))
        print("結果を保存しました: " + _text(str(path)), file=ctx.output)
        return 2, str(path)
    try:
        saved, _ = selection.save_selection_result(ctx.directory, ctx.home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録は保持しています。", file=ctx.output)
        return 1, None
    print("結果を保存しました: " + _text(str(saved)), file=ctx.output)
    return 2, str(saved)


def individual(directory, renderer, config, ctx):
    """Individual operations: 0.30.0's entries 1-4 with the same numbers, then 5 and 6 (design 3.7)."""
    output, stream = ctx.output, ctx.stream
    print("1. 新しいゲームを準備（初期化→DLL→ソフト電池→割り当て。途中からの再開も可）", file=output)
    print("2. ゲームの状態を確認（何も変更しません）", file=output)
    print("3. 新しいProtonを準備用slotに置く（起動しない）", file=output)
    print("4. 詳細メニュー（検証用・手動の操作）", file=output)
    print("5. ゲームを移す（このバンドルの準備用Protonへ）", file=output)
    print("6. 前のProtonへ戻す（別の準備用Protonへ）", file=output)
    print("q. 取消", file=output)
    answer = stream.readline(32).strip()
    options = ctx.options()
    if answer == "1":
        from preparation_one_pass import interactive_one_pass
        return interactive_one_pass(directory, renderer, config, **options)
    if answer == "2":
        from preparation_status import interactive_status
        return interactive_status(directory, renderer, config, **options)
    if answer == "3":
        from preparation_static_placement import interactive_confirmed_placement
        return interactive_confirmed_placement(directory, renderer, config, **options)
    if answer == "4":
        from preparation_probe import detailed_menu
        return detailed_menu(directory, renderer, config, **options)
    if answer == "5":
        from preparation_proton_update import interactive_move
        return interactive_move(directory, renderer, config, **options)
    if answer == "6":
        from preparation_proton_update import interactive_revert
        return interactive_revert(directory, renderer, config, **options)
    print("取り消しました。", file=output)
    return 0, None
