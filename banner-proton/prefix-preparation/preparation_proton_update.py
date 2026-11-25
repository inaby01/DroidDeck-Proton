"""Moving prepared games between preparation slots (design: Proton update 4.2-4.6, 4.8).

Read-only decisions from the three DroidDeck files of one registration, the binding
history with its supplementary records (``binding-notes``), the slots this tool placed
and the bundle's list of slots it replaces. Writing goes through the guarded binding
writer; this module only decides and keeps the supplementary records.
"""

import copy
import hashlib
import re
import time

from preparation_binding import (
    FILES,
    STEAM_PATH,
    _choice,
    _games_document,
    _json,
    registered_tool,
    validate_binding_record,
)
from preparation_common import MAX_JSON, VERSION, Invalid, app_id, fields, require
from preparation_slot_manifest import SLOT_PREFIX, placed_slots, slot_name
from preparation_vdf import Document

NOTES = "binding-notes"
NOTE_KINDS = ("apply", "move", "revert")
CACHES = "slot-caches"
PYCACHE = "__pycache__"
MAX_CACHES = 4096
FIRST_NOTES_VERSION = (0, 31, 0)
PREFIX_VERSION = re.compile(rb"^CURRENT_PREFIX_VERSION=\"([0-9.-]{1,32})\"$", re.MULTILINE)


def _version(text):
    match = re.fullmatch(r"([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})", text) if type(text) is str else None
    return None if match is None else tuple(int(part) for part in match.groups())


def tool_id_of(directory):
    """The tool ID (``config.vdf`` name) of a preparation slot directory."""
    return slot_name(directory).replace(" ", "-", 1)


def points_to(choice, directory, tool_id):
    """Whether a selection entry assigns ``directory`` (design 4.6: ``valve``, ``dir``, ``name``)."""
    return (type(choice) is dict and choice.get("valve") is False and choice.get("dir") == directory and
            choice.get("name", tool_id) == tool_id)


def current_selection(before, key):
    """The target's entries in the three files from a binding plan's ``before`` bytes.

    Returns {"games": choice | None, "applied": choice | None, "config": tool name | None}.
    """
    key = app_id(key)
    games = _games_document(before["games"])["games"].get(key)
    state = _json(before["state"], {})
    applied = state.get("games_applied")
    applied = applied.get(key) if type(applied) is dict else None
    _choice(games)
    _choice(applied)
    require(before["config"] is not None, "existing config required")
    node = Document(before["config"], value_limit=MAX_JSON).node(STEAM_PATH).value
    require(type(node) is dict, "invalid Steam block")
    mapping = node.get("CompatToolMapping")
    entry = mapping.value.get(key) if mapping is not None and type(mapping.value) is dict else None
    name = entry.value.get("name") if entry is not None and type(entry.value) is dict else None
    return {"games": games, "applied": applied, "config": None if name is None else str(name.value)}


def current_files(steam, settings):
    """The three files as bytes, without needing any tool to be registered (design 4.8)."""
    from preparation_binding import _raw
    from preparation_common import safe_path
    steam, settings = safe_path(steam), safe_path(settings)
    return {"config": _raw(safe_path(steam / "config/config.vdf", steam)),
            "games": _raw(safe_path(settings / "games.json", settings)),
            "state": _raw(safe_path(settings / "state.json", settings))}


def bound_files(before, key, directory, tool):
    """Which of the three files already assign ``directory`` (``valve``, ``dir`` and the tool ID; design 4.6).

    A ``name`` the DroidDeck screen wrote counts when it is the tool ID; byte equality with
    the binding plan is not required.
    """
    current = current_selection(before, key)
    found = []
    if points_to(current["games"], directory, tool):
        found.append("games")
    if current["config"] == tool:
        found.append("config")
    # state.json also holds what the binding writes besides games_applied: the target is picked,
    # not in the automatic history and not a native choice (plan_binding).
    state = _json(before["state"], {})
    auto, picked, native = state.get("auto"), state.get("picked", []), state.get("native_choices", [])
    key = app_id(key)
    if points_to(current["applied"], directory, tool) and type(picked) is list and key in picked and \
            not (type(auto) is dict and key in auto) and not (type(native) is list and key in native):
        found.append("state")
    return found


def _mapping_entry(raw, key):
    """The target's whole ``CompatToolMapping`` entry (``name``, ``config``, ``priority``...), unpacked."""
    node = Document(raw, value_limit=MAX_JSON).node(STEAM_PATH).value
    mapping = node.get("CompatToolMapping") if type(node) is dict else None
    entry = mapping.value.get(key) if mapping is not None and type(mapping.value) is dict else None

    def unpack(item):
        return {name: unpack(value) for name, value in item.value.items()} if type(item.value) is dict else item.value
    return None if entry is None else unpack(entry)


def target_items(files, key):
    """The target's entries in the three files that a binding writes (design 3.5 pin).

    The selection entries, the whole ``config.vdf`` mapping entry, and the target's part of
    ``state.json``'s ``auto``, ``picked`` and ``native_choices`` (``plan_binding`` changes
    them). Other games' entries are not part of it.
    """
    key = app_id(key)
    current = current_selection(files, key)
    state = _json(files["state"], {})
    auto = state.get("auto")
    return {**current, "config_entry": _mapping_entry(files["config"], key),
            "auto": auto.get(key) if type(auto) is dict else None,
            "picked": key in state.get("picked", []) if type(state.get("picked", [])) is list else None,
            "native_choice": key in state.get("native_choices", []) if type(state.get("native_choices", [])) is list
            else None}


# ---- supplementary records -------------------------------------------------------------

def file_hashes(plan):
    """Per-file before/after evidence of a binding plan, saved before the first replacement (6)."""
    result = {}
    for name in FILES:
        before, after = plan.before[name], plan.after[name]
        result[name] = {"present_before": before is not None,
                        "before_sha256": None if before is None else hashlib.sha256(before).hexdigest(),
                        "after_sha256": hashlib.sha256(after).hexdigest(), "changed": before != after}
    return result


def note(binding_id, key, kind, directory, previous, plan, cache_move=None):
    """A new supplementary record as written (write-time checks, design 4.3)."""
    require(kind in NOTE_KINDS, "unknown binding note kind")
    record = {"schema_version": 1, "kind": "binding-note", "tool_version": VERSION, "binding_id": binding_id,
              "app_id": app_id(key), "created_ns": time.time_ns(), "note_kind": kind, "directory": slot_name(directory),
              "previous_directory": None if previous is None else slot_name(previous), "files": file_hashes(plan),
              "cache_move": cache_move}
    validate_note(record)
    require(kind != "apply" or previous is None, "a new assignment has no previous slot")
    require(kind == "apply" or (previous is not None and previous != directory), "a move or revert needs another slot")
    return record


def validate_note(record):
    """Read-time shape (does not compare with the reader's own slot, design 4.3)."""
    fields(record, ("schema_version", "kind", "tool_version", "binding_id", "app_id", "created_ns", "note_kind",
                    "directory", "previous_directory", "files", "cache_move"))
    require(record["schema_version"] == 1 and record["kind"] == "binding-note", "unknown binding note")
    require(type(record["tool_version"]) is str and 0 < len(record["tool_version"]) <= 64, "invalid note writer")
    require(type(record["binding_id"]) is str and record["binding_id"].startswith("binding-") and
            len(record["binding_id"]) == 40, "invalid binding ID")
    require(app_id(record["app_id"]) == record["app_id"], "invalid app ID")
    require(type(record["created_ns"]) is int and record["created_ns"] > 0, "invalid note time")
    require(record["note_kind"] in NOTE_KINDS, "unknown binding note kind")
    slot_name(record["directory"])
    if record["note_kind"] == "apply":
        require(record["previous_directory"] is None, "a new assignment has no previous slot")
    else:
        require(record["previous_directory"] is not None and slot_name(record["previous_directory"]) != record["directory"],
                "a move or revert needs another slot")
    files = record["files"]
    fields(files, FILES)
    for item in files.values():
        fields(item, ("present_before", "before_sha256", "after_sha256", "changed"))
        require(type(item["present_before"]) is bool and type(item["changed"]) is bool, "invalid note file")
        require(_sha256(item["after_sha256"]) and (item["before_sha256"] is None if not item["present_before"]
                                                   else _sha256(item["before_sha256"])), "invalid note file hash")
    move = record["cache_move"]
    require(move is None or record["note_kind"] == "revert", "only a revert moves caches")
    if move is not None:
        fields(move, ("planned", "moved", "destination"))
        require(move["destination"] == CACHES + "/" + record["binding_id"], "invalid cache move destination")
        require(type(move["planned"]) is list and len(move["planned"]) <= MAX_CACHES and type(move["moved"]) is list and
                len(move["moved"]) <= len(move["planned"]), "invalid cache move")
        for item in move["planned"]:
            fields(item, ("relative", "device", "inode", "files"))
            _cache_parts(item["relative"])
            require(type(item["device"]) is int and type(item["inode"]) is int and type(item["files"]) is dict and
                    all(type(name) is str and _sha256(digest) for name, digest in item["files"].items()),
                    "invalid planned cache")
        for number, item in enumerate(move["moved"], 1):
            fields(item, ("relative", "name"))
            require(item["relative"] == move["planned"][number - 1]["relative"] and item["name"] == f"c{number:04d}",
                    "invalid moved cache")
    return record


def _sha256(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def write_note(store, record):
    """Write a new supplementary record (under the held store lock). Returns its hash."""
    validate_note(record)
    return store.write_record(NOTES, record["binding_id"] + ".json", record)


def history(store, key):
    """Binding history of one registration with its supplementary records (design 4.3 table).

    Each item: {"binding_id", "status", "completed_files", "tool_version", "note": record | None,
    "note_state": "valid" | "old" | "missing"}. Also returns the orphan notes (no binding
    record: interrupted before the record was written) and whether an unreadable binding
    record may belong to this registration (it stops, like the current history reader).
    """
    key = app_id(key)
    items, orphans = [], []
    bindings, notes = {}, {}
    try:
        with store.directory(("bindings",)) as fd:
            names = sorted(store._names(fd))
    except FileNotFoundError:
        names = []
    for name in names:
        if name.startswith("tmp-"):
            continue
        record, _ = store.read_record("bindings", name)  # Unreadable stops (it could hide a partial binding).
        validate_binding_record(record, any_version=True)
        if record["app_id"] == key:
            bindings[record["binding_id"]] = record
    try:
        with store.directory((NOTES,)) as fd:
            note_names = sorted(store._names(fd))
    except FileNotFoundError:
        note_names = []
    for name in note_names:
        if name.startswith("tmp-"):
            continue
        try:
            record, _ = store.read_record(NOTES, name)
            validate_note(record)
        except (OSError, Invalid, TypeError, KeyError, ValueError):
            continue  # A broken note is the same as a missing one for the binding it belongs to.
        if record["app_id"] == key and name == record["binding_id"] + ".json":
            notes[record["binding_id"]] = record
    for binding_id, record in sorted(bindings.items()):
        found = notes.get(binding_id)
        version = _version(record["tool_version"])
        if found is not None and found["app_id"] == record["app_id"]:
            state = "valid"
        elif version is not None and version < FIRST_NOTES_VERSION:
            state = "old"
        else:
            state, found = "missing", None
        items.append({"binding_id": binding_id, "status": record["status"],
                      "completed_files": list(record["completed_files"]), "tool_version": record["tool_version"],
                      "note": found, "note_state": state})
    orphans = [record for binding_id, record in sorted(notes.items()) if binding_id not in bindings]
    return items, orphans


def history_state(items):
    """(usable, reason) for moving or reverting with this history (design 4.2, 4.3)."""
    relevant = [item for item in items if not (item["status"] == "binding-failed" and not item["completed_files"])]
    if any(item["status"] == "binding-running" for item in relevant):
        return False, "binding-running-record"
    if any(item["status"] == "binding-failed" for item in relevant):
        return False, "binding-failed-after-writing"
    if not any(item["status"] == "binding-verified" for item in relevant):
        return False, "no-verified-binding"
    return True, None


def touched(items, directory):
    """Whether a valid note shows this slot was assigned before (design 4.2 exclusion)."""
    return any(item["note_state"] == "valid" and item["status"] == "binding-verified" and
               directory in (item["note"]["directory"], item["note"]["previous_directory"]) for item in items)


def notes_missing(items):
    return any(item["note_state"] == "missing" and item["status"] == "binding-verified" for item in items)


# ---- prefix version ----------------------------------------------------------------------

def proton_prefix_version(raw):
    """``CURRENT_PREFIX_VERSION`` of a ``proton`` script (exactly one assignment line, 4.5)."""
    found = PREFIX_VERSION.findall(raw) if type(raw) is bytes else []
    require(len(found) == 1, "Proton prefix version not found exactly once")
    return found[0].decode("ascii")


def prefix_version_matches(proton_raw, version_file_raw):
    try:
        return proton_prefix_version(proton_raw) == version_file_raw.decode("ascii").strip()
    except (Invalid, UnicodeError, AttributeError):
        return False


# ---- decisions ---------------------------------------------------------------------------

def classify(before, key, bundle_directory, placed, steam, superseded, items):
    """Where the target stands and what a move would do (design 4.2, 4.6). Read-only.

    Returns {"kind": ..., "source": slot | None, "reason": text | None, "batch": bool, "choice": dict | None}:
    - "bound": all three files assign the bundle slot.
    - "move": all three files consistently assign another slot this tool placed (4.2).
    - "align": the operator chose the bundle slot on the DroidDeck screen only (4.6, observed direction).
    - "screen-other": the reverse direction (the screen chose another slot); never written.
    - "other": anything else this tool does not move (Steam default, unknown tool, mixed files).
    ``batch`` says whether the batch run may do it; "choice" is the selection to write for "align".
    ``steam`` is used for ``registered_tool`` of the source slot.
    """
    bundle_tool = tool_id_of(bundle_directory)
    current = current_selection(before, key)
    games, applied, config = current["games"], current["applied"], current["config"]

    def result(kind, source=None, reason=None, batch=False, choice=None):
        return {"kind": kind, "source": source, "reason": reason, "batch": batch, "choice": choice}

    if points_to(games, bundle_directory, bundle_tool) and points_to(applied, bundle_directory, bundle_tool) and \
            config == bundle_tool:
        return result("bound")

    def source_ok(directory):
        if type(directory) is not str or not directory.startswith(SLOT_PREFIX) or directory == bundle_directory:
            return "not-a-preparation-slot"
        if directory not in placed:
            return "slot-not-placed-by-this-tool"
        try:
            tool, _ = registered_tool(steam, directory)
        except (OSError, Invalid, TypeError, KeyError, ValueError):
            return "slot-folder-missing-or-unregistered"
        if tool != tool_id_of(directory):
            return "slot-tool-id-differs"
        return None

    usable, why = history_state(items)
    old_dir = applied.get("dir") if type(applied) is dict else None
    old_tool = tool_id_of(old_dir) if type(old_dir) is str and old_dir.startswith(SLOT_PREFIX) else None
    consistent_old = (old_tool is not None and points_to(applied, old_dir, old_tool) and config == old_tool)
    if consistent_old and points_to(games, old_dir, old_tool):
        problem = source_ok(old_dir) or (None if usable else why)
        if problem:
            return result("other", old_dir, problem)
        if notes_missing(items):
            return result("move", old_dir, "binding-note-missing")
        if touched(items, bundle_directory):
            return result("move", old_dir, "returned-from-this-slot")
        if old_dir not in superseded:
            return result("move", old_dir, "not-superseded-by-this-bundle")
        return result("move", old_dir, None, batch=True)
    if consistent_old and points_to(games, bundle_directory, bundle_tool):
        # 4.6: only the observed direction (screen chose this slot, config and applied still on the old slot).
        problem = source_ok(old_dir) or (None if usable else why)
        if problem:
            return result("other", old_dir, problem)
        choice = copy.deepcopy(games)
        if notes_missing(items):
            return result("align", old_dir, "binding-note-missing", choice=choice)
        if old_dir not in superseded:
            # As for a move (4.2): only slots this bundle replaces are aligned by the batch run.
            return result("align", old_dir, "not-superseded-by-this-bundle", choice=choice)
        return result("align", old_dir, None, batch=True, choice=choice)
    if points_to(applied, bundle_directory, bundle_tool) and config == bundle_tool and type(games) is dict:
        return result("screen-other", games.get("dir"), "screen-chose-another-proton")
    return result("other", old_dir, "not-assigned-to-a-placed-slot")


def placed_roots(store, steam, bundle_directory):
    """Roots of the other preparation slots this tool placed (for the 4.4 (c) layout check).

    Same conditions as a move source (4.2, 4.7): placed by this tool, the folder exists and
    its registration (``registered_tool``) names the slot's tool ID.
    """
    from preparation_common import safe_path
    placed, _ = placed_slots(store)
    roots = []
    for directory in sorted(placed):
        if directory == bundle_directory:
            continue
        try:
            root = safe_path(safe_path(steam) / "compatibilitytools.d" / directory, safe_path(steam))
            tool, _ = registered_tool(steam, directory)
        except (OSError, Invalid, TypeError, KeyError, ValueError):
            continue
        if tool == tool_id_of(directory) and root.is_dir():
            roots.append(root)
    return tuple(roots), placed


# ---- individual operation 5: move one game ------------------------------------------------

FIRST_LAUNCH_NOTE = "切り替えたあとの最初の起動は、prefixの更新で長くなることがあります。"
REASON_TEXT = {
    None: "",
    "binding-note-missing": "（割り当ての補足の記録が欠けています。まとめての実行では移しません）",
    "returned-from-this-slot": "（このProtonから戻したゲームです。まとめての実行では移しません）",
    "not-superseded-by-this-bundle": "（このバンドルが置き換える版ではありません。まとめての実行では移しません）",
}


def bundle_directory(config):
    """The bundle's preparation slot name, from its payload root."""
    return slot_name(SLOT_PREFIX + config["payload"]["root"].removeprefix("DroidDeck-Proton "))


def unreadable_reason(error):
    """A short reason for a game left out of a list (our own messages only; no local paths)."""
    return str(error) if isinstance(error, Invalid) else type(error).__name__


def move_candidates(store, steam, settings, config, records):
    """Games that ``move`` or ``align`` would apply to, with their classification (read-only).

    Returns (found, roots, unreadable): ``unreadable`` lists the games that could not be
    judged ({"app_id", "reason"}), so they are shown instead of silently left out.
    """
    from preparation_binding import plan_binding
    directory = bundle_directory(config)
    roots, placed = placed_roots(store, steam, directory)
    superseded = tuple(config.get("supersedes", ()))
    found, unreadable = [], []
    for record in records:
        key = record["app_id"]
        try:
            items, _ = history(store, key)
            plan = plan_binding(steam, settings, key, directory)
            decision = classify(plan.before, key, directory, placed, steam, superseded, items)
        except (OSError, Invalid, TypeError, KeyError, ValueError) as error:
            unreadable.append({"app_id": key, "reason": unreadable_reason(error)})
            continue
        if decision["kind"] in ("move", "align"):
            found.append((record, decision))
    return found, roots, unreadable


UNREADABLE_TEXT = "記録や設定を読めなかったため一覧に出していないゲーム: "


def print_unreadable(unreadable, output, text):
    """One line per game left out of a list, with the reason (A12)."""
    for item in unreadable:
        print("  " + UNREADABLE_TEXT + "ID " + text(item["app_id"]) + "（" + text(item["reason"]) + "）", file=output)


def move_check(store, steam, config, key, pinned, targets=None):
    """The ``under_lock`` comparison: the rebuilt plan must classify exactly as confirmed (3.5),
    and, when ``targets`` is given, the target's items must be the confirmed ones."""
    directory = bundle_directory(config)

    def check(fresh):
        if targets is not None:
            require(target_items(fresh.before, key) == targets, "confirmed target items changed")
        items, _ = history(store, key)
        _, placed = placed_roots(store, steam, directory)
        again = classify(fresh.before, key, directory, placed, steam, tuple(config.get("supersedes", ())), items)
        compared = ("kind", "source", "choice", "batch", "reason")
        require({k: again[k] for k in compared} == {k: pinned[k] for k in compared}, "move decision changed")
    return check


def plan_move(*, record, digest, decision, roots, config, directory, renderer, steam, settings, home, environment,
              runtime_root, source, stop):
    """(plan, refresh, blockers) to move or align one game (shared by operation 5 and the batch run)."""
    import preparation_selection as selection
    from preparation_common import safe_path
    from preparation_game_prefix import plan_game_binding

    def refresh():
        current, _, now = selection.registration_catalog(environment)
        require(current == source, "registration source changed")
        return plan_game_binding(record=record, record_sha256=digest, config=config, directory=directory,
                                 renderer=renderer, source=current, games=now, steam=steam, settings=settings,
                                 home=home, environment=environment, runtime_root=runtime_root, stop_check=stop,
                                 previous_slots=roots, choice=decision["choice"])
    plan = refresh()
    require(plan.base.customization.directory == bundle_directory(config), "bundle slot name differs")
    blockers = list(plan.blockers)
    version_file = safe_path(plan.base.compatdata / "version", steam)
    if not prefix_version_matches(plan.base.inventory.captured.get("proton"),
                                  version_file.read_bytes() if version_file.is_file() else None):
        blockers.append("prefix-version-differs")
    return plan, refresh, blockers


def apply_move(store, plan, refresh, stop, *, key, decision, config, steam, targets=None, before=None):
    """Write a planned move under the held target lock: the note first, then the three files (4.3)."""
    from preparation_game_prefix import apply_game_binding
    kind = "move"  # An alignment also assigns this slot coming from another one.

    def on_binding_id(run_id):
        if before is not None:
            before(run_id)
        write_note(store, note(run_id, key, kind, bundle_directory(config), decision["source"], plan.binding))
    return apply_game_binding(plan, store, refresh, plan.digest, stop,
                              under_lock=move_check(store, steam, config, key, decision, targets),
                              on_binding_id=on_binding_id)


def interactive_move(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                     steam=None, settings=None, home=None, runtime_root=None):
    """Individual operation 5: move one prepared game to this bundle's slot (design 4.2-4.6)."""
    import hashlib
    import os
    import sys
    from pathlib import Path

    import preparation_selection as selection
    from preparation_common import safe_path
    from preparation_dependency_install import describe_error
    from preparation_game_prefix import RECORDS
    from preparation_processes import ProcessStopCheck
    from preparation_store import PrivateStore

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    runtime_root = Path("/") if runtime_root is None else runtime_root
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    protected, stage, started = [steam, settings], "move-plan", False
    report = None
    try:
        selection.validate_selection_config(config)
        require("game_preparation" in config, "game preparation not enabled")
        target = bundle_directory(config)
        with PrivateStore(management) as store:
            records = []
            for item in store.inventory()["game_prefixes"]:
                if item.get("status") == "initialized-unverified":
                    record, digest = store.read_record(RECORDS, item["trial_id"] + ".json")
                    records.append((record, digest))
            candidates, roots, unreadable = move_candidates(store, steam, settings, config,
                                                            [record for record, _ in records])
        if not candidates:
            print("このProtonへ移せるゲームはありません。", file=output)
            print_unreadable(unreadable, output, selection._text)
            report = {"mode": "move-result", "tool_version": VERSION, "status": "nothing-to-move", "writes": [],
                      "unreadable_games": unreadable, "preparation_complete": False}
        else:
            print_unreadable(unreadable, output, selection._text)
            source, _, games = selection.registration_catalog(environment)
            for number, (record, decision) in enumerate(candidates, 1):
                title = games.get(record["app_id"], {}).get("title", "（登録が見つかりません）")
                what = "移す" if decision["kind"] == "move" else "DroidDeckの画面の選択にそろえる"
                print(f"{number}. {selection._text(title)} [ID {record['app_id']}] 今: " +
                      selection._text(str(decision["source"])) + " → " + selection._text(target) + f"（{what}）" +
                      REASON_TEXT.get(decision["reason"], ""), file=output)
            print("移すゲームの番号（qで取消）: ", end="", file=output, flush=True)
            answer = stream.readline(32).strip()
            if answer == "q" or not answer:
                print("取り消しました。", file=output)
                return 0, None
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(candidates), "invalid game selection")
            record, decision = candidates[int(answer) - 1]
            digest = next(found for rec, found in records if rec is record)
            protected.extend(Path(game["exe"]).parent for game in games.values())
            stop = ProcessStopCheck(safe_path(steam / "steamapps/compatdata" / record["app_id"], steam))

            print("prefix・tool・依存をWineを起動せず照合し、移す計画を作っています。", file=output, flush=True)
            plan, refresh, blockers = plan_move(record=record, digest=digest, decision=decision, roots=roots, config=config,
                                                directory=directory, renderer=renderer, steam=steam, settings=settings,
                                                home=home, environment=environment, runtime_root=runtime_root,
                                                source=source, stop=stop)
            summary = plan.summary()
            for item in summary["dependencies"]:
                layout = " / " + item["layout"] if item.get("layout") else ""
                print("  依存: " + selection._text(item["dependency_id"] + " / " + item["state"] + layout +
                                                  (" / " + item["reason"] if item.get("reason") else "")), file=output)
            report = {"mode": "move-result", "tool_version": VERSION, "decision": decision, "plan": summary,
                      "blockers": blockers, "unreadable_games": unreadable, "binding_written": False,
                      "preparation_complete": False}
            if blockers:
                for blocker in blockers:
                    print("停止理由: " + selection._text(blocker), file=output)
                if "prefix-version-differs" in blockers:
                    print("このProtonはprefixの版を変えます。今の版では移せません。", file=output)
                print("移しません。変更せずに結果を保存します。", file=output)
                report["writes"] = []
            else:
                print("変更予定: " + selection._text(", ".join(summary["binding"]["planned_files"]) or "なし") +
                      f"（他ゲームの保留選択 {summary['binding']['other_pending_count']}件は変更しません）", file=output)
                print("DroidDeckの画面での切り替えと、同期のコマンドは要りません。", file=output)
                print(FIRST_LAUNCH_NOTE, file=output)
                print("このゲームを " + selection._text(target) + " へ移す場合は1、取消はq（ゲームは起動しません）: ",
                      end="", file=output, flush=True)
                if stream.readline(32).strip() != "1":
                    print("取り消しました。", file=output)
                    return 0, None
                stage, started = "move-apply", True
                selection._private_report_directory(home, protected)
                lock = hashlib.sha256(str(plan.base.compatdata).encode()).hexdigest()
                with PrivateStore(management) as store, store.locked(lock):
                    result = apply_move(store, plan, refresh, stop, key=record["app_id"], decision=decision,
                                        config=config, steam=steam)
                report.update(binding=result, binding_written=result["status"] == "binding-verified",
                              writes=[{"scope": "target-only-games-config-state"},
                                      {"scope": "private-binding-backup-record-and-note"}])
                print("移しました（" + selection._text(result["status"]) + "）。DroidDeckから起動してください。", file=output)
                print(FIRST_LAUNCH_NOTE, file=output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "move-result", "tool_version": VERSION, "stage": stage, **describe_error(error, stage),
                  "preparation_complete": False, "writes": [] if not started else [{"scope": "partial-binding-preserve"}]}
        print("検査停止: " + selection._text(report["check"]) + " / " + selection._text(report["reason"] or report["error_class"]),
              file=output)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録と設定のバックアップは保持しています。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    return 2, str(saved)


# ---- individual operation 6: assign a game back to another preparation slot ----------------

REVERT_NOTE = "新しいProtonから前のProtonへ戻す向きは、実機ではまだ確かめていません。"
REFUSED_TEXT = {
    "slot-manifest-missing": "照合情報がありません（このProtonを同梱した0.31.0以降のバンドルを一度実行すると作られます）",
    "slot-manifest-broken": "照合情報を読めません（書き換えません。status.sh で確かめてください）",
    "slot-manifest-mismatch": "同じ名前で別の中身の照合情報があります",
    "slot-manifest-rules-differ": "照合情報の照合規則の版が、このツールと違います",
    "slot-differs-from-saved-data": "今のslotの中身が、保存した照合情報と違います",
}
REFUSED_GUIDE = "このProtonへは、DroidDeckの画面と同期のコマンドで戻せます。"


def print_refused(refused, output, text):
    """Slots that are not revert targets, with the reason and the manual route (design 4.8)."""
    for name, reason in sorted(refused.items()):
        print("  " + text(name) + ": " + REFUSED_TEXT.get(reason, text(reason)) + "。" + REFUSED_GUIDE, file=output)


def revert_dependencies(record, config, compatdata, exe, stop, saved, target_root, previous_slots):
    """Dependency states against the revert target, shown but never required (design 4.8)."""
    from preparation_game_prefix import _dependency_states, validate_game_config
    from preparation_slot_manifest import inventory_of
    from preparation_softdenchi_recipe import softdenchi_recipe
    try:
        profiles, recipes = validate_game_config(config.get("game_preparation"))
        profile = profiles.get(record["profile"]["profile_id"])
        require(profile is not None, "game profile not in this bundle")
        states = _dependency_states(profile, recipes, compatdata, softdenchi_recipe(), stop,
                                    exe, (inventory_of(saved), target_root), previous_slots)
        return [{key: item[key] for key in ("dependency_id", "state", "reason", "layout") if key in item}
                for item in states], None
    except (OSError, Invalid, TypeError, KeyError, ValueError) as error:
        return [], unreadable_reason(error)


def revert_targets(store, steam, bundle):
    """Other preparation slots this tool placed that can be verified again (design 4.7, 4.8).

    Returns ([(directory, record)], {directory: reason}) for the usable and the refused ones.
    The slot is verified against its saved inventory and generated files, caches allowed.
    """
    from preparation_common import safe_path
    from preparation_payload import verify_fex_runtime_tree
    from preparation_slot_manifest import inventory_of, state, usable
    placed, _ = placed_slots(store)
    usable_slots, refused = [], {}
    for directory in sorted(placed):
        if directory == bundle:
            continue
        found, record = state(store, directory)
        if found != "same" or not usable(record):
            refused[directory] = "slot-manifest-" + ("rules-differ" if found == "same" else found)
            continue
        try:
            tool, _ = registered_tool(steam, directory)
            require(tool == tool_id_of(directory) == record["tool_id"], "slot tool ID differs")
            root = safe_path(safe_path(steam) / "compatibilitytools.d" / directory, safe_path(steam))
            verify_fex_runtime_tree(root, inventory_of(record), record["overlays"])
        except (OSError, Invalid, TypeError, KeyError, ValueError):
            refused[directory] = "slot-differs-from-saved-data"
            continue
        usable_slots.append((directory, record))
    return usable_slots, refused


def marked_slot(items, bundle, candidates):
    """The slot a game was moved from to this bundle slot, by the newest valid note (4.8)."""
    found = [item["note"] for item in items if item["note_state"] == "valid" and item["status"] == "binding-verified" and
             item["note"]["directory"] == bundle and item["note"]["previous_directory"] in candidates]
    return max(found, key=lambda record: record["created_ns"])["previous_directory"] if found else None


def _cache_parts(relative):
    """Path components of an accepted cache directory, relative to the slot root."""
    parts = relative.split("/") if type(relative) is str else []
    require(parts and parts[-1] == PYCACHE and not {"", ".", ".."} & set(parts), "invalid cache path")
    return parts


def _open_parent(root_fd, parts):
    """A descriptor of the cache's parent directory, walked without following links."""
    import os
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = following
    except BaseException:
        os.close(parent)
        raise
    return parent


def _cache_files(directory_fd):
    import os
    hashes = {}
    for name in sorted(os.listdir(directory_fd)):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        with os.fdopen(descriptor, "rb") as stream:
            hashes[name] = hashlib.sha256(stream.read(16 * 1024 * 1024)).hexdigest()
    return hashes


def list_caches(root, verified):
    """The ``__pycache__`` directories the verification accepted: relative path, identity, file hashes.

    Only the directories ``verify_fex_runtime_tree`` reported as ``python_caches`` (design
    4.7 step 1); a ``__pycache__`` of the payload itself is not a cache and is never moved.
    """
    import os
    accepted = sorted((verified.get("python_caches") or {}).get("directories") or {})
    require(len(accepted) <= MAX_CACHES, "too many cache directories")
    caches = []
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for relative in accepted:
            parent = _open_parent(root_fd, _cache_parts(relative))
            try:
                fd = os.open(PYCACHE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    caches.append({"relative": relative, "device": info.st_dev, "inode": info.st_ino,
                                   "files": _cache_files(fd)})
                finally:
                    os.close(fd)
            finally:
                os.close(parent)
    finally:
        os.close(root_fd)
    return caches


def move_caches(store, root, plan_caches, binding_id, record, record_hash):
    """Move the listed cache directories into the private store, one non-replacing rename each.

    The note (``record``) already holds the plan; after each move its "moved" list is
    updated atomically. Stops at the first refusal (EXDEV, an existing name, a changed
    directory) without touching the settings. Returns the new note hash.
    """
    import os

    from preparation_publication import _rename_function, rename_noreplace
    rename = _rename_function()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with store.directory((CACHES, binding_id), create=True) as destination:
            for number, item in enumerate(plan_caches, 1):
                parent = _open_parent(root_fd, _cache_parts(item["relative"]))
                try:
                    info = os.stat(PYCACHE, dir_fd=parent, follow_symlinks=False)
                    require((info.st_dev, info.st_ino) == (item["device"], item["inode"]), "cache directory changed")
                    name = f"c{number:04d}"
                    rename_noreplace(rename, parent, PYCACHE, destination, name)
                    moved_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination)
                    try:
                        info = os.fstat(moved_fd)
                        require((info.st_dev, info.st_ino) == (item["device"], item["inode"]), "moved cache differs")
                        require(_cache_files(moved_fd) == item["files"], "moved cache files differ")
                    finally:
                        os.close(moved_fd)
                    os.fsync(parent)
                    os.fsync(destination)
                finally:
                    os.close(parent)
                record["cache_move"]["moved"].append({"relative": item["relative"], "name": name})
                record_hash = store.write_record(NOTES, binding_id + ".json", record, record_hash)
    finally:
        os.close(root_fd)
    return record_hash


def interactive_revert(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                       steam=None, settings=None, home=None, runtime_root=None, proc_root=None):
    """Individual operation 6: assign one game back to another preparation slot (design 4.8)."""
    import os
    import sys
    from pathlib import Path

    import preparation_selection as selection
    from preparation_binding import apply_binding, plan_binding
    from preparation_common import safe_path
    from preparation_dependency_install import describe_error
    from preparation_game_prefix import RECORDS
    from preparation_payload import runtime_writes, verify_fex_runtime_tree
    from preparation_processes import ProcessStopCheck, observe_slot_users
    from preparation_recheck import check_game_identity
    from preparation_slot_manifest import inventory_of
    from preparation_slot_manifest import state as manifest_state
    from preparation_store import PrivateStore

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    proc_root = Path("/proc") if proc_root is None else proc_root
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    management = home / ".local/state/droiddeck-prefix-preparation/tool-store"
    protected, stage, started = [steam, settings], "revert-plan", False
    report = None
    progress = {}  # The note of the running revert, so a later failure still reports the moved caches (4.7).
    try:
        selection.validate_selection_config(config)
        require("game_preparation" in config, "game preparation not enabled")
        bundle = bundle_directory(config)
        bundle_tool = tool_id_of(bundle)
        source, _, games = selection.registration_catalog(environment)
        with PrivateStore(management) as store:
            bound, unreadable = [], []
            for item in store.inventory()["game_prefixes"]:
                if item.get("status") != "initialized-unverified":
                    continue
                record, digest = store.read_record(RECORDS, item["trial_id"] + ".json")
                key = record["app_id"]
                try:
                    items, _ = history(store, key)
                    # Read without the bundle slot's registration: a broken bundle slot must not hide the game.
                    current = current_selection(current_files(steam, settings), key)
                except (OSError, Invalid, TypeError, KeyError, ValueError) as error:
                    unreadable.append({"app_id": key, "reason": unreadable_reason(error)})
                    continue
                if points_to(current["games"], bundle, bundle_tool) and points_to(current["applied"], bundle, bundle_tool) \
                        and current["config"] == bundle_tool and history_state(items)[0]:
                    bound.append((record, digest, items))
            targets, refused = revert_targets(store, steam, bundle) if bound else ([], {})
            placed_at_list = placed_slots(store)[0]
            other_roots = {name: placed_roots(store, steam, name)[0] for name, _ in targets}
        if not bound or not targets:
            print("このProtonから戻せるゲームはありません。" if not bound else
                  "戻す先にできる準備用Protonがありません（DroidDeckの画面と同期のコマンドで戻せます）。", file=output)
            print_unreadable(unreadable, output, selection._text)
            print_refused(refused, output, selection._text)
            report = {"mode": "revert-result", "tool_version": VERSION, "status": "nothing-to-revert",
                      "refused_targets": refused, "unreadable_games": unreadable, "writes": [],
                      "preparation_complete": False}
        else:
            print_unreadable(unreadable, output, selection._text)
            for number, (record, _, _) in enumerate(bound, 1):
                title = games.get(record["app_id"], {}).get("title", "（登録が見つかりません）")
                print(f"{number}. {selection._text(title)} [ID {record['app_id']}] 今: " + selection._text(bundle), file=output)
            print("戻すゲームの番号（qで取消）: ", end="", file=output, flush=True)
            answer = stream.readline(32).strip()
            if answer == "q" or not answer:
                print("取り消しました。", file=output)
                return 0, None
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(bound), "invalid game selection")
            record, digest, items = bound[int(answer) - 1]
            key = record["app_id"]
            names = [name for name, _ in targets]
            mark = marked_slot(items, bundle, names)
            ordered = sorted(names, key=lambda name: (name != mark, name))
            print("別の準備用Protonへ割り当てます。割り当て先の番号（qで取消）:", file=output)
            for number, name in enumerate(ordered, 1):
                print(f"{number}. " + selection._text(name) + ("（このProtonへ移す前のProton）" if name == mark else ""),
                      file=output)
            if refused:
                print("戻す先にできないProton:", file=output)
                print_refused(refused, output, selection._text)
            answer = stream.readline(32).strip()
            if answer == "q" or not answer:
                print("取り消しました。", file=output)
                return 0, None
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(ordered), "invalid slot selection")
            target_dir = ordered[int(answer) - 1]
            saved = dict(targets)[target_dir]
            target_root = safe_path(steam / "compatibilitytools.d" / target_dir, steam)
            protected.extend(Path(game["exe"]).parent for game in games.values())
            stage = "revert-check"
            identity = check_game_identity(record=record, record_sha256=digest, source=source, games=games, steam=steam,
                                           home=home)
            compatdata = identity["compatdata"]
            stop = ProcessStopCheck(compatdata, proc_root)
            _, tool_hashes = registered_tool(steam, target_dir)
            proton_raw = (target_root / "proton").read_bytes()
            require(hashlib.sha256(proton_raw).hexdigest() == tool_hashes["proton"], "slot launcher changed while reading")
            blockers = []
            version_file = safe_path(compatdata / "version", steam)
            if not prefix_version_matches(proton_raw, version_file.read_bytes() if version_file.is_file() else None):
                blockers.append("prefix-version-differs")
            if not stop.check()["clear_in_view"]:
                blockers.append("game-prefix-in-use")
            users = observe_slot_users(target_root, proc_root)
            if not users["clear"]:
                blockers.append("target-slot-in-use")
            verified = verify_fex_runtime_tree(target_root, inventory_of(saved), saved["overlays"])
            caches = list_caches(target_root, verified)
            plan = plan_binding(steam, settings, key, target_dir)
            dependencies, dependencies_unreadable = revert_dependencies(
                record, config, compatdata, identity["exe"], stop, saved, target_root, other_roots[target_dir])
            report = {"mode": "revert-result", "tool_version": VERSION, "app_id": key, "from": bundle, "to": target_dir,
                      "marked": mark == target_dir, "caches_to_move": len(caches), "blockers": blockers,
                      "dependencies": dependencies, "dependencies_unreadable": dependencies_unreadable,
                      "refused_targets": refused, "unreadable_games": unreadable,
                      "slot_runtime_writes": runtime_writes(verified), "binding_written": False,
                      "preparation_complete": False, "process_observation": {"slot_users": users}}
            print("戻す先: " + selection._text(target_dir), file=output)
            print("戻す先のProtonは、置いたときに保存した中身の一覧と照合しました（配布物とは照合していません）。", file=output)
            for item in dependencies:
                print("  依存: " + selection._text(" / ".join(str(item[key]) for key in ("dependency_id", "state", "layout",
                                                                                        "reason") if item.get(key))),
                      file=output)
            if dependencies_unreadable:
                print("  依存: 判定できません（" + selection._text(dependencies_unreadable) + "）", file=output)
            print("依存（DLL・ソフト電池）の判定は、戻す条件にしません（prefixの中は変えません）。", file=output)
            if blockers:
                for blocker in blockers:
                    print("停止理由: " + selection._text(blocker), file=output)
                if "prefix-version-differs" in blockers:
                    print("戻す先のProtonはprefixの版が違います。戻せません。", file=output)
                print("戻しません。変更せずに結果を保存します。", file=output)
                report["writes"] = []
            else:
                print(REVERT_NOTE, file=output)
                print(f"戻す先のProtonのPythonキャッシュ（{len(caches)}か所）をツールの私有の場所へ移します。"
                      "割り当てが途中で止まっても、移したキャッシュは移したままです（次の起動で作り直されます）。", file=output)
                print("操作が終わるまで、ゲームを起動しないでください（戻す先のProtonを使うほかのゲームも含みます）。", file=output)
                print(FIRST_LAUNCH_NOTE, file=output)
                print("このゲームを " + selection._text(target_dir) + " へ戻す場合は1、取消はq: ", end="", file=output, flush=True)
                if stream.readline(32).strip() != "1":
                    print("取り消しました。", file=output)
                    return 0, None
                stage, started = "revert-apply", True
                selection._private_report_directory(home, protected)
                lock = hashlib.sha256(str(compatdata).encode()).hexdigest()
                moved = {"done": False}
                with PrivateStore(management) as store, store.locked(lock):
                    def ready():
                        current_source, _, now = selection.registration_catalog(environment)
                        require(current_source == source and now.get(key) == games.get(key), "registration changed")
                        check_game_identity(record=record, record_sha256=digest, source=source, games=now, steam=steam,
                                            home=home)
                        require(stop.check()["clear_in_view"], "target process view not clear")
                        require(observe_slot_users(target_root, proc_root)["clear"], "revert target slot in use")
                        found, current = manifest_state(store, target_dir)
                        require(found == "same" and current == saved, "slot data changed")
                        require(placed_slots(store)[0].get(target_dir, False) == placed_at_list[target_dir],
                                "revert target placement record changed")
                        _, hashes = registered_tool(steam, target_dir)
                        require(hashes == tool_hashes, "slot tool changed")
                        result = verify_fex_runtime_tree(target_root, inventory_of(saved), saved["overlays"])
                        if moved["done"]:
                            require(result.get("python_caches") is None, "caches appeared in the revert target")
                        return {"target": True, "stopped": True, "slot_record": True}

                    def under_lock(fresh):
                        current = current_selection(fresh.before, key)
                        require(points_to(current["games"], bundle, bundle_tool) and
                                points_to(current["applied"], bundle, bundle_tool) and current["config"] == bundle_tool,
                                "assignment changed")
                        again = verify_fex_runtime_tree(target_root, inventory_of(saved), saved["overlays"])
                        require(list_caches(target_root, again) == caches, "revert target caches changed")

                    def on_binding_id(run_id):
                        entry = note(run_id, key, "revert", target_dir, bundle, plan,
                                     cache_move={"planned": caches, "moved": [], "destination": CACHES + "/" + run_id})
                        record_hash = write_note(store, entry)
                        progress.update(entry=entry)
                        move_caches(store, target_root, caches, run_id, entry, record_hash)
                        strict = verify_fex_runtime_tree(target_root, inventory_of(saved), saved["overlays"])
                        require(strict.get("python_caches") is None, "caches remain in the revert target")
                        moved["done"] = True

                    result = apply_binding(plan, steam, settings, store, ready, kind="revert", bundle_directory=bundle,
                                           under_lock=under_lock, on_binding_id=on_binding_id)
                report.update(binding=result, binding_written=result["status"] == "binding-verified",
                              writes=[{"scope": "target-only-games-config-state"},
                                      {"scope": "private-binding-backup-record-and-note"},
                                      {"scope": "revert-target-caches-moved-to-private-store", "count": len(caches)}])
                print("戻しました（" + selection._text(result["status"]) + "）。DroidDeckから起動してください。", file=output)
                print("もう一度新しいProtonへ移すときは、recovery.sh の2を使ってください。", file=output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"mode": "revert-result", "tool_version": VERSION, "stage": stage, **describe_error(error, stage),
                  "preparation_complete": False,
                  "writes": [] if not started else [{"scope": "partial-revert-preserve"}]}
        print("検査停止: " + selection._text(report["check"]) + " / " + selection._text(report["reason"] or report["error_class"]),
              file=output)
        if progress:
            move = progress["entry"]["cache_move"]
            report["cache_move"] = {"binding_id": progress["entry"]["binding_id"], "moved": len(move["moved"]),
                                    "planned": len(move["planned"]), "destination": move["destination"]}
            print(f"戻す先のPythonキャッシュを{len(move['moved'])}か所移しました（私有記録の " +
                  selection._text(move["destination"]) + "）。次の起動で作り直されます。", file=output)
    try:
        saved_path, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録と設定のバックアップは保持しています。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved_path)), file=output)
    return 2, str(saved_path)
