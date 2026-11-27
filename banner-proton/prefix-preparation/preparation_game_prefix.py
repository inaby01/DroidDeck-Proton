"""Registered game: initialize a never-launched new prefix with the reviewed preparation slot.

This is the game-registration counterpart of the dedicated probe trial. It reuses
the same guarded session (fixed builtin initialization, no forced termination, no
retry, no adoption of existing prefixes). Existing prefixes stay read-only. A game
profile is bound to the record; dependencies and binding are separate steps.
"""

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

import preparation_trial as trial
from preparation_assets import (
    MAX_EXE,
    digest_json,
    exe_identity,
    measure_stream,
    pe_machine,
)
from preparation_common import (
    SHA256,
    VERSION,
    fields,
    identifier,
    regular_open,
    require,
    revision,
    safe_path,
    string,
)
from preparation_execution import _aliases
from preparation_installation import plan_installation
from preparation_processes import ProcessStopCheck
from preparation_static_placement import _private_xalia_context, validate_build_review
from preparation_store import PrivateStore

SCOPE = "registered-game-new-prefix"
RECORDS = "game-prefixes"
# Binding blocker when the target game or Wine was seen running around the dependency checks.
# The "process:" form keeps it apart from dependency blockers ("dependency-…:<id>"), whose ids
# may be any identifier, including this text.
PROCESS_BLOCKER = "process:target-process-view-not-clear"
ID_PREFIX = "gprefix-"
HANDLERS = ("softdenchi-interactive", "mfc-local", "game-folder-file", "prefix-dll")
# Handlers whose recipes may be declared ready: the guarded SoftDenchi installer, a read-only
# check of a file already in the registered game's folder (nothing is copied or installed), and
# one declared x86 DLL placed into the prefix's syswow64 (menu 12). ``mfc-local`` stays reserved.
READY_HANDLERS = ("softdenchi-interactive", "game-folder-file", "prefix-dll")
GAME_FOLDER_FILE_LIMIT = 64 * 1024 * 1024
NON_ASCII_NOTE = ("注意: 登録EXEのパスにASCII以外の文字（日本語など）が含まれます。"
                  "このようなフォルダー名で、ゲームが起動直後に終了した例があります（原因は未確定）。"
                  "フォルダー名を変える場合は、この初期化の前に変えて登録し直してください（初期化後は登録パスが固定されます）。")
PE_MACHINES = ("x86", "x86_64")


def _directory_identity(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    return {"device": info.st_dev, "inode": info.st_ino}


def prefix_identity(compatdata):
    """Directory identity of the created prefix root; a restored or replaced prefix never matches."""
    return _directory_identity(safe_path(compatdata))


def wineprefix_identity(compatdata):
    """Directory identity of the WINEPREFIX (pfx) created by the initialization inside the prefix root."""
    compatdata = safe_path(compatdata)
    return _directory_identity(safe_path(compatdata / "pfx", compatdata))


def require_initialized_directories(compatdata, record):
    """Directory swaps only: restoring files inside the same directories is not detected."""
    require(prefix_identity(compatdata) == record["prefix_identity"], "game prefix replaced since initialization")
    require(wineprefix_identity(compatdata) == record["wineprefix_identity"], "game Wine prefix replaced since initialization")


def registration_identity(exe, title):
    """Digests of the normalized registered EXE path and title; the record keeps no plain title."""
    return {"exe_path_sha256": hashlib.sha256(str(safe_path(exe)).encode()).hexdigest(),
            "title_sha256": hashlib.sha256(string(title).encode()).hexdigest()}


def validate_game_config(value):
    """Operator-declared profiles and recipes. Declarations never authorize execution by themselves."""
    fields(value, ("profiles", "recipes"), ("default_profile",))
    recipes = {}
    require(type(value["recipes"]) is list and 0 < len(value["recipes"]) <= 64, "invalid recipe list")
    for item in value["recipes"]:
        if type(item) is dict and item.get("handler") == "prefix-dll":
            from preparation_prefix_dll import validate_prefix_dll_recipe
            validate_prefix_dll_recipe(item)
        folder_file = type(item) is dict and item.get("handler") == "game-folder-file"
        prefix_dll = type(item) is dict and item.get("handler") == "prefix-dll"
        fields(item, ("dependency_id", "revision", "handler", "status", "reason") + (("file", "required_by") if folder_file else ()) +
               (("asset", "destination") if prefix_dll else ()))
        key = identifier(item["dependency_id"])
        require(key not in recipes, "duplicate recipe")
        revision(item["revision"])
        require(item["handler"] in HANDLERS and item["status"] in ("ready", "blocked"), "invalid recipe")
        require(item["handler"] in READY_HANDLERS or item["status"] == "blocked", "only SoftDenchi, a game-folder check or a prefix DLL can be ready")
        string(item["reason"])
        if folder_file:
            _validate_game_folder_file(item)
        recipes[key] = item
    profiles = {}
    require(type(value["profiles"]) is list and 0 < len(value["profiles"]) <= 64, "invalid profile list")
    for item in value["profiles"]:
        fields(item, ("profile_id", "revision", "title", "edition", "edition_status", "dependencies", "exe_sha256"))
        key = identifier(item["profile_id"])
        require(key not in profiles, "duplicate profile")
        revision(item["revision"])
        string(item["title"])
        string(item["edition"])
        require(item["edition_status"] in ("unconfirmed", "confirmed"), "invalid edition status")
        # No dependencies: only initialize the prefix and bind it (design: no-SoftDenchi 4.2).
        require(type(item["dependencies"]) is list and len(item["dependencies"]) <= 32 and
                len(set(item["dependencies"])) == len(item["dependencies"]) and
                all(identifier(dep) in recipes for dep in item["dependencies"]), "profile references unknown dependency")
        require(item["exe_sha256"] is None or type(item["exe_sha256"]) is str and SHA256.fullmatch(item["exe_sha256"]),
                "invalid expected EXE hash")
        # A game-folder file is checked for the executable it was derived from; the profile must pin that executable.
        require(all(recipes[dep]["handler"] != "game-folder-file" or
                    item["exe_sha256"] == recipes[dep]["required_by"]["exe_sha256"] for dep in item["dependencies"]),
                "game-folder dependency requires the profile EXE hash it was derived from")
        names = [recipes[dep]["asset"]["filename"].lower() for dep in item["dependencies"] if recipes[dep]["handler"] == "prefix-dll"]
        require(len(names) == len(set(names)), "prefix DLL names repeat within a profile")
        profiles[key] = item
    if "default_profile" in value:
        chosen = value["default_profile"]
        require(type(chosen) is str and chosen in profiles and profiles[chosen]["exe_sha256"] is None,
                "default profile must name a profile without an EXE hash")
    return profiles, recipes


def automatic_profiles(value):
    """Profiles a new registration may get without a choice (batch run, design: Proton update 5).

    ``default_profile`` when the bundle names one (design: no-SoftDenchi 5), otherwise every
    profile without an EXE hash; the caller uses the result only when it has exactly one entry.
    """
    if type(value) is dict and "default_profile" in value:
        return [value["default_profile"]]
    return [item["profile_id"] for item in value["profiles"] if item["exe_sha256"] is None]


def _validate_game_folder_file(item):
    spec, origin = item["file"], item["required_by"]
    fields(spec, ("name", "size", "sha256", "pe_machine"))
    fields(origin, ("exe_sha256", "import"))
    name = string(spec["name"])
    require(name.isascii() and name == name.strip() and "/" not in name and "\\" not in name and name not in (".", "..") and
            name.lower().endswith(".dll") and len(name) <= 64, "invalid game-folder file name")
    require(type(spec["size"]) is int and 0 < spec["size"] <= GAME_FOLDER_FILE_LIMIT, "invalid game-folder file size")
    require(type(spec["sha256"]) is str and SHA256.fullmatch(spec["sha256"]) is not None, "invalid game-folder file hash")
    require(spec["pe_machine"] in PE_MACHINES, "invalid game-folder file architecture")
    require(type(origin["exe_sha256"]) is str and SHA256.fullmatch(origin["exe_sha256"]) is not None, "invalid game-folder origin")
    require(type(origin["import"]) is str and origin["import"].lower() == name.lower(),
            "game-folder file must be the declared import of the executable")


def inspect_game_folder_file(exe, spec):
    """Read-only: the declared file directly in the registered EXE's folder (ASCII name, case-insensitive).

    ``present-verified`` means exactly one single-link regular file of that name with the
    declared size, SHA-256 and PE architecture, which is also the architecture of the
    registered EXE. It is a match with the declaration only: provenance is not checked, the
    EXE import table is not read, and nothing is copied, moved or loaded; whether the game
    actually loads it is only observable at launch.
    """
    exe = safe_path(exe)
    folder = exe.parent
    wanted = spec["name"].lower()
    try:
        with os.scandir(folder) as entries:
            matches = [entry for entry in entries if entry.name.isascii() and entry.name.lower() == wanted]
        if not matches:
            return {"state": "absent", "reason": "file not found in the game folder"}
        if len(matches) > 1:
            return {"state": "incompatible", "reason": "several files differ only in case"}
        if matches[0].is_symlink():
            return {"state": "incompatible", "reason": "symbolic link"}
        with regular_open(folder / matches[0].name, GAME_FOLDER_FILE_LIMIT) as stream:
            measured = measure_stream(stream, GAME_FOLDER_FILE_LIMIT, "pe")
        with regular_open(exe, MAX_EXE) as stream:
            exe_machine = pe_machine(stream, os.fstat(stream.fileno()).st_size)
    except OSError as error:
        return {"state": "uninspected", "reason": "game folder or file unreadable: " + type(error).__name__}
    except ValueError as error:
        return {"state": "incompatible", "reason": str(error)}
    if (measured["size"], measured["sha256"], measured["pe_machine"]) != (spec["size"], spec["sha256"], spec["pe_machine"]):
        return {"state": "incompatible", "reason": "size, hash or architecture differs"}
    if measured["pe_machine"] != exe_machine:
        return {"state": "incompatible", "reason": "architecture differs from the game executable"}
    return {"state": "present-verified"}


def exe_path_ascii(exe):
    """Whether the registered EXE path is ASCII; a non-ASCII folder name was seen together with an exit right after start."""
    return str(exe).isascii()


@dataclass(frozen=True)
class GamePlacement:
    """The attributes the shared initialization session needs; no probe material."""
    digest: str
    installation: object = field(repr=False)
    review: dict = field(repr=False)
    store_root: object = field(repr=False)
    settings: object = field(repr=False)


@dataclass(frozen=True)
class GamePrefixPlan:
    trial: object = field(repr=False)
    profile: dict = field(repr=False)
    profile_digest: str
    exe: dict = field(repr=False)
    selection: str
    dependencies: tuple
    registration: dict = field(repr=False)
    exe_path_ascii: bool = True

    @property
    def digest(self):
        return self.trial.digest

    @property
    def compatdata(self):
        return self.trial.compatdata

    def summary(self):
        base = self.trial.summary()
        base.update(scope=SCOPE, profile={key: self.profile[key] for key in ("profile_id", "revision", "title", "edition",
                                                                              "edition_status")},
                    profile_selection=self.selection, executable={"sha256": self.exe["sha256"], "size": self.exe["size"]},
                    dependencies=list(self.dependencies), exe_path_ascii=self.exe_path_ascii,
                    tool_runtime_writes=self.trial.placement.installation.summary().get("tool_runtime_writes"), binding_written=False,
                    dependencies_installed=False, existing_prefix_modified=False)
        return base


def plan_game_prefix(*, config, directory, renderer, source, games, key, profile_id, steam, settings, home, environment,
                     runtime_root, inventory=None):
    """Read-only plan for one registered game without a prefix (``inventory``: payload read once, for lists)."""
    profiles, recipes = validate_game_config(config.get("game_preparation"))
    require(profile_id in profiles, "unknown game profile")
    profile = profiles[profile_id]
    require(key in games, "selected registration absent")
    exe = safe_path(games[key]["exe"])
    from preparation_probe import EXE
    require(exe.name != EXE, "probe registrations use the dedicated trial scope")
    payload = config["payload"]
    require(payload.get("tool_slot") == "preparation" and "placement_review" in config, "reviewed preparation slot required")
    review = validate_build_review(config["placement_review"])
    require(review["archive_sha512"] == payload["sha512"], "reviewed payload identity differs")
    from preparation_selection import _archive
    installation = plan_installation(archive=_archive(directory, payload), sha512=payload["sha512"], archive_root=payload["root"],
        mode=payload["mode"], runtime_root=runtime_root, runtime_audit=config["runtime_reference"], registrations=source,
        registration_id=key, exe_root=exe.parent, steam=steam, renderer=renderer, parent_environment=environment,
        tool_slot="preparation", archive_from_folder=True, inventory=inventory)
    trial._live_runtime(installation)
    report = installation.summary()
    require(report["action"] == "reuse-verified-tree", "verified installed preparation tool required")
    require(not report["prefix"]["exists"], "existing prefix is read-only; a new registration is required")
    inventory = installation.inventory
    require(inventory.external_links == 0, "external payload links forbidden")
    require(not any(name in inventory.entries for name in ("dist", "dist.lock", "steampipe_fixups.json")),
            "mutable distribution maintenance path not supported")
    require(inventory.entries.get("files/share/default_pfx_arm64", {}).get("kind") == "directory",
            "shipped arm64 default prefix required")
    identity = exe_identity(exe)
    if profile["exe_sha256"] is not None:
        require(profile["exe_sha256"] == identity["sha256"], "game executable differs from the profile")
    selection = "operator-selected-unverified" if profile["exe_sha256"] is None else "profile-hash-matched"
    home, steam, settings = map(safe_path, (home, steam, settings))
    work = safe_path(home / ".local/share/droiddeck-preparation-work" / key / "work", home)
    private_home = safe_path(work.parent / "home", home)
    compatdata = safe_path(steam / "steamapps/compatdata" / key, steam)
    store_root = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store", home)
    _aliases(steam, key)
    require(not os.path.lexists(compatdata) and not os.path.lexists(work.parent), "new prefix and private paths required")
    for path in (work.parent, store_root):
        for protected in (steam, settings, exe.parent):
            require(path != protected and not path.is_relative_to(protected) and not protected.is_relative_to(path),
                    "game prefix paths overlap protected inputs")
    policy = _private_xalia_context(installation, review)
    if policy is not None:
        policy.guard()
    files = [value for name, value in inventory.entries.items() if name.startswith("files/share/default_pfx_arm64/")]
    fs = os.statvfs(compatdata.parent)
    block = fs.f_frsize or fs.f_bsize
    require(block > 0 and files, "prefix allocation baseline unavailable")
    baseline = block + sum(((entry["size"] + block - 1) // block) * block if entry["kind"] == "file" else block for entry in files)
    require(fs.f_bavail * block >= baseline + trial.RESERVE, "insufficient prefix baseline and reserve")
    require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
    dependencies = tuple({"dependency_id": dep, "handler": recipes[dep]["handler"], "status": recipes[dep]["status"],
                          "reason": recipes[dep]["reason"]} for dep in profile["dependencies"])
    profile_digest = digest_json(profile)
    placement_digest = digest_json({"installation": installation.digest, "review": review, "key": key})
    placement = GamePlacement(placement_digest, installation, review, store_root, settings)
    registration = registration_identity(exe, games[key]["title"])
    signature = {"scope": SCOPE, "version": VERSION, "placement": placement_digest, "home": str(home), "work": str(work),
                 "compatdata": str(compatdata), "baseline": baseline, "profile": profile_digest, "exe": identity["sha256"],
                 "registration": registration, "dependencies": list(dependencies)}
    plan = trial.TrialPlan(digest_json(signature), placement, home, work, private_home, compatdata, baseline)
    return GamePrefixPlan(plan, profile, profile_digest, identity, selection, dependencies, registration, exe_path_ascii(exe))


class GamePrefixSession(trial.TrialSession):
    scope, records, id_prefix = SCOPE, RECORDS, ID_PREFIX

    def __init__(self, plan, store, refresh, confirmed_digest, stop_check):
        require(isinstance(plan, GamePrefixPlan), "trusted game prefix plan required")
        super().__init__(plan.trial, store, refresh, confirmed_digest, stop_check)
        self.record["profile"] = {"profile_id": plan.profile["profile_id"], "revision": plan.profile["revision"],
                                  "profile_digest": plan.profile_digest, "exe_sha256": plan.exe["sha256"],
                                  "exe_size": plan.exe["size"], "selection": plan.selection, **plan.registration}

    def _prefix_created(self):
        # Saved before spawn: later steps accept only this directory, never a replacement at the same path.
        self.record["prefix_identity"] = prefix_identity(self.plan.compatdata)

    def _initialized(self):
        # The WINEPREFIX exists only after the fixed initialization; bind later steps to it as well.
        self.record["wineprefix_identity"] = wineprefix_identity(self.plan.compatdata)

    def _guard(self):
        super()._guard()
        if "prefix_identity" in self.record:
            require(prefix_identity(self.plan.compatdata) == self.record["prefix_identity"], "game prefix replaced during initialization")


def interactive_game_prefix(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                            steam=None, settings=None, home=None, runtime_root=Path("/")):
    """One explicit device action: choose a registered game and a profile, preview, confirm, initialize."""
    import sys

    import preparation_selection as selection
    from preparation_binding import droiddeck_lock
    from preparation_probe import EXE

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    directory = safe_path(directory)
    protected, stage, started, session = [steam, settings], "game-prefix-plan", False, None
    try:
        selection.validate_selection_config(config)
        profiles, _ = validate_game_config(config.get("game_preparation"))
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        base = steam / "steamapps/compatdata"
        candidates = [key for key, game in games.items() if Path(game["exe"]).name != EXE and
                      not os.path.lexists(base / key) and not (int(key) >= 2**31 and os.path.lexists(base / str(int(key) - 2**32)))]
        require(candidates, "no registered game without a prefix")
        for number, key in enumerate(candidates, 1):
            print(f"{number}. {selection._text(games[key]['title'])} [ID {key}]", file=output)
            print("   " + selection._text(games[key]["exe"]), file=output)
        print("新規prefixを作る実ゲーム登録の番号（qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32).strip()
        if answer == "q":
            return 0, None
        require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(candidates), "invalid game selection")
        key = candidates[int(answer) - 1]
        ids = sorted(profiles)
        for number, profile_id in enumerate(ids, 1):
            print(f"{number}. {selection._text(profiles[profile_id]['title'])} / {profile_id} / "
                  f"{selection._text(profiles[profile_id]['edition'])}", file=output)
        print("この登録に対応する作品プロファイルの番号（例: 1。一覧の名前でも可、qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32).strip()
        if answer == "q":
            return 0, None
        if answer in profiles:
            profile_id = answer
        else:
            require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(ids), "invalid profile selection")
            profile_id = ids[int(answer) - 1]

        def refresh():
            current, _, now = selection.registration_catalog(environment)
            require(current == source and key in now, "game registration changed")
            return plan_game_prefix(config=config, directory=directory, renderer=renderer, source=current, games=now,
                                    key=key, profile_id=profile_id, steam=steam, settings=settings, home=home,
                                    environment=environment, runtime_root=runtime_root)

        print("配布物・準備用tool全体・runtime識別・登録EXE・未作成prefixを照合しています（Wineは起動しません）。", file=output, flush=True)
        plan = refresh()
        preview = plan.summary()
        print("新規prefix: " + selection._text(preview["prefix"]), file=output)
        print("作品プロファイル: " + selection._text(preview["profile"]["title"]) + "（" +
              ("手動選択・EXEの既知ハッシュなし" if plan.selection == "operator-selected-unverified" else "EXEハッシュ一致") + "）",
              file=output)
        for dep in preview["dependencies"]:
            print("  依存: " + selection._text(dep["dependency_id"] + " / " + dep["status"]), file=output)
        if not plan.exe_path_ascii:
            print(NON_ASCII_NOTE, file=output)
        print(f"出荷時prefix見積 {plan.trial.baseline_bytes / 1024**2:.1f} MiB + 余裕1 GiB。実増分の上限は未測定です。", file=output)
        print("実行: 準備用Proton run cmd.exe /d /c exit 0（ゲーム・installerは起動しません。依存導入・割り当ても行いません）", file=output)
        print("新規prefix、専用work/HOME、私有記録/lock、設定の協調lock、結果JSONを書きます。既存prefix・ゲームフォルダーは変更しません。", file=output)
        print("すべてのゲーム・Wineを終了してから続行してください。他namespaceの停止は保証できません。", file=output)
        print("この新規prefixを初期化する場合は1、取消はq: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            return 0, None
        stage, started = "game-prefix-start", True
        selection._private_report_directory(home, protected)
        management = plan.trial.placement.store_root
        lock = hashlib.sha256(str(plan.compatdata).encode()).hexdigest()
        with PrivateStore(management, create=True) as store, store.locked(lock), droiddeck_lock(settings):
            session = GamePrefixSession(plan, store, refresh, plan.digest, ProcessStopCheck(plan.compatdata))
            session.start()
            while True:
                stage = "game-prefix-wait"
                outcome = session.wait(30)
                if outcome["status"] != "needs-user":
                    break
                print("未完了です。強制終了していません。さらに待つ場合は1、記録を残して戻る場合はq: ", end="", file=output, flush=True)
                if stream.readline(32).strip() != "1":
                    break
        report = {"mode": "game-prefix-initialization-result", "scope": SCOPE, "tool_version": VERSION, "initialization": outcome,
                  "planned_scope": preview, "prefix_created": plan.compatdata.exists(), "wine_launch_attempted": True,
                  "binding_written": False, "dependencies_installed": False, "preparation_complete": False,
                  "writes": [{"scope": "new-game-prefix", "path": str(plan.compatdata)},
                             {"scope": "new-private-work-home", "path": str(plan.trial.work.parent)},
                             {"scope": "private-journal-and-locks", "path": str(management)},
                             {"scope": "cooperative-settings-lock-only", "path": str(settings / "lock")}]}
    except (OSError, ValueError, TypeError, KeyError) as error:
        from preparation_dependency_install import describe_error
        report = {"mode": "game-prefix-initialization-result", "scope": SCOPE, "tool_version": VERSION, "stage": stage,
                  **describe_error(error, stage), "preparation_complete": False,
                  "writes": [] if not started else [{"scope": "partial-game-prefix-preserve-and-inspect"}]}
        if session is not None:
            report["initialization"] = dict(session.record)
        print("検査停止: " + selection._text(report["check"]) + " / " + selection._text(report["reason"] or report["error_class"]),
              file=output)
        print("新規prefixの初期化は停止しました。作成物を削除せず、結果を保存します。", file=output)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。私有記録と作成物を保持しています。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    print("初期化の状態: " + report.get("initialization", {}).get("status", "stopped-before-result"), file=output)
    return 2, str(saved)



@dataclass(frozen=True)
class GameBindingPlan:
    digest: str
    base: object = field(repr=False)
    profile: dict = field(repr=False)
    dependencies: tuple
    binding: object = field(repr=False)
    blockers: tuple
    recipes: dict = field(repr=False)
    profile_revision_change: object = None
    exe_path_ascii: bool = True
    previous_slots: tuple = ()

    def summary(self):
        return {"scope": "registered-game-target-only-binding", "input_digest": self.digest, "app_id": self.base.record["app_id"],
                "origin": self.base.record["trial_id"], "profile_id": self.profile["profile_id"],
                "profile_revision_change": self.profile_revision_change, "exe_path_ascii": self.exe_path_ascii,
                "tool_runtime_writes": self.base.tool_writes,
                "dependencies": list(self.dependencies), "binding": self.binding.summary(),
                "tool_directory": self.base.customization.directory, "blockers": list(self.blockers),
                "game_launched": False, "authentication_performed": False, "preparation_complete": False, "writes": []}


def _dependency_states(profile, recipes, compatdata, recipe, stop_check, exe, payload=None, previous_slots=()):
    """Live, offline dependency states. A view that is not clear makes every check uninspected."""
    return _observed_dependencies(profile, recipes, compatdata, recipe, stop_check, exe, payload, previous_slots)[0]


def _observed_dependencies(profile, recipes, compatdata, recipe, stop_check, exe, payload=None, previous_slots=()):
    """Dependency states and whether the target was seen stopped before and after the checks.

    The second value is the stopped-process guarantee for binding: with no dependencies there
    is no state to turn ``uninspected``, so callers must require it themselves (design 4.3).

    ``payload`` is (verified inventory, tool directory) of the selected Proton, used by ``prefix-dll``.
    ``previous_slots`` lets the x86 layout check accept a link into another tool-placed slot
    (read-only judgement and the move decision only; design: Proton update 4.4). The layout
    is part of a ``prefix-dll`` state.
    """
    from preparation_dependency_state import inspect_dependency_state
    from preparation_prefix_dll import inspect_prefix_dll
    clear = stop_check.check()["clear_in_view"]
    states = []
    for dependency in profile["dependencies"]:
        item = recipes[dependency]
        # What was checked is part of the state, so the plan digest and the result change with the recipe.
        declared = {"dependency_id": dependency, "recipe_revision": item["revision"], "recipe_digest": digest_json(item)}
        if item["handler"] == "game-folder-file":
            declared["declared_file"] = dict(item["file"])
        if item["handler"] == "prefix-dll":
            declared["declared_asset"] = {key: item["asset"][key] for key in ("filename", "expected_size", "expected_sha256", "pe_machine")}
        if item["status"] != "ready":
            states.append({**declared, "state": "blocked", "reason": item["reason"]})
        elif not clear:
            states.append({**declared, "state": "uninspected", "reason": "target-process-view-not-clear"})
        elif item["handler"] == "game-folder-file":
            states.append({**declared, **inspect_game_folder_file(exe, item["file"])})
        elif item["handler"] == "prefix-dll":
            require(payload is not None, "payload required for a prefix DLL check")
            found = inspect_prefix_dll(compatdata, item, *payload, previous_slots)
            states.append({**declared, **{key: found[key] for key in ("state", "reason", "layout") if key in found}})
        else:
            require(item["handler"] == "softdenchi-interactive", "unsupported ready handler")
            states.append({**declared, "state": inspect_dependency_state(compatdata, recipe)["state"]})
    after = stop_check.check()["clear_in_view"]
    if clear and not after:
        states = [{**item, "state": "uninspected", "reason": "concurrent-process-observed"} if item["state"] != "blocked" else item
                  for item in states]
    return tuple(states), clear and after


def _payload(base):
    from preparation_dependency_install import _tool_directory
    return base.inventory, _tool_directory(base)


def plan_game_binding(*, record, record_sha256, config, directory, renderer, source, games, steam, settings, home,
                      environment, runtime_root, stop_check, recipe=None, inventory=None, previous_slots=(), choice=None):
    """Read-only. Binding is allowed only when every profile dependency is live present-verified.

    ``previous_slots`` and ``choice`` are for moving a game from another preparation slot
    (design: Proton update 4.4, 4.6): the x86 layout may still link into one of those slots,
    and an aligned DroidDeck screen choice is written as it is.
    """
    from preparation_binding import plan_binding
    from preparation_recheck import plan_recheck
    from preparation_softdenchi_recipe import softdenchi_recipe, validate_recipe
    recipe = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
    base = plan_recheck(record=record, record_sha256=record_sha256, config=config, directory=directory, renderer=renderer,
                        source=source, games=games, steam=steam, settings=settings, home=home, environment=environment,
                        runtime_root=runtime_root, records=RECORDS, inventory=inventory)
    profiles, recipes = validate_game_config(config.get("game_preparation"))
    profile = profiles.get(record["profile"]["profile_id"])
    require(profile is not None, "game profile changed since initialization")
    revision_change = profile_revision_change(profile, record["profile"])
    require(isinstance(stop_check, ProcessStopCheck) and stop_check.compatdata == base.compatdata, "matching process observation required")
    exe = base.target.exe
    previous_slots = tuple(safe_path(root) for root in previous_slots)
    dependencies, stopped = _observed_dependencies(profile, recipes, base.compatdata, recipe, stop_check, exe,
                                                   _payload(base), previous_slots)
    blockers = sorted({("dependency-blocked:" if item["state"] == "blocked" else "dependency-not-verified:") + item["dependency_id"]
                       for item in dependencies if item["state"] != "present-verified"} |
                      (set() if stopped else {PROCESS_BLOCKER}))
    binding = plan_binding(steam, settings, record["app_id"], base.customization.directory, choice)
    signature = {"version": VERSION, "base": base.digest, "profile": record["profile"]["profile_digest"],
                 "current_profile": digest_json(profile), "dependencies": list(dependencies), "binding": binding.digest,
                 "blockers": blockers, "previous_slots": [str(root) for root in previous_slots]}
    return GameBindingPlan(digest_json(signature), base, profile, dependencies, binding, tuple(blockers), recipes,
                           revision_change, exe_path_ascii(exe), previous_slots)


def profile_revision_change(profile, recorded):
    """The profile bound at initialization, or a later revision of it pinned to the initialized EXE.

    A later revision is accepted only for the same profile ID with a strictly higher
    revision that pins the EXE hash measured at initialization (still checked live by the
    recheck). Its dependencies are evaluated live at binding, so they need no pinning here;
    the record has no dependency list, so removed dependencies cannot be detected, and title
    and edition are not part of the record either. Menu 11 shows them for the operator.
    """
    current = digest_json(profile)
    if current == recorded["profile_digest"]:
        return None
    require(profile["profile_id"] == recorded["profile_id"] and profile["revision"] > recorded["revision"] and
            profile["exe_sha256"] is not None and profile["exe_sha256"] == recorded["exe_sha256"],
            "game profile changed since initialization")
    return {"initialized_revision": recorded["revision"], "initialized_digest": recorded["profile_digest"],
            "current_revision": profile["revision"], "current_digest": current}


def apply_game_binding(plan, store, refresh, confirmation, stop_check, recipe=None, *, on_binding_id, under_lock=None):
    """Operator-confirmed target-only binding through the guarded internal writer.

    The readiness callback rechecks the registration, the FEX-contract tool tree, the
    prefix identity and version, and every dependency with the stopped view observed
    before and after the inspection, before each file write.
    """
    from preparation_binding import apply_binding
    from preparation_execution import _prefix
    from preparation_payload import runtime_writes, verify_fex_runtime_tree
    from preparation_softdenchi_recipe import softdenchi_recipe, validate_recipe
    recipe = softdenchi_recipe() if recipe is None else validate_recipe(recipe)
    require(isinstance(plan, GameBindingPlan) and confirmation == plan.digest, "exact binding confirmation required")
    require(not plan.blockers, "game binding blocked")
    # The stopped-target guarantee rests on this observation (design: no-SoftDenchi 4.3).
    require(isinstance(stop_check, ProcessStopCheck) and stop_check.compatdata == plan.base.compatdata,
            "matching process observation required")
    require(refresh().digest == plan.digest, "game binding plan changed")
    base = plan.base
    tool = safe_path(base.target.steam / "compatibilitytools.d" / base.customization.directory, base.target.steam)
    # Only SoftDenchi, read-only game-folder checks and prefix DLLs can be ready (validate_game_config); mfc-local stays blocked.
    require(all(item["state"] == "present-verified" for item in plan.dependencies), "dependencies not verified")

    def ready():
        base.target.verify()
        base.runtime.verify()
        require(runtime_writes(verify_fex_runtime_tree(tool, base.inventory, base.customization.overlays)) == base.tool_writes,
                "tool runtime writes changed")
        require_initialized_directories(base.compatdata, base.record)
        require(_prefix(base.compatdata) == base.prefix_version, "game prefix version changed")
        # Same check as planning: an unclear view before or after inspection is never verified.
        # Last step, so the observation is the one closest to the write (design 4.3).
        states, stopped = _observed_dependencies(plan.profile, plan.recipes, base.compatdata, recipe, stop_check,
                                                 base.target.exe, _payload(base), plan.previous_slots)
        require(all(item["state"] == "present-verified" for item in states), "dependency postconditions changed")
        require(stopped, "target process view not clear")
        return {"target": True, "dependencies": True, "payload": True, "stopped": True}
    return apply_binding(plan.binding, base.target.steam, base.settings, store, ready,
                         bundle_directory=base.customization.directory, under_lock=under_lock, on_binding_id=on_binding_id)
