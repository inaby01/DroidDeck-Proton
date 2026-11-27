"""The managed recheck of a registered-game prefix: the checks every later step repeats.

It verifies the initialization record, the registration and game EXE, the slot tree, the
runtime and the prefix. It runs nothing itself (the probe recheck command was removed in 1.0.1).
FEX's one empty private directory is a separate, source-reviewed runtime contract, never a
general extra-file allowance.
"""

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import digest_json
from preparation_binding import _raw
from preparation_common import VERSION, require, safe_path
from preparation_customization import plan_customizations
from preparation_execution import _aliases, _prefix
from preparation_installation import CAPTURE
from preparation_payload import (
    FEX_RUNTIME_CONTRACT,
    PayloadInventory,
    inspect_archive_from_folder,
    runtime_writes,
    verify_fex_runtime_tree,
)
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
    # Journal of the origin record: registered-game new prefixes.
    records: str = "game-prefixes"
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
                  environment, runtime_root, records="game-prefixes", inventory=None):
    require(records == "game-prefixes", "unknown managed prefix journal")
    key = _game_record(record, games)
    steam, settings, home = map(safe_path, (steam, settings, home))
    store_root = safe_path(home / ".local/state/droiddeck-prefix-preparation/tool-store", home)
    with PrivateStore(store_root) as store:
        require(store.read_record(records, record["trial_id"] + ".json")[1] == record_sha256, "trial record changed")
    target, exe = _game_registration(progress, record, source, games, steam)
    progress.append("recheck-build-review")
    payload = config["payload"]
    require(payload.get("tool_slot") == "preparation", "reviewed preparation slot required")
    review = validate_build_review(config["placement_review"])
    require(review["archive_sha512"] == payload["sha512"], "recheck source identity differs")
    progress.append("recheck-payload-archive")
    from preparation_selection import _archive
    # The archive is read from the operator's asset folder without comparing timestamps (every byte is hashed).
    if inventory is None:
        inventory = inspect_archive_from_folder(_archive(directory, payload), payload["sha512"], payload["root"], capture=CAPTURE)
    else:
        # The status check reads the archive once with read_payload_inventory (operational entry 6.2).
        require(isinstance(inventory, PayloadInventory) and inventory.archive_sha512 == payload["sha512"] and
                inventory.root == payload["root"], "payload inventory differs")
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
    compatdata, version = _game_prefix(progress, steam, key, record)
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
    return RecheckPlan(digest_json(signature), record, record_sha256, store_root, inventory, custom,
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
    # The registration read now must still name the EXE of the given catalog (it may have changed since).
    require(target.exe == exe, "game registration EXE changed")
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


class RecheckSession:
    """The guard of a managed recheck plan, repeated by every later step right before it acts."""

    def __init__(self, plan, store, stop_check):
        require(isinstance(plan, RecheckPlan), "trusted managed recheck plan required")
        self.plan, self.store, self.stop = plan, store, stop_check
        self.settings_identity = _settings(plan.target.steam, plan.settings)

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
        _initialized_prefix(p.compatdata, p.record, p.prefix_version)
        require(_settings(p.target.steam, p.settings) == self.settings_identity, "settings changed during recheck")
        require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
        for path in (p.work, p.private_home):
            _private_existing(path, p.work.parents[4])
