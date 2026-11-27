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
    require,
    safe_path,
)
from preparation_installation import InstallationPlan
from preparation_payload import verify_tree
from preparation_slot_manifest import save_after_verification
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
    # An ordinary registered game, only read (design: operational entry 4); the dedicated probe
    # registration that earlier versions could use instead was removed in 1.0.1.
    confirmation: dict = field(repr=False)
    store_root: object = field(repr=False)
    settings: object = field(repr=False)

    def summary(self):
        summary = self.installation.summary()
        return {"mode": "static-preparation-tool-plan", "input_digest": self.digest, "scope": "static-preparation-slot-only",
                "action": summary["action"], "destination": summary["destination"], "capacity": summary["capacity"],
                "review": dict(self.review), "confirmation_registration": dict(self.confirmation),
                "planned_writes": summary["planned_writes"] + ([] if summary["action"] == "reuse-verified-tree" else [
                    {"path": str(self.store_root), "action": "private-installation-journal-and-locks"},
                    {"path": str(self.settings / "lock"), "action": "cooperative-settings-lock-only"}]),
                "private_xalia_context": {"reviewed_files": len(self.review.get("private_xalia_files", [])),
                                          "required_tool_parent_mode": "0700" if self.review.get("private_xalia_files") else None,
                                          "payload_modes_changed": False},
                "execution_authorized": False, "prefix_initialization_authorized": False, "binding_authorized": False,
                "full_preparation_blockers": [x for x in summary["blockers"] if x != "payload-provenance-unreviewed"],
                "preparation_complete": False, "writes": []}


def _signature(installation, review, confirmation, store_root, settings):
    report = installation.summary()
    fixed = {name: report[name] for name in ("action", "destination", "mode", "tool_slot", "prefix")}
    fixed["capacity"] = {name: report["capacity"][name] for name in ("scope", "estimated_additional_bytes", "reserve_bytes")}
    return digest_json({"tool_version": VERSION, "scope": "static-preparation-slot-only", "installation": installation.digest,
                       "fixed_plan": fixed,
                       "review": review, "confirmation": confirmation, "store": str(store_root), "settings": str(settings)})


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
    from preparation_target import registrations
    target = installation.target
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


def plan_confirmed_placement(installation, review, store_root, settings):
    """Placement of the bundle slot, confirmed by an ordinary registered game that is only read."""
    return _plan_placement(installation, review, store_root, settings)


MANIFEST_TEXT = {
    "created": "このProtonの照合情報を保存しました（あとでこのProtonへ戻せるようにするため）。",
    "same": "このProtonの照合情報は保存済みです。",
    "mismatch": "保存済みの照合情報が今の中身と違うため、書き換えていません。このProtonへはツールでは戻せません。",
    "broken": "保存済みの照合情報が読めないため、書き換えていません。このProtonへはツールでは戻せません。",
    "rules-differ": "保存済みの照合情報は照合規則の版が違うため、書き換えていません。このProtonへはツールでは戻せません。",
    "failed": "照合情報を保存できませんでした。配置はそのままです。このProtonへはツールでは戻せません。",
}


def _plan_placement(installation, review, store_root, settings):
    require(isinstance(installation, InstallationPlan), "trusted installation plan required")
    review = copy.deepcopy(validate_build_review(review))
    store_root, settings = safe_path(store_root), safe_path(settings)
    report = installation.summary()
    require(report["tool_slot"] == "preparation" and installation.customization.summary()["tool_slot"] == "preparation" and
            installation.inventory.archive_sha512 == review["archive_sha512"] and report["payload"]["archive_sha512"] == review["archive_sha512"],
            "reviewed preparation slot required")
    require(settings.is_dir(), "existing settings directory required")
    steam = safe_path(installation.target.steam)
    expected_destination = safe_path(steam / "compatibilitytools.d" / installation.customization.directory, steam)
    require(report["destination"] == str(expected_destination), "placement destination differs from generated slot")
    require(steam != settings and not steam.is_relative_to(settings) and not settings.is_relative_to(steam), "settings overlap Steam")
    for root in (steam, settings, installation.target.exe.parent):
        require(not (store_root == root or store_root.is_relative_to(root) or root.is_relative_to(store_root)), "placement store overlaps inputs")
    if installation.runtime.view != "current-root":
        require(all(path != installation.runtime.root and path.is_relative_to(installation.runtime.root) for path in
                    (steam, settings, store_root, safe_path(installation.target.source), installation.target.exe)),
                "snapshot placement must remain inside snapshot")
    else:
        require(str(installation.runtime.root) == "/", "live root required")
    _private_xalia_context(installation, review)
    confirmation = _confirmation(installation, settings, store_root)
    require(confirmation["source_archive_sha512"] == review["archive_sha512"] and
            confirmation["source_inventory_digest"] == installation.inventory.digest, "confirmation and placement archive identities differ")
    installation.target.verify()
    installation.runtime.verify()
    digest = _signature(installation, review, confirmation, store_root, settings)
    return StaticPlacementPlan(digest, installation, review, confirmation, store_root, settings)


def _same_plan(current, expected):
    if not isinstance(current, StaticPlacementPlan):
        return False
    a, b = current.installation, expected.installation
    return (current.digest == expected.digest and current.review == expected.review and current.confirmation == expected.confirmation and
            current.store_root == expected.store_root and
            current.settings == expected.settings and a.digest == b.digest and a.target == b.target and
            a.inventory == b.inventory and a.customization == b.customization and a.runtime.identity_digest == b.runtime.identity_digest and
            a.archive == b.archive)


def apply_static_placement(plan, refresh, store, confirmed_digest):
    """Only this narrow operation can omit launch readiness; it cannot launch."""
    require(isinstance(plan, StaticPlacementPlan) and callable(refresh), "trusted static placement plan required")
    store._guard()
    require(confirmed_digest == plan.digest and plan.digest == _signature(plan.installation, plan.review, plan.confirmation,
            plan.store_root, plan.settings), "exact placement confirmation required")
    installation = plan.installation
    private_xalia = _private_xalia_context(installation, plan.review)
    compatdata = safe_path(installation.target.steam / "steamapps/compatdata" / installation.target.registration_id,
                          installation.target.steam)
    require(store.root == plan.store_root and store._held_target == hashlib.sha256(str(compatdata).encode()).hexdigest(),
            "matching placement locks required")
    fresh = refresh()
    require(_same_plan(fresh, plan), "static placement plan changed")
    if installation.summary()["action"] == "reuse-verified-tree":
        # The slot was verified against this payload by the refreshed plan (design: Proton update 4.7).
        return {**plan.summary(), "mode": "static-matching-tool-observed", "material_installed_now": False,
                "slot_manifest": save_after_verification(store, installation)}
    require(fresh.installation.summary()["capacity"]["estimate_fits"], "insufficient static placement capacity")
    require(not os.path.lexists(safe_path(installation.summary()["destination"])), "new slot must be absent")

    def ready(published=False):
        store._guard()
        if private_xalia is not None and private_xalia.parent.exists():
            private_xalia.guard()
        require(_confirmation(installation, plan.settings, plan.store_root) == plan.confirmation,
                "placement confirmation changed")
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
            "confirmation_registration": plan.confirmation, "material_installed_now": True,
            "private_xalia_context": plan.summary()["private_xalia_context"],
            "writes": [{"path": installation.summary()["destination"], "scope": "new-static-preparation-tool-tree"},
                       {"path": str(store.root), "scope": "private-installation-journal-and-locks"},
                       {"path": str(plan.settings / "lock"), "scope": "cooperative-settings-lock-only"}],
            "prefix_created": False, "binding_written": False, "wine_executed": False,
            "execution_authorized": False, "preparation_complete": False,
            "slot_manifest": save_after_verification(store, installation)}


def _confirmation_candidates(games, steam, settings, management):
    """(selectable, excluded) registrations for the operational placement; excluded ones carry a reason."""
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
