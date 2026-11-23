"""Read-only composition of payload, expected adoption, runtime and target plans.

No extractor, installer, helper or launch is called here. This plan cannot grant
readiness to the internal writers. Filesystem capacity is an installation-only
estimate, not a bound on Wine/prefix/installer growth.
"""

import os
from dataclasses import dataclass, field

from preparation_assets import digest_json
from preparation_common import Invalid, checked, require, safe_path
from preparation_customization import plan_customizations
from preparation_payload import (
    FEX_RUNTIME_CONTRACT,
    FEX_RUNTIME_DIRECTORY,
    PayloadInventory,
    inspect_archive,
    inspect_archive_from_folder,
    runtime_writes,
    verify_fex_runtime_tree,
    verify_tree,
)
from preparation_runtime_context import plan_runtime_environment
from preparation_target import pin_registration

# "proton" for its CURRENT_PREFIX_VERSION before a game is moved (design: Proton update 4.5).
CAPTURE = ("version", "toolmanifest.vdf", "user_settings.py", "proton")
RESERVE = 64 * 1024**2


def _capacity(destination, inventory, customization, action):
    parent = destination.parent
    while not parent.exists():
        parent = parent.parent
    parent = safe_path(parent)
    require(parent.is_dir(), "installation ancestor must be a directory")
    fs = os.statvfs(parent)
    block = fs.f_frsize or fs.f_bsize
    require(block > 0, "unknown filesystem allocation size")
    rounded = lambda size: ((size + block - 1) // block) * block
    # One staged tree renamed on the same filesystem; count metadata overhead
    # conservatively, plus a fixed reserve. No extraction takes place in planning.
    estimated = (sum(rounded(entry["size"]) if entry["kind"] == "file" else block
                     for entry in inventory.entries.values()) + block +
                 sum(rounded(len(raw)) for raw in customization.files.values()) + RESERVE) if action == "install-new" else 0
    available = fs.f_bavail * block
    return {"scope": "tool-installation-only", "estimated_additional_bytes": estimated,
            "reserve_bytes": RESERVE if estimated else 0, "available_bytes": available,
            "estimate_fits": available >= estimated,
            "prefix_and_dependencies_bytes": None, "total_preparation_capacity_verified": False,
            "write_permission": "unverified"}


@dataclass(frozen=True)
class InstallationPlan:
    digest: str
    report: dict = field(repr=False)
    inventory: object = field(repr=False)
    customization: object = field(repr=False)
    runtime: object = field(repr=False)
    target: object = field(repr=False)
    archive: object = field(repr=False)
    # True when the archive is read from the operator's asset folder (timestamps not compared).
    archive_from_folder: bool = False

    def summary(self):
        # No renderer bytes, runtime values, label contents or raw settings.
        import copy
        return copy.deepcopy(self.report)


def _tree_variants(directory, inventory, archive_name, mode, helper, renderer, label, tool_slot):
    """Strict tree match. Only the dedicated preparation slot also accepts the
    source-reviewed FEX runtime contract (one owned, empty, 0700 AppConfig directory)."""
    matches, observations = [], []
    def verifier(root, tree, overlays):
        # Without the FEX directory the ordinary strict check applies unchanged.
        if tool_slot == "preparation" and os.path.lexists(root / FEX_RUNTIME_DIRECTORY):
            return verify_fex_runtime_tree(root, tree, overlays)
        return verify_tree(root, tree, overlays)
    for mask in (0o022, 0o077):
        candidate = plan_customizations(inventory, archive_name, mode, helper, renderer, label=label, umask=mask, tool_slot=tool_slot)
        try:
            verified = verifier(directory, inventory, candidate.overlays)
        except (OSError, Invalid) as error:
            diagnostic = getattr(error, "tree_diagnostic", {"check": "tree-validation-rejected", "error_class": type(error).__name__,
                                                          "errno": getattr(error, "errno", None)})
            observations.append({"creation_umask": format(mask, "04o"), "tree_matches": False, **diagnostic})
            continue
        observations.append({"creation_umask": format(mask, "04o"), "tree_matches": True,
                             "runtime_writes": runtime_writes(verified)})
        matches.append((mask, candidate))
    return matches, {"directory": directory.name, "strict_match": len(matches) == 1, "variants": observations,
                     "runtime_contract": FEX_RUNTIME_CONTRACT if tool_slot == "preparation" else None,
                     "modified_by_tool": False, "contents_recorded": False, "first_mismatch_only": True}


def plan_installation(*, archive, sha512, archive_root, mode, runtime_root, runtime_audit,
                      registrations, registration_id, exe_root, steam, renderer, parent_environment=None, tool_slot="legacy",
                      archive_from_folder=False, inventory=None):
    """``inventory``: the payload already read once from the asset folder (read-only lists only)."""
    require(mode in ("off", "observe", "cleanup"), "unsupported installation mode")
    steam = safe_path(steam)
    target = checked("target-registration-exe", pin_registration, registrations, registration_id, exe_root, steam)
    if inventory is None:
        read_archive = inspect_archive_from_folder if archive_from_folder else inspect_archive
        inventory = checked("payload-archive", read_archive, archive, sha512, archive_root, capture=CAPTURE)
    else:
        require(isinstance(inventory, PayloadInventory) and archive_from_folder and inventory.archive_sha512 == sha512 and
                inventory.root == archive_root, "payload inventory differs")
    require(inventory.external_links == 0, "external payload links require separate policy")
    runtime = checked("runtime-context", plan_runtime_environment, runtime_root, runtime_audit, parent_environment)
    helper = runtime.root / "usr/local/bin/steam-compatibility"
    customization = checked("expected-customizations", plan_customizations, inventory, safe_path(archive).name, mode, helper, renderer,
                                        label=runtime.label, umask=int(runtime.umask, 8), tool_slot=tool_slot)
    destination = safe_path(steam / "compatibilitytools.d" / customization.directory, steam)
    # A game executable/install directory must never be inside the tool tree,
    # and the tree must never be installed inside that game's directory.
    require(not target.exe.is_relative_to(destination) and not destination.is_relative_to(target.exe.parent),
            "tool and game paths overlap")
    action, reused_mask, tool_writes = "install-new", None, None
    if destination.exists():
        require(destination.is_dir(), "installation destination must be a directory")
        # The old installer did not record its creation mask. Accept only these
        # two generator-backed variants; never measure a file into expectations.
        matches, observation = _tree_variants(destination, inventory, safe_path(archive).name, mode, helper, renderer, runtime.label, tool_slot)
        if len(matches) != 1:
            error = Invalid("existing installation differs from approved generated trees")
            error.installed_tree_diagnostic = observation
            raise error
        mask, customization = matches[0]
        reused_mask, action = format(mask, "04o"), "reuse-verified-tree"
        tool_writes = next(item.get("runtime_writes") for item in observation["variants"] if item["tree_matches"])
    legacy_observation = None
    if tool_slot == "preparation":
        legacy = plan_customizations(inventory, safe_path(archive).name, mode, helper, renderer,
                                     label=runtime.label, umask=int(runtime.umask, 8))
        legacy_path = steam / "compatibilitytools.d" / legacy.directory
        if os.path.lexists(legacy_path):
            _, legacy_observation = _tree_variants(legacy_path, inventory, safe_path(archive).name, mode, helper, renderer, runtime.label, "legacy")
    base = safe_path(steam / "steamapps/compatdata", steam)
    require(not base.exists() or base.is_dir(), "compatdata parent must be a directory")
    key = int(target.registration_id)
    names = [str(key)] + ([str(key - 2**32)] if key >= 2**31 else [])
    # Any existing entry, including a partial prefix, blocks initialization.
    existing = [name for name in names if os.path.lexists(base / name)]
    require(len(existing) <= 1, "ambiguous signed/unsigned prefix candidates")
    for name in existing:
        require(safe_path(base / name, steam).is_dir(), "existing prefix entry is not a directory")
    prefix = {"compatdata": str(base / (existing[0] if existing else names[0])),
              "exists": bool(existing), "action": "preserve-existing" if existing else "initialize-new-blocked"}
    capacity = _capacity(destination, inventory, customization, action)
    blockers = ["payload-provenance-unreviewed", "registration-export-freshness-unverified",
                "process-stop-scope-unverified", "gui-connection-unverified", "runtime-equivalence-unverified",
                "prefix-and-dependencies-capacity-unverified", "dependencies-not-executable", "installation-writer-not-exposed"]
    if existing:
        blockers.append("existing-prefix-preserve")
    if runtime.view != "current-root":
        blockers.append("runtime-snapshot-cannot-authorize-execution")
    if not capacity["estimate_fits"]:
        blockers.append("insufficient-estimated-installation-capacity")
    signature = {"inventory": inventory.digest, "archive_sha512": sha512, "customization": customization.digest,
                 "runtime": runtime.identity_digest, "target": target.digest, "destination": str(destination),
                 "action": action, "prefix": prefix, "mode": mode, "tool_slot": tool_slot, "tool_runtime_writes": tool_writes}
    digest = digest_json(signature)
    # Recheck mutable identity inputs before publishing a composed report.
    target.verify()
    runtime.verify(parent_environment)
    report = {"input_digest": digest, "action": action, "destination": str(destination), "mode": mode, "tool_slot": tool_slot,
              "legacy_tool_observation": legacy_observation, "tool_runtime_writes": tool_writes,
              "reused_creation_umask": reused_mask, "payload": inventory.summary(),
              "customization": customization.summary(), "runtime": runtime.summary(),
              "target_pin_digest": target.digest, "prefix": prefix, "capacity": capacity,
              "planned_writes": [] if action == "reuse-verified-tree" else [
                  {"path": str(destination.parent / ".prefix-preparation-staging-<random>"), "action": "create-private-staged-tree"},
                  {"path": str(destination), "action": "publish-new-tree-without-replacement"}],
              "binding": "deferred-until-dependencies-verified", "blockers": blockers,
              "preparation_complete": False, "writes": []}
    return InstallationPlan(digest, report, inventory, customization, runtime, target, safe_path(archive), archive_from_folder)
