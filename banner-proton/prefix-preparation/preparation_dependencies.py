"""Read-only concrete dependency plans. Execution exists only in the managed-prefix session.

Evidence declarations and submitted postcondition observations are descriptions,
not execution/binding authorization. MFC generation and layout remain separate.
"""

from preparation_assets import (
    asset_blockers,
    digest_json,
    inspect_assets,
    validate_manifest,
)
from preparation_common import HANDLERS, VERSION, Invalid, fields, require
from preparation_softdenchi_recipe import bind_asset, softdenchi_recipe

SOFTDENCHI_CHECKS = ("product-registration-and-version", "installed-files-hashes-pe-versions",
                    "ucmansvc-service-image-and-start-type", "x86-com-registration", "x64-com-registration")
MFC_CHECKS = ("destination-file-hash-pe-version", "verified-wow64-dll-layout", "narrow-native-load-check")
STATES = ("uninspected", "absent", "present-unverified", "present-verified", "partial", "incompatible")


def dependency_plan(handler, spec, inspection, observed_state="uninspected"):
    """Bind one measured asset to a fixed handler without issuing a command."""
    require(handler in HANDLERS, "unsupported dependency handler")
    validate_manifest({"schema_version": 1, "assets": [spec]})
    require(observed_state in STATES, "unknown dependency observation state")
    require(inspection["asset_id"] == spec["asset_id"] and inspection["revision"] == spec["revision"] and
            inspection["spec_digest"] == digest_json(spec), "dependency asset inspection differs")
    blockers = asset_blockers(spec, inspection["measured"])
    recipe_binding = None
    if handler == "softdenchi-interactive":
        try:
            recipe_binding = bind_asset(softdenchi_recipe(), spec, inspection["measured"])
        except Invalid:
            recipe_binding = None
    if recipe_binding is None:
        blockers.append("asset-product-version-and-role-unverified")
    if handler == "softdenchi-interactive":
        require(spec["format"] == "pe" and spec["pe_machine"] == "x86", "x86 setup bootstrap required")
        checks = SOFTDENCHI_CHECKS
        action = {"kind": "interactive-original-bootstrap", "arguments": [], "silent_arguments_inferred": False,
                  "msi_only_bypass": False, "user_license_decision": "required", "inner_product_architecture": "x86_64",
                  "prerequisites": "preserve-original-bootstrap-handling"}
        # The executor and offline postconditions exist only inside the managed-prefix session.
        blockers.append("execution-only-through-managed-prefix-session")
    else:
        require(spec["format"] == "pe" and spec["pe_machine"] == "x86", "x86 MFC asset required")
        checks = MFC_CHECKS
        action = {"kind": "single-mfc42-file-only", "destination": "unresolved-until-payload-and-prefix-architecture-check",
                  "broad-vcrun6-install": False, "msvcrt-or-oleaut32-overrides": False, "mfc140-substitute": False}
        blockers.extend(("prefix-dll-architecture-map-unverified", "native-load-probe-not-connected",
                         "mfc-copy-executor-not-connected"))
    if observed_state in ("partial", "incompatible", "present-unverified"):
        blockers.append("existing-dependency-state-preserve-and-inspect")
    elif observed_state == "present-verified":
        blockers.append("persisted-verified-state-requires-live-reinspection")
    blockers.append("current-managed-prefix-recheck-not-bound")
    signature = {"handler": handler, "recipe_revision": 1, "asset_spec": digest_json(spec),
                 "measured": inspection["measured"], "observed_state": observed_state, "checks": list(checks)}
    return {"schema_version": 1, "tool_version": VERSION, "mode": "dependency-installation-plan", "handler": handler,
            "recipe_revision": 1, "asset_id": spec["asset_id"], "asset_revision": spec["revision"],
            "asset_spec_digest": digest_json(spec), "measured": inspection["measured"], "input_digest": digest_json(signature),
            "asset_evidence": "operator-declared-plus-measured-identity", "recipe_binding": recipe_binding,
            "observed_state": observed_state,
            "planned_operation": action, "required_postconditions": list(checks),
            "automatic_repair": False, "automatic_upgrade": False, "skip_installation_authorized": False,
            "postcondition_observations_authorize_execution": False,
            "blockers": sorted(set(blockers)), "execution_authorized": False, "binding_authorized": False,
            "preparation_complete": False, "writes": []}


def plan_local_dependency(document, root, asset_id, handler):
    specs = validate_manifest(document)
    require(asset_id in specs, "dependency asset not declared")
    selected = {"schema_version": 1, "assets": [specs[asset_id]]}
    measured = inspect_assets(selected, root)[0]
    return dependency_plan(handler, specs[asset_id], measured)


def summarize_postcondition_observations(handler, observations):
    """Describe a full fixed observation set; never accept it as live authority."""
    require(handler in HANDLERS, "unsupported dependency handler")
    expected = SOFTDENCHI_CHECKS if handler == "softdenchi-interactive" else MFC_CHECKS
    fields(observations, expected)
    require(all(value in ("passed", "failed", "uninspected") and type(value) is str for value in observations.values()),
            "invalid postcondition observation")
    failed = [key for key in expected if observations[key] == "failed"]
    missing = [key for key in expected if observations[key] == "uninspected"]
    return {"result": "failed-observations" if failed else "incomplete-observations" if missing else "all-reported-checks-passed",
            "failed": failed, "uninspected": missing, "live_evidence_verified": False,
            "execution_authorized": False, "binding_authorized": False, "preparation_complete": False}
