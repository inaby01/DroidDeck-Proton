#!/usr/bin/env python3
"""Offline inspection, blocked plans and private local staging (no prefix executor)."""

import argparse
import hashlib
import itertools
import json
import re
import runpy
import sys
import unicodedata
from pathlib import Path

# -I excludes script paths; add only the trusted distribution directory, never CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from preparation_assets import exe_identity, inspect_assets
from preparation_binding import plan_binding
from preparation_common import (
    HANDLERS,
    MAX_DEPENDENCIES,
    MAX_DEPTH,
    MAX_REPORT,
    MAX_STRING,
    SHA256,
    VERSION,
    Invalid,
    app_id,
    fields,
    identifier,
    load_json,
    read_bytes,
    require,
    revision,
    safe_path,
    string,
    unchanged,
)
from preparation_dependencies import plan_local_dependency
from preparation_installation import plan_installation
from preparation_payload import inspect_archive, verify_tree
from preparation_preflight import inspect_preflight, preflight_script
from preparation_runtime import inspect_runtime, runtime_audit_command
from preparation_selection import interactive_selection, selection_script
from preparation_store import PrivateStore, stage_local
from preparation_target import registrations
from preparation_vdf import parse_vdf

__all__ = ["Invalid", "unchanged"]


def unique_ids(values):
    require(type(values) is list and len(values) <= MAX_DEPENDENCIES, "invalid dependency list")
    for value in values:
        identifier(value)
    require(len(set(values)) == len(values), "duplicate dependency ID")


def validate_profile(profile):
    fields(profile, ("schema_version", "profile_id", "revision", "title", "edition", "edition_status",
                     "droiddeck_versions", "proton_versions", "dependencies", "evidence", "exe_sha256"))
    require(type(profile["schema_version"]) is int and profile["schema_version"] == 1, "unknown profile schema")
    identifier(profile["profile_id"])
    revision(profile["revision"])
    for name in ("title", "edition"):
        string(profile[name])
    require(profile["edition_status"] in ("unconfirmed", "confirmed"), "invalid edition status")
    for name in ("droiddeck_versions", "proton_versions", "evidence"):
        require(type(profile[name]) is list and 0 < len(profile[name]) <= 128, "invalid profile list")
        for value in profile[name]:
            string(value)
    unique_ids(profile["dependencies"])
    digest = profile["exe_sha256"]
    require(digest is None or type(digest) is str and SHA256.fullmatch(digest), "invalid expected EXE hash")
    return profile


def validate_recipes(document):
    fields(document, ("schema_version", "dependencies"))
    require(type(document["schema_version"]) is int and document["schema_version"] == 1, "unknown recipe schema")
    entries = document["dependencies"]
    require(type(entries) is list and len(entries) <= MAX_DEPENDENCIES, "too many dependencies")
    recipes = {}
    for entry in entries:
        fields(entry, ("dependency_id", "revision", "handler", "requires", "status", "reason"))
        key = identifier(entry["dependency_id"])
        require(key not in recipes, "duplicate recipe")
        revision(entry["revision"])
        require(entry["handler"] in HANDLERS, "unknown handler")
        unique_ids(entry["requires"])
        # Until assets and postconditions are concrete, no executable recipe is accepted.
        require(entry["status"] == "blocked", "only blocked recipes supported in this stage")
        string(entry["reason"])
        recipes[key] = entry

    depths = {}
    visiting = set()

    def visit(key):
        require(key in recipes, "unknown dependency")
        require(key not in visiting, "dependency cycle")
        if key in depths:
            return depths[key]
        require(len(visiting) < MAX_DEPTH, "dependency graph too deep")
        visiting.add(key)
        depth = 1 + max((visit(child) for child in recipes[key]["requires"]), default=0)
        visiting.remove(key)
        require(depth <= MAX_DEPTH, "dependency graph too deep")
        depths[key] = depth
        return depth

    for key in recipes:
        visit(key)
    return recipes


def dependency_order(profile, recipes):
    result = []

    def visit(key):
        require(key in recipes, "profile references unknown dependency")
        if key not in result:
            for child in recipes[key]["requires"]:
                visit(child)
            result.append(key)

    for key in profile["dependencies"]:
        visit(key)
    return result


def prefix_info(steam, key):
    base = safe_path(steam / "steamapps/compatdata", steam)
    candidates = []
    if base.exists():
        require(base.is_dir(), "compatdata parent is not a directory")
        names = list(itertools.islice(base.iterdir(), 4097))
        require(len(names) <= 4096, "too many prefix entries")
        for item in names:
            if re.fullmatch(r"-?[0-9]{1,10}", item.name) and int(item.name) % 2**32 == int(key):
                require(app_id(item.name) == key, "noncanonical prefix alias")
                safe_path(item, base)
                require(item.is_dir(), "prefix candidate is not a directory")
                candidates.append(item)
    require(len(candidates) <= 1, "ambiguous signed/unsigned prefix candidates")
    path = candidates[0] if candidates else base / key
    pfx = safe_path(path / "pfx", steam)
    require(not pfx.exists() or pfx.is_dir(), "pfx is not a directory")
    version = safe_path(path / "version", steam)
    return {"compatdata": str(path), "exists": bool(candidates), "pfx_exists": pfx.exists(),
            "version": read_bytes(version, MAX_STRING).decode("utf-8").strip() if version.exists() else None,
            "dependencies": "uninspected", "fonts": "uninspected"}


def selection_info(steam, settings, key):
    result = {"ui_choice": None, "steam_game_tool": None, "steam_default_tool": None,
              "payload": "uninspected", "wrapper": "uninspected", "synchronization": "uninspected"}
    fingerprints = {}
    games = safe_path(settings / "games.json", settings)
    if games.exists():
        data, fingerprints["games"] = load_json(games)
        fields(data, ("version", "games"))
        require(type(data["version"]) is int and data["version"] == 1 and type(data["games"]) is dict,
                "unknown game choices format")
        # Deliberately project only known choice fields; never print raw settings.
        choice = data["games"].get(key)
        if choice is not None:
            fields(choice, ("valve", "dir"))
            require(type(choice["valve"]) is bool, "invalid tool kind")
            name = string(choice["dir"])
            require(Path(name).name == name and name not in (".", ".."), "invalid tool directory")
            result["ui_choice"] = {"valve": choice["valve"], "dir": name}
    config = safe_path(steam / "config/config.vdf", steam)
    if config.exists():
        raw = read_bytes(config)
        fingerprints["config"] = hashlib.sha256(raw).hexdigest()
        data = parse_vdf(raw)
        for name in ("InstallConfigStore", "Software", "Valve", "Steam"):
            require(type(data) is dict and name in data, "missing Steam VDF block")
            data = data[name]
        require(type(data) is dict, "invalid Steam VDF block")
        mapping = data.get("CompatToolMapping", {})
        require(type(mapping) is dict, "invalid tool mapping")
        for app, output in ((key, "steam_game_tool"), ("0", "steam_default_tool")):
            if app in mapping:
                require(type(mapping[app]) is dict and type(mapping[app].get("name")) is str, "invalid tool mapping entry")
                result[output] = mapping[app]["name"]
    return result, fingerprints


def build_report(args):
    steam = safe_path(args.steam_root)
    settings = safe_path(args.settings_root)
    added, added_hash = load_json(args.registrations)
    games = registrations(added)
    report = {"schema_version": 1, "tool_version": VERSION, "mode": "plan" if args.plan else "inspect",
              "writes": [], "blockers": ["execution-not-implemented"], "uninspected": [
                  "running-processes", "free-space", "asset-provenance-and-hashes", "dependency-postconditions",
                  "payload-integrity", "synchronization-impact", "normal-launch-binding"],
              "input_hashes": {"registrations": added_hash}, "games": list(games.values())}
    assets = getattr(args, "assets", None)
    asset_root = getattr(args, "asset_root", None)
    if assets is not None:
        require(asset_root is not None, "--asset-root required with --assets")
        document, manifest_hash = load_json(assets)
        report["assets"] = inspect_assets(document, asset_root)
        report["input_hashes"]["assets"] = manifest_hash
        report["uninspected"].remove("asset-provenance-and-hashes")
        report["uninspected"].append("asset-evidence-authenticity-and-recipe-binding")
        report["blockers"].append("assets-not-bound-to-executable-recipes")
        for asset in report["assets"]:
            report["blockers"].extend("asset:" + asset["asset_id"] + ":" + reason for reason in asset["blockers"])
    else:
        require(asset_root is None, "--asset-root requires --assets")
    tool_directory = getattr(args, "tool_directory", None)
    require(tool_directory is None or args.app_id is not None, "select a registration before a binding tool")
    if args.app_id is None:
        require(args.profile is None and args.recipes is None, "select --app-id before choosing a profile")
        report["blockers"].append("select-registration-id")
        return report
    key = app_id(args.app_id)
    require(key in games, "registration ID not found")
    require(args.exe_root is not None, "--exe-root required for selected registration")
    exe_root = safe_path(args.exe_root)
    require(exe_root != Path("/"), "EXE root must be narrower than filesystem root")
    game = games[key]
    exe = safe_path(game["exe"], exe_root)
    identity = exe_identity(exe)
    selection, hashes = selection_info(steam, settings, key)
    report.pop("games")
    report.update(target={**game, "identity": identity}, prefix=prefix_info(steam, key), selection=selection)
    report["input_hashes"].update(hashes)
    if tool_directory is None:
        report["blockers"].append("synchronization-impact-uninspected")
    else:
        binding = plan_binding(steam, settings, key, tool_directory).summary()
        report["binding_plan"] = binding
        report["selection"]["synchronization"] = "target-only-planned-not-applied"
        report["selection"]["wrapper"] = "present-unverified"
        report["input_hashes"]["binding"] = binding["input_digest"]
        report["blockers"].extend(binding["blockers"])
        report["uninspected"].remove("synchronization-impact")
        report["uninspected"].append("tool-registration-and-normal-launch-verification")
    if report["prefix"]["exists"]:
        report["blockers"].append("existing-prefix-read-only")
    if args.profile is None:
        require(args.recipes is None, "--recipes requires --profile")
        report["blockers"].append("profile-not-selected")
    else:
        require(args.recipes is not None, "--recipes required with --profile")
        profile, profile_hash = load_json(args.profile)
        recipes, recipes_hash = load_json(args.recipes)
        validate_profile(profile)
        recipes = validate_recipes(recipes)
        order = dependency_order(profile, recipes)
        report["profile"] = {name: profile[name] for name in ("profile_id", "revision", "title", "edition", "edition_status")}
        report["input_hashes"].update(profile=profile_hash, recipes=recipes_hash)
        report["dependencies"] = [{**recipes[key], "inspection": "uninspected"} for key in order]
        report["blockers"].extend("recipe-blocked:" + key for key in order)
        if profile["edition_status"] != "confirmed":
            report["blockers"].append("edition-unconfirmed")
        if profile["exe_sha256"] is None:
            report["blockers"].append("exe-known-hash-unavailable")
        elif identity["sha256"] != profile["exe_sha256"]:
            report["blockers"].append("exe-hash-mismatch")
        # Declared versions are useful constraints, never proof of installed payload identity.
        report["compatibility"] = {"status": "unverified", "droiddeck": args.droiddeck_version,
                                   "proton": args.proton_version, "version_source": "operator-declared"}
        for value, allowed, name in ((args.droiddeck_version, profile["droiddeck_versions"], "droiddeck"),
                                     (args.proton_version, profile["proton_versions"], "proton")):
            if value not in allowed:
                report["blockers"].append(name + "-version-unknown-or-incompatible")
        report["blockers"].append("compatibility-unverified")
    report["input_digest"] = hashlib.sha256(json.dumps(
        {"hashes": report["input_hashes"], "target": report["target"], "prefix": report["prefix"],
         "selection": selection, "compatibility": report.get("compatibility"), "assets": report.get("assets")}, sort_keys=True).encode()).hexdigest()
    if args.plan:
        report["proposed_steps"] = [
            {"step": "proton-add-or-reuse", "status": "uninspected"},
            {"step": "prefix-initialize" if not report["prefix"]["exists"] else "existing-prefix-preserve", "status": "blocked"},
            {"step": "dependencies", "status": "blocked"},
            {"step": "binding-and-sync", "status": "blocked"}]
    return report


def display(value):
    # JSON escapes C0/newlines; also escape bidi/format controls before terminal display.
    rendered = json.dumps(value, ensure_ascii=False, indent=2)
    rendered = "".join(f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") and char != "\n"
                   or char in "\u2028\u2029" else char for char in rendered)
    require(len(rendered.encode("utf-8")) <= MAX_REPORT, "report exceeds display limit")
    return rendered


def _installer_renderer():
    parent = Path(__file__).resolve().parent.parent
    installer = parent / "install-softdenchi.py"
    if not installer.exists():
        installer = parent / "banner-proton/install-softdenchi.py"
    return runpy.run_path(str(installer))["render_installation"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--inspect", action="store_true")
    mode.add_argument("--select-plan", action="store_true", help="select a registration and save a blocked plan only")
    mode.add_argument("--emit-selection-script", action="store_true", help="emit short user launcher; optional confirmed registration material")
    mode.add_argument("--inspect-preflight", action="store_true", help="inspect paths/runtime; optionally probe private temporary capabilities")
    mode.add_argument("--emit-preflight-script", action="store_true", help="emit a standalone preflight script without running probes")
    mode.add_argument("--emit-runtime-audit", action="store_true", help="print a pasteable read-only runtime audit command")
    mode.add_argument("--inspect-runtime", action="store_true", help="read-only runtime source/library/socket inventory")
    mode.add_argument("--inspect-payload", action="store_true", help="read-only archive and optional installed-tree identity check")
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--plan-dependency", action="store_true", help="read-only measured asset and concrete dependency plan")
    mode.add_argument("--plan-preparation", action="store_true", help="compose read-only installation/reuse, runtime and target plans")
    mode.add_argument("--stage-local", action="store_true", help="cache assets and pause private state; never prepare a prefix")
    mode.add_argument("--list-local", action="store_true", help="read private cache/run inventory")
    parser.add_argument("--registrations", type=Path, help="DroidDeck added-games JSON, explicit input only")
    parser.add_argument("--steam-root", type=Path)
    parser.add_argument("--settings-root", type=Path)
    parser.add_argument("--exe-root", type=Path)
    parser.add_argument("--app-id")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--recipes", type=Path)
    parser.add_argument("--droiddeck-version")
    parser.add_argument("--proton-version")
    parser.add_argument("--dependency-handler", choices=sorted(HANDLERS))
    parser.add_argument("--dependency-asset")
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--asset-root", type=Path)
    parser.add_argument("--tool-directory", help="plan target-only binding to an already registered custom tool")
    parser.add_argument("--management-root", type=Path)
    parser.add_argument("--resume-run")
    parser.add_argument("--payload-archive", type=Path)
    parser.add_argument("--payload-sha512")
    parser.add_argument("--payload-root")
    parser.add_argument("--payload-directory", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--runtime-audit", type=Path)
    parser.add_argument("--probe-temporary", action="store_true", help="opt into temporary/native/GUI probes in preflight mode only")
    parser.add_argument("--installation-mode", choices=("cleanup",))
    parser.add_argument("--selection-config", type=Path)
    parser.add_argument("--script-entry", choices=("prepare", "status", "diagnose", "recovery"),
                        help="which script --emit-selection-script writes (1.0.0)")
    parser.add_argument("--selection-directory", type=Path)
    args = parser.parse_args()
    try:
        require(args.select_plan or args.emit_selection_script or args.selection_config is None, "selection config requires selection mode")
        require(args.emit_selection_script or args.script_entry is None, "script entry requires script emission")
        require(args.select_plan or args.selection_directory is None, "selection directory requires selection mode")
        require(args.inspect_preflight or not args.probe_temporary, "temporary probes require preflight mode")
        require(args.plan_preparation or not any((args.runtime_audit, args.installation_mode)),
                "runtime audit and installation mode require composed planning")
        require(args.plan_dependency or not (args.dependency_handler or args.dependency_asset),
                "dependency options require dependency planning")
        if args.plan_dependency:
            allowed = {"plan_dependency", "assets", "asset_root", "dependency_handler", "dependency_asset"}
            require(not any(value for key, value in vars(args).items() if key not in allowed), "dependency planning is a separate mode")
            require(all((args.assets, args.asset_root, args.dependency_handler, args.dependency_asset)), "dependency planning inputs required")
            result = plan_local_dependency(load_json(args.assets)[0], args.asset_root, args.dependency_asset, args.dependency_handler)
        elif args.select_plan or args.emit_selection_script:
            allowed = {"select_plan", "emit_selection_script", "selection_config", "selection_directory", "script_entry"}
            require(not any(value for key, value in vars(args).items() if key not in allowed), "selection is a separate mode")
            config = load_json(args.selection_config)[0] if args.selection_config is not None else None
            if args.emit_selection_script:
                print(selection_script(config, args.script_entry or "prepare"), end="")
                return 0
            status, _ = interactive_selection(args.selection_directory or Path.cwd(), _installer_renderer(), config)
            return status
        elif args.emit_preflight_script:
            require(not any(value for key, value in vars(args).items() if key != "emit_preflight_script"), "preflight emitter accepts no inputs")
            print(preflight_script(), end="")
            return 0
        elif args.inspect_preflight:
            allowed = {"inspect_preflight", "steam_root", "settings_root", "probe_temporary"}
            require(not any(value for key, value in vars(args).items() if key not in allowed), "preflight is a separate mode")
            result = inspect_preflight(args.steam_root or Path.home() / ".local/share/Steam",
                                       args.settings_root or Path.home() / ".local/share/droiddeck-compat", args.probe_temporary)
        elif args.emit_runtime_audit:
            require(not any(value for key,value in vars(args).items() if key != "emit_runtime_audit"), "audit emitter accepts no inputs")
            print(runtime_audit_command(),end="")
            return 0
        elif args.inspect_runtime:
            allowed = {"inspect_runtime","runtime_root"}
            require(args.runtime_root is not None and not any(value for key,value in vars(args).items() if key not in allowed),
                    "runtime inspection requires only an explicit root")
            result = {"tool_version":VERSION, **inspect_runtime(args.runtime_root)}
        elif args.plan_preparation:
            require(not any((args.management_root, args.resume_run, args.payload_directory, args.tool_directory)),
                    "composed planning cannot use store or installed-tree overrides")
            require(all(value is not None for value in (args.payload_archive, args.payload_sha512, args.payload_root,
                        args.runtime_root, args.runtime_audit, args.installation_mode, args.registrations,
                        args.steam_root, args.settings_root, args.exe_root, args.app_id)), "composed planning inputs required")
            audit, audit_digest = load_json(args.runtime_audit)
            # Only the trusted distributed installer is loaded, never the inspected
            # runtime helper or archive Python. Support the allowlisted test layout.
            renderer = _installer_renderer()
            installation = plan_installation(archive=args.payload_archive, sha512=args.payload_sha512,
                archive_root=args.payload_root, mode=args.installation_mode, runtime_root=args.runtime_root,
                runtime_audit=audit, registrations=args.registrations, registration_id=args.app_id,
                exe_root=args.exe_root, steam=args.steam_root, renderer=renderer)
            summary = installation.summary()
            if summary["action"] == "reuse-verified-tree":
                args.tool_directory = installation.customization.directory
            result = build_report(args)
            installation.target.verify()
            installation.runtime.verify()
            result.update(mode="plan-preparation", installation_plan=summary)
            result["uninspected"].remove("payload-integrity")
            result["uninspected"].remove("free-space")
            result["uninspected"].append("prefix-and-dependencies-capacity")
            reused = summary["action"] == "reuse-verified-tree"
            result["selection"]["payload"] = "verified-expected-tree" if reused else "not-installed-archive-inspected"
            if reused:
                result["binding_plan"]["payload"] = "verified-expected-tree"
                result["binding_plan"]["blockers"].remove("payload-integrity-unverified")
                result["blockers"].remove("payload-integrity-unverified")
            result["proposed_steps"] = [
                {"step": "proton-add-or-reuse", "status": summary["action"]},
                {"step": "prefix", "status": summary["prefix"]["action"]},
                {"step": "dependencies", "status": "blocked"},
                {"step": "binding-and-sync", "status": "target-only-planned" if reused else "deferred-until-installed"},
                {"step": "template-create-or-copy", "status": "not-implemented"}]
            result["input_hashes"].update(installation=installation.digest, runtime_audit=audit_digest)
            result["input_digest"] = hashlib.sha256(json.dumps(
                {"target_report": result["input_digest"], "installation": installation.digest,
                 "audit": audit_digest}, sort_keys=True).encode()).hexdigest()
            result["blockers"].extend(summary["blockers"])
        elif args.inspect_payload:
            allowed = {"inspect_payload", "payload_archive", "payload_sha512", "payload_root", "payload_directory"}
            require(not any(value for key, value in vars(args).items() if key not in allowed), "payload inspection is a separate mode")
            inventory = inspect_archive(args.payload_archive, args.payload_sha512, args.payload_root)
            result = {"tool_version": VERSION, "mode": "inspect-payload", **inventory.summary()}
            if args.payload_directory is not None:
                result["installed_payload"] = verify_tree(args.payload_directory, inventory)
        elif args.list_local:
            require(args.runtime_root is None, "runtime options require --inspect-runtime")
            require(not any((args.payload_archive, args.payload_sha512, args.payload_root, args.payload_directory)),
                    "payload options require --inspect-payload")
            require(args.management_root is not None, "--management-root required")
            require(not any((args.registrations, args.steam_root, args.settings_root, args.exe_root, args.app_id,
                             args.profile, args.recipes, args.assets, args.asset_root, args.resume_run,
                             args.droiddeck_version, args.proton_version, args.tool_directory)), "inventory accepts only a management root")
            with PrivateStore(args.management_root) as store:
                result = {"tool_version": VERSION, "mode": "list-local", "writes": [], **store.inventory()}
        else:
            require(args.runtime_root is None, "runtime options require --inspect-runtime")
            require(not any((args.payload_archive, args.payload_sha512, args.payload_root, args.payload_directory)),
                    "payload options require --inspect-payload")
            require(args.registrations is not None and args.steam_root is not None and args.settings_root is not None,
                    "registration and settings paths required")
            if args.stage_local:
                require(args.management_root is not None, "--management-root required")
                result = stage_local(args, lambda: build_report(args))
            else:
                require(args.management_root is None and args.resume_run is None, "store options require a local management mode")
                result = build_report(args)
        report = display(result)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError, KeyError):
        # Do not echo exception text, filesystem paths or unknown input content.
        if args.stage_local:
            parser.exit(1, "Local staging stopped; private cache/run files may remain. "
                           "Use --list-local to inspect them. No prefix preparation performed.\n")
        parser.exit(1, "Input rejected; no preparation performed. Check input formats and paths.\n")
    print(report)
    # A readable report is distinct from a usable preparation plan.
    return 2 if args.plan or args.plan_dependency or args.plan_preparation or args.stage_local or args.inspect_preflight else 0


if __name__ == "__main__":
    raise SystemExit(main())
