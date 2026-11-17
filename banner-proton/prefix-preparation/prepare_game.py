#!/usr/bin/env python3
"""Offline, read-only prefix inspection and blocked preparation plans (no executor)."""

import argparse
import hashlib
import itertools
import json
import os
import re
import stat
import struct
import unicodedata
from pathlib import Path

VERSION = "0.1.0"
MAX_JSON = 1024 * 1024
MAX_REPORT = 1024 * 1024
MAX_DEPTH = 16
MAX_STRING = 4096
MAX_DEPENDENCIES = 128
MAX_EXE = 2 * 1024**3
ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
HANDLERS = {"mfc-local", "softdenchi-interactive"}


class Invalid(ValueError):
    """An input cannot be interpreted safely."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def fields(value, required, optional=()):
    require(type(value) is dict, "expected object")
    require(set(required) <= value.keys() <= set(required) | set(optional), "unknown or missing fields")


def string(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= MAX_STRING, "invalid string")
    return value


def identifier(value):
    require(type(value) is str and ID.fullmatch(value), "invalid identifier")
    return value


def revision(value):
    require(type(value) is int and 1 <= value <= 0x7FFFFFFF, "invalid revision")


def app_id(value):
    if type(value) is str:
        require(re.fullmatch(r"(?:0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})", value), "invalid app ID")
        value = int(value)
    require(type(value) is int and -0x80000000 <= value <= 0xFFFFFFFF and value != 0, "invalid app ID")
    return str(value & 0xFFFFFFFF)


def safe_path(value, root=None):
    path = Path(string(str(value)))
    require(path.is_absolute() and ".." not in path.parts, "absolute path without '..' required")
    require(not any(part == ".env" or part.startswith(".env.") for part in path.parts), "environment files forbidden")
    if root is not None:
        require(path != root and path.is_relative_to(root), "path outside allowed root")
    for part in reversed([path, *path.parents]):
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(mode), "symlink in input path")
    return path


def regular_open(path, limit):
    path = safe_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, "rb")
    try:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "single-link regular file required")
        require(info.st_size <= limit, "input file too large")
    except BaseException:
        stream.close()
        raise
    return stream


def unchanged(before, after):
    require((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input changed during read")


def read_bytes(path, limit=MAX_JSON):
    with regular_open(path, limit) as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        unchanged(before, os.fstat(stream.fileno()))
    require(len(data) <= limit, "input file too large")
    return data


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def bounded(value, depth=0):
    require(depth <= MAX_DEPTH, "input nesting too deep")
    if type(value) is str:
        require(len(value.encode("utf-8")) <= MAX_STRING, "string too long")
    elif type(value) is dict:
        for key, item in value.items():
            bounded(key, depth + 1)
            bounded(item, depth + 1)
    elif type(value) is list:
        for item in value:
            bounded(item, depth + 1)
    else:
        require(value is None or type(value) in (int, bool), "unsupported JSON scalar")


def load_json(path):
    raw = read_bytes(path)
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        bounded(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid or excessive JSON") from error
    return value, hashlib.sha256(raw).hexdigest()


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


def registrations(document):
    """Read the added-games list consumed by DroidDeck 0.7.1's proton-run."""
    require(type(document) is list and len(document) <= 4096, "invalid added-games list")
    result = {}
    for entry in document:
        require(type(entry) is dict, "invalid game registration")
        key = app_id(entry.get("appid"))
        exe = safe_path(string(entry.get("exe")))
        title = string(entry.get("name") or entry.get("title") or exe.name)
        require(key not in result, "duplicate or signed/unsigned alias registration ID")
        result[key] = {"app_id": key, "title": title, "exe": str(exe)}
    return result


def exe_identity(path):
    """Stream a bounded executable; inspect only DOS/PE headers, never load it."""
    with regular_open(path, MAX_EXE) as stream:
        before = os.fstat(stream.fileno())
        dos = stream.read(64)
        require(len(dos) == 64 and dos[:2] == b"MZ", "EXE lacks DOS header")
        offset = struct.unpack_from("<I", dos, 60)[0]
        require(64 <= offset <= before.st_size - 26, "invalid PE offset")
        stream.seek(offset)
        header = stream.read(26)
        require(header[:4] == b"PE\0\0", "EXE lacks PE signature")
        optional_size = struct.unpack_from("<H", header, 20)[0]
        require(optional_size >= 2 and offset + 24 + optional_size <= before.st_size, "truncated PE optional header")
        machine = struct.unpack_from("<H", header, 4)[0]
        magic = struct.unpack_from("<H", header, 24)[0]
        require((machine, magic) in ((0x14C, 0x10B), (0x8664, 0x20B), (0xAA64, 0x20B)), "unsupported PE architecture")
        stream.seek(0)
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            require(size <= MAX_EXE, "EXE grew beyond limit")
            digest.update(chunk)
        unchanged(before, os.fstat(stream.fileno()))
    return {"sha256": digest.hexdigest(), "size": size,
            "pe_machine": {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}[machine],
            "provenance": "local-measurement-only"}


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


def parse_vdf(raw):
    """Bounded text KeyValues parser; no executable helper or permissive fallback."""
    text = raw.decode("utf-8")
    pattern = re.compile(r'\s+|//[^\n]*|"(?:[^"\\]|\\.)*"|[{}]')
    tokens = []
    end = 0
    for match in pattern.finditer(text):
        require(match.start() == end, "unsupported VDF token")
        token = match.group()
        end = match.end()
        if not token.isspace() and not token.startswith("//"):
            tokens.append(token)
    require(end == len(text), "invalid VDF tail")
    position = 0

    def quoted(token):
        require(token.startswith('"'), "expected VDF string")
        value = re.sub(r'\\(["\\])', r'\1', token[1:-1])
        require(len(value.encode("utf-8")) <= MAX_STRING, "VDF string too long")
        return value

    def block(depth=0, nested=False):
        nonlocal position
        require(depth <= MAX_DEPTH, "VDF nesting too deep")
        result = {}
        while position < len(tokens):
            key = tokens[position]
            position += 1
            if key == "}":
                require(nested, "unexpected VDF close")
                return result
            key = quoted(key)
            require(key not in result and position < len(tokens), "duplicate or incomplete VDF entry")
            value = tokens[position]
            position += 1
            result[key] = block(depth + 1, True) if value == "{" else quoted(value)
        require(not nested, "unclosed VDF block")
        return result

    return block()


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
    report["blockers"].append("synchronization-impact-uninspected")
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
         "selection": selection, "compatibility": report.get("compatibility")}, sort_keys=True).encode()).hexdigest()
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--inspect", action="store_true")
    mode.add_argument("--plan", action="store_true")
    parser.add_argument("--registrations", type=Path, required=True, help="DroidDeck added-games JSON, explicit input only")
    parser.add_argument("--steam-root", type=Path, required=True)
    parser.add_argument("--settings-root", type=Path, required=True)
    parser.add_argument("--exe-root", type=Path)
    parser.add_argument("--app-id")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--recipes", type=Path)
    parser.add_argument("--droiddeck-version")
    parser.add_argument("--proton-version")
    args = parser.parse_args()
    try:
        report = display(build_report(args))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        # Do not echo exception text, filesystem paths or unknown input content.
        parser.exit(1, "Input rejected; no preparation performed. Check input formats and paths.\n")
    print(report)
    # A readable report is distinct from a usable preparation plan.
    return 2 if args.plan else 0


if __name__ == "__main__":
    raise SystemExit(main())
