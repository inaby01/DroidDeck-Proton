"""Bundle validation, guidance references, report saving and the four emitted scripts.

The emitted scripts (prepare.sh, status.sh, diagnose.sh, recovery.sh) embed trusted code and
the bundle, and preserve input separately from their Python heredoc. The plan-only selection
screen was removed in 1.0.1.
"""

import contextlib
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from pathlib import Path

from preparation_common import (
    MAX_REPORT,
    fields,
    load_json,
    read_bytes,
    require,
    safe_path,
    string,
)
from preparation_target import registrations


def operational_layout(config):
    """Whether the bundle shows the operational entry first (design: operational entry 3).

    Every operational step must be configured; a bundle missing one is refused (1.0.1).
    """
    return (type(config) is dict and bool(config.get("probe_material", False)) and config.get("initialization_trial") is True
            and all(name in config for name in ("placement_review", "game_preparation", "dependency_installation")))


RECOVERY_NUMBERS = {8: 5, 9: 6, 10: 4}


def menu_ref(config, number):
    """How guidance names an earlier menu: its place in recovery.sh (1.0.0)."""
    return "recovery.sh の" + str(RECOVERY_NUMBERS[number]) if number in RECOVERY_NUMBERS else "recovery.sh"


def one_pass_ref(config):
    """How guidance names the one-pass preparation of one game (recovery.sh 1)."""
    return "recovery.sh の1"


def _text(value):
    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c).startswith("C") or c in "\u2028\u2029" else c
                   for c in str(value)[:240])


def validate_selection_config(config):
    fields(config, ("schema_version", "payload", "runtime_reference"),
           ("probe_material", "placement_review", "initialization_trial", "dependency_installation", "game_preparation",
            "supersedes", "diagnostics"))
    require(type(config.get("probe_material", False)) is bool, "invalid probe menu option")
    require(type(config.get("initialization_trial", False)) is bool, "invalid initialization trial menu option")
    require(type(config["schema_version"]) is int and config["schema_version"] == 1, "unknown selection config")
    payload = config["payload"]
    fields(payload, ("archive", "sha512", "root", "mode"), ("alternate_relative_path", "tool_slot"))
    name = string(payload["archive"])
    require(re.fullmatch(r"DroidDeck-Proton-[0-9]{1,4}-[0-9]{1,4}\.[0-9]{1,4}-softdenchi-r[1-9][0-9]{0,3}-aarch64\.tar\.gz", name), "unsupported archive name")
    require(type(payload["sha512"]) is str and re.fullmatch(r"[0-9a-f]{128}", payload["sha512"]), "expected archive checksum required")
    require(type(payload["mode"]) is str and payload["mode"] == "cleanup", "invalid installation mode")
    expected_root = "DroidDeck-Proton " + name.removeprefix("DroidDeck-Proton-").removesuffix("-aarch64.tar.gz")
    require(type(payload["root"]) is str and payload["root"] == expected_root,
            "archive root differs from filename")
    if "alternate_relative_path" in payload:
        relative = string(payload["alternate_relative_path"])
        parts = relative.split("/")
        require(1 < len(parts) <= 8 and all(part and part not in (".", "..", ".env") and not part.startswith(".env.")
                and not any(c in part for c in "\0\\\r\n") for part in parts) and parts[-1] == name, "invalid archive layout")
    require(payload.get("tool_slot", "legacy") in ("legacy", "preparation"), "unknown tool slot")
    require(type(config["runtime_reference"]) is dict, "runtime reference required")
    if "placement_review" in config:
        from preparation_static_placement import validate_build_review
        validate_build_review(config["placement_review"])
        require(config["placement_review"]["archive_sha512"] == payload["sha512"] and payload.get("tool_slot") == "preparation",
                "placement review must match the preparation payload")
    if "dependency_installation" in config:
        from preparation_dependency_install import validate_dependency_config
        require(config.get("initialization_trial") is True and "placement_review" in config,
                "dependency installation requires the managed trial configuration")
        validate_dependency_config(config["dependency_installation"])
    if "supersedes" in config:
        # Earlier preparation slots this bundle replaces; only these move in the batch run (design: Proton update 4.2).
        from preparation_slot_manifest import slot_name
        superseded = config["supersedes"]
        require(type(superseded) is list and len(superseded) <= 64 and len(set(superseded)) == len(superseded),
                "invalid superseded slot list")
        for name in superseded:
            slot_name(name)
        require(payload.get("tool_slot") == "preparation" and
                "SoftDenchi-Prep-Proton " + expected_root.removeprefix("DroidDeck-Proton ") not in superseded,
                "a bundle cannot supersede its own slot")
    if "diagnostics" in config:
        # Explicit diagnostic mode (design: installer log): only installer_log, a strict boolean.
        from preparation_installer_log import validate_diagnostics
        validate_diagnostics(config["diagnostics"])
    if "game_preparation" in config:
        from preparation_game_prefix import validate_game_config
        require(config.get("initialization_trial") is True and "placement_review" in config,
                "game preparation requires the managed trial configuration")
        validate_game_config(config["game_preparation"])
    return config


def registration_catalog(environment):
    source = safe_path(string(environment.get("BL_ADDED_GAMES")))
    document, digest = load_json(source)
    games = registrations(document)
    require(games, "no added games")
    return source, digest, games


def _archive(directory, payload):
    candidates = [safe_path(directory / payload["archive"], directory)]
    if payload.get("alternate_relative_path"):
        candidates.append(safe_path(directory / payload["alternate_relative_path"], directory))
    present = [path for path in candidates if os.path.lexists(path)]
    require(len(present) == 1 and present[0].is_file(), "archive missing or ambiguous")
    return present[0]


def save_selection_report(directory, report, protected_roots=()):
    directory = safe_path(directory)
    require(not any(directory == root or directory.is_relative_to(root) for root in map(safe_path, protected_roots)),
            "report folder overlaps protected data")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(before.st_uid == os.getuid() and not before.st_mode & 0o022, "report folder must be owned and private from other writers")
        for _ in range(8):
            name = "plan-" + secrets.token_hex(4) + ".json"
            saved = copy.deepcopy(report)
            saved["writes"] = list(saved.get("writes", [])) + [{"scope": "report-only", "filename": name}]
            raw = (json.dumps(saved, ensure_ascii=True, indent=2) + "\n").encode()
            require(len(raw) <= MAX_REPORT, "report too large")
            current = safe_path(directory).stat()
            require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), "report folder changed")
            try:
                output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            except FileExistsError:
                continue
            with os.fdopen(output_fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(fd)
            return name
        raise ValueError("report filename collisions")
    finally:
        os.close(fd)


def _input_metadata(path):
    """Inspect a selected EXE's path/FD metadata only, even after strict read refusal."""
    try:
        path = safe_path(path)
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
        finally:
            os.close(fd)
        def project(info):
            return {"regular": stat.S_ISREG(info.st_mode), "link_count": info.st_nlink,
                    "owner_matches_self": info.st_uid == os.getuid(), "mode": format(stat.S_IMODE(info.st_mode), "04o")}
        return {"status": "metadata-read", "path": project(before), "fd": project(opened),
                "same_inode": (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)}
    except (OSError, ValueError) as error:
        return {"status": "unavailable", "error_class": type(error).__name__, "errno": getattr(error, "errno", None)}


def _private_report_directory(home, protected_roots):
    home = safe_path(home)
    destination = safe_path(home / ".local/state/droiddeck-prefix-preparation/reports", home)
    require(not any(destination == root or destination.is_relative_to(root) for root in map(safe_path, protected_roots)),
            "private report directory overlaps protected data")
    with contextlib.ExitStack() as stack:
        fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        for name in (None, ".local", "state", "droiddeck-prefix-preparation", "reports"):
            if name is not None:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                stack.callback(os.close, child)
                fd = child
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "private report ancestor unsafe")
        # Saving reopens and revalidates the resolved path; do not chmod existing ancestors.
        safe_path(destination)
    return destination


def _export_report(directory, source, protected_roots):
    """Copy a private result to the explicitly selected launcher folder only.

    Shared filesystem ownership/mode emulation is allowed for this data export,
    never for assets, caches, source readers, private reports or execution paths.
    The original private result remains authoritative. No existing file is opened
    for writing; no existing directory or file permissions are modified.
    """
    directory, source = safe_path(directory), safe_path(source)
    require(not any(directory == root or directory.is_relative_to(root) for root in map(safe_path, protected_roots)),
            "shared report export overlaps protected data")
    raw = read_bytes(source, MAX_REPORT)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        current = safe_path(directory).stat()
        require((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino), "report export folder changed")
        output_fd = os.open(source.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(output_fd, "wb") as output:
            info = os.fstat(output.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "invalid newly created report export")
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)


def save_selection_result(directory, home, report, protected_roots):
    try:
        return Path(directory) / save_selection_report(directory, report, protected_roots), None
    except (OSError, ValueError):
        private = _private_report_directory(home, protected_roots)
        # Failed shared/direct save may have left an incomplete new JSON; keep it.
        fallback = copy.deepcopy(report)
        fallback["report_storage"] = {"authoritative": "private-linux-home", "shared_export_privacy": "filesystem-dependent"}
        name = save_selection_report(private, fallback, protected_roots)
        source = private / name
        try:
            _export_report(directory, source, protected_roots)
            return Path(directory) / name, source
        except (OSError, ValueError):
            return source, None


SCRIPT_ENTRIES = ("prepare", "status", "diagnose", "recovery")


def selection_script(config, entry="prepare"):
    """Embed only trusted distribution sources and optional validated local data.

    ``entry`` is the use of the emitted script (1.0.0): prepare.sh, status.sh, diagnose.sh or
    recovery.sh. Each script embeds the same sources and runs on its own. Only an operational
    bundle is accepted (1.0.1).
    """
    require(entry in SCRIPT_ENTRIES, "unknown script entry")
    require(operational_layout(config), "operational bundle required")
    validate_selection_config(config)
    require(len(json.dumps(config).encode()) <= MAX_REPORT, "bundle configuration too large")
    parent = Path(__file__).resolve().parent
    names = ("preparation_common", "preparation_assets", "preparation_vdf", "preparation_binding", "preparation_target",
             "preparation_payload", "preparation_runtime", "preparation_customization", "preparation_runtime_context",
             "preparation_installation", "preparation_processes", "preparation_publication", "preparation_execution",
             "preparation_tool_writer", "preparation_store", "preparation_slot_manifest", "preparation_static_placement", "preparation_trial", "preparation_recheck", "preparation_softdenchi_recipe",
             "preparation_dependency_state", "preparation_vc_record", "preparation_installer_log", "preparation_dependency_install", "preparation_prefix_dll", "preparation_game_prefix",
             "preparation_one_pass", "preparation_proton_update", "preparation_status", "preparation_batch",
             "preparation_diagnose", "preparation_redo", "preparation_selection")
    sources = {name: read_bytes(parent / (name + ".py")).decode("utf-8") for name in names}
    installer = parent.parent / "install-softdenchi.py"
    if not installer.exists():
        installer = parent.parent / "banner-proton/install-softdenchi.py"
    sources["preparation_distributed_installer"] = read_bytes(installer).decode("utf-8")
    code = ("import os, sys, types\n" + "sources = " + ascii(sources) + "\n" +
            "for name, source in sources.items():\n"
            "    module = types.ModuleType(name)\n"
            "    module.__file__ = '/__droiddeck_embedded__/' + name + '.py'\n"
            "    sys.modules[name] = module\n"
            "    exec(compile(source, name, 'exec'), module.__dict__)\n" +
            "with os.fdopen(os.dup(3), 'r', encoding='utf-8') as selection_input:\n"
            "    status, _ = sys.modules['preparation_batch'].interactive_workflow(\n"
            "        sys.argv[1], sys.modules['preparation_distributed_installer'].render_installation,\n"
            "        config=" + ascii(config) + ", input_stream=selection_input, entry=" + ascii(entry) + ")\n"
            "raise SystemExit(status)\n")
    compile(code, "selection-launcher", "exec")
    delimiter = "DROIDDECK_SELECTION_" + hashlib.sha256(code.encode()).hexdigest()[:16]
    return ("#!/bin/bash\n# Plans and explicitly confirmed dedicated operations; default planning never executes Wine.\n"
            "if (( $# != 0 )); then echo 'この起動にはオプションは不要です。' >&2; exit 1; fi\n"
            'script_parent=.\nif [[ ${BASH_SOURCE[0]} == */* ]]; then script_parent=${BASH_SOURCE[0]%/*}; fi\n'
            'script_dir=$(CDPATH=\'\' cd -- "$script_parent" && pwd -P) || exit 1\n'
            '/usr/bin/python3 -I -B - "$script_dir" 3<&0 <<\'' + delimiter + "'\n" + code + delimiter + "\n")
