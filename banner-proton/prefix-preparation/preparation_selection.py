"""Interactive, plan-only target selection and exclusive report saving.

No installer, launch adapter, binding writer or prefix writer is called. The
short user launcher embeds trusted code/config and preserves input separately
from its Python heredoc. Reports alone are written, alongside the launcher.
"""

import contextlib
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import unicodedata
from pathlib import Path

from preparation_assets import digest_json, exe_identity
from preparation_binding import (
    binding_error,
    inspect_binding_inputs,
    inspect_steam_config,
    plan_binding,
)
from preparation_common import (
    MAX_REPORT,
    VERSION,
    checked,
    fields,
    input_change,
    load_json,
    read_bytes,
    require,
    safe_path,
    string,
)
from preparation_execution import (
    inspect_initialization_inputs,
    inspect_prelaunch_context,
)
from preparation_installation import plan_installation
from preparation_target import pin_registration, registrations


def operational_layout(config):
    """Whether the bundle shows the operational entry first (design: operational entry 3).

    The same conditions as menu 12; a bundle missing one keeps the earlier screen.
    """
    return (type(config) is dict and bool(config.get("probe_material", False)) and config.get("initialization_trial") is True
            and all(name in config for name in ("placement_review", "game_preparation", "dependency_installation")))


def menu_ref(config, number):
    """How guidance names a menu of the earlier screen: inside the detailed menu (individual operation 4)
    when the operational first screen is shown (design: Proton update 3.7)."""
    return ("個別の操作の4（詳細メニュー）の" if operational_layout(config) else "メニュー") + str(number)


def one_pass_ref(config):
    """How guidance names the one-pass preparation (individual operation 1, earlier screen 12)."""
    return "3（個別の操作）の1" if operational_layout(config) else "12"


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
    require(re.fullmatch(r"DroidDeck-Proton-11-12\.8-softdenchi[1-9][A-Za-z0-9.-]*-aarch64\.tar\.gz", name), "unsupported archive name")
    require(type(payload["sha512"]) is str and re.fullmatch(r"[0-9a-f]{128}", payload["sha512"]), "expected archive checksum required")
    require(type(payload["mode"]) is str and payload["mode"] in ("off", "observe", "cleanup"), "invalid installation mode")
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


def _verify_catalog(environment, source, digest):
    require(safe_path(string(environment.get("BL_ADDED_GAMES"))) == source and load_json(source)[1] == digest,
            "registration source changed")


def _prefix_state(steam, key):
    base = safe_path(steam / "steamapps/compatdata", steam)
    require(not base.exists() or base.is_dir(), "invalid compatdata parent")
    names = [key] + ([str(int(key) - 2**32)] if int(key) >= 2**31 else [])
    existing = []
    if base.exists():
        with os.scandir(base) as children:
            for count, child in enumerate(children):
                require(count < 4096, "too many prefix entries")
                if re.fullmatch(r"-?[0-9]+", child.name) and int(child.name) % 2**32 == int(key):
                    require(child.name in names, "noncanonical prefix alias")
                    require(safe_path(base / child.name, steam).is_dir(), "invalid existing prefix")
                    existing.append(child.name)
    require(len(existing) <= 1, "ambiguous prefix aliases")
    return {"compatdata": str(base / (existing[0] if existing else key)), "exists": bool(existing),
            "action": "preserve-existing" if existing else "initialize-new-blocked"}


def _archive(directory, payload):
    candidates = [safe_path(directory / payload["archive"], directory)]
    if payload.get("alternate_relative_path"):
        candidates.append(safe_path(directory / payload["alternate_relative_path"], directory))
    present = [path for path in candidates if os.path.lexists(path)]
    require(len(present) == 1 and present[0].is_file(), "archive missing or ambiguous")
    return present[0]


def _prefix_capacity(steam, inventory):
    base = safe_path(steam / "steamapps/compatdata", steam)
    ancestor = base
    while not ancestor.exists():
        ancestor = ancestor.parent
    fs = os.statvfs(ancestor)
    block = fs.f_frsize or fs.f_bsize
    require(block > 0, "unknown allocation unit")
    entries = [entry for name, entry in inventory.entries.items() if name.startswith("files/share/default_pfx_arm64/")]
    estimate = sum(((entry["size"] + block - 1) // block) * block if entry["kind"] in ("file", "hardlink") else block
                   for entry in entries) + block if entries else None
    return {"basis": "shipped-files/share/default_pfx_arm64-only", "source_entries": len(entries),
            "template_allocation_estimate_bytes": estimate, "available_bytes": fs.f_bavail * block,
            "initialization_growth_bytes": None, "dependencies_bytes": None, "complete_preparation_fits": False,
            "dependency_prepared_template": False}


def selected_plan(directory, config, key, source, source_digest, games, steam, settings, home, renderer, environment,
                  runtime_root=Path("/"), collected_context=None):
    directory, steam, settings, home = map(safe_path, (directory, steam, settings, home))
    require(steam.is_dir() and settings.is_dir(), "existing Steam/settings roots required")
    config = validate_selection_config(copy.deepcopy(config))
    _verify_catalog(environment, source, source_digest)
    require(key in games, "selected registration absent")
    # Project only known registration fields. Do not save the raw Android list.
    target = games[key]
    exe = safe_path(target["exe"])
    require(exe.parent != Path("/"), "executable parent too broad")
    pin = checked("target-registration-exe", pin_registration, source, key, exe.parent, steam)
    prefix = checked("prefix-location", _prefix_state, steam, key)
    work = safe_path(home / ".local/share/droiddeck-preparation-work" / key / "work")
    private_home = safe_path(home / ".local/share/droiddeck-preparation-work" / key / "home")
    report = {"schema_version": 1, "tool_version": VERSION, "mode": "selected-preparation-plan", "status": "blocked",
              "target": {**target, "identity": exe_identity(exe)}, "target_pin_digest": pin.digest,
              "registration": {"source": "current-runtime-environment-file", "source_sha256": source_digest,
                               "rechecked": True, "android_export_freshness": "unverified"},
              "prefix": prefix, "private_paths": {"work": str(work), "home": str(private_home)},
              "payload_request": {"filename": config["payload"]["archive"], "sha512": config["payload"]["sha512"],
                                  "root": config["payload"]["root"], "mode": config["payload"]["mode"]},
              "planned_writes": [], "blockers": ["execution-not-exposed", "profile-and-recipes-not-selected",
                "new-test-registration-not-confirmed", "android-registration-freshness-unverified"],
              "preparation_complete": False, "writes": []}
    if prefix["exists"]:
        report["blockers"].append("existing-prefix-preserve")
    from preparation_probe import EXE, verify_probe_registration
    if exe.name == EXE:
        report["probe_registration"] = checked("dedicated-probe-registration", verify_probe_registration,
            exe, key, source, steam, home / ".local/state/droiddeck-prefix-preparation/probe-store")
        report["blockers"].remove("new-test-registration-not-confirmed")
        report["blockers"].append("registration-probe-only-not-game-profile")
    archive = None
    try:
        archive = _archive(directory, config["payload"])
    except ValueError:
        report["blockers"].append("archive-missing-or-ambiguous")
    if archive is not None:
        installation = checked("installation-plan", plan_installation, archive=archive, sha512=config["payload"]["sha512"], archive_root=config["payload"]["root"],
            mode=config["payload"]["mode"], runtime_root=runtime_root, runtime_audit=config["runtime_reference"],
            registrations=source, registration_id=key, exe_root=exe.parent, steam=steam, renderer=renderer, parent_environment=environment, tool_slot=config["payload"].get("tool_slot", "legacy"))
        report["installation_plan"] = installation.summary()
        if "placement_review" in config:
            review = config["placement_review"]
            require(review["archive_sha512"] == report["installation_plan"]["payload"]["archive_sha512"], "reviewed payload identity differs")
            report["payload_source_review"] = {**review, "archive_identity_rechecked": True, "execution_readiness": "unverified"}
            report["installation_plan"]["blockers"].remove("payload-provenance-unreviewed")
            report["installation_plan"]["payload"]["blockers"].remove("payload-provenance-unreviewed")
        report["blockers"].extend(report["installation_plan"]["blockers"])
        report["planned_writes"].extend(report["installation_plan"]["planned_writes"])
        report["prefix_capacity"] = _prefix_capacity(steam, installation.inventory)
        if report["prefix_capacity"]["template_allocation_estimate_bytes"] is None:
            report["blockers"].append("prefix-template-baseline-unavailable")
        elif report["prefix_capacity"]["available_bytes"] < report["prefix_capacity"]["template_allocation_estimate_bytes"]:
            report["blockers"].append("insufficient-template-baseline-space")
        report["blockers"].append("initialization-and-dependencies-growth-unmeasured")
        tool = Path(report["installation_plan"]["destination"])
        for private in (work, private_home):
            if any(private == protected or private.is_relative_to(protected) or protected.is_relative_to(private)
                   for protected in (steam, settings, exe.parent, tool)):
                report["blockers"].append("private-launch-path-overlap")
            if os.path.lexists(private):
                report["blockers"].append("private-launch-path-already-exists")
        if report["installation_plan"]["action"] == "reuse-verified-tree":
            report["steam_config_validation"] = inspect_steam_config(steam)
            source_entries = {**installation.inventory.entries, **installation.customization.overlays}
            branch = "files/bin-arm64" if "files/bin-arm64" in source_entries else "files/bin"
            report["native_wine_layout"] = {"branch": branch, "execution_tested": False,
                "inputs": {name: {"present": branch + "/" + name in source_entries,
                    "kind": source_entries.get(branch + "/" + name, {}).get("kind")}
                           for name in ("wine", "wineserver")}}
            launcher_hashes = {name: source_entries[name]["sha256"] if name in source_entries else None
                               for name in ("proton", "version", "user_settings.py")}
            report["initialization_inputs"] = inspect_initialization_inputs(
                tool=tool, steam=steam, registration_id=key, expected_hashes=launcher_hashes,
                work=work, home=private_home)
            try:
                report["binding_plan"] = checked("binding-plan", plan_binding,
                    steam, settings, key, installation.customization.directory).summary()
                report["binding_plan"]["payload"] = "verified-expected-tree"
                report["binding_plan"]["blockers"].remove("payload-integrity-unverified")
            except (OSError, ValueError, TypeError, KeyError) as error:
                report["binding_plan"] = {"status": "blocked", "error": binding_error(error),
                    "blockers": ["binding-input-rejected"], "writes": [], "execution_authorized": False}
                report["binding_diagnostics"] = inspect_binding_inputs(
                    steam, settings, key, installation.customization.directory)
                report["blockers"].append("binding-input-rejected")
        installation.runtime.verify(environment)
        installation.target.verify()
    if not prefix["exists"]:
        report["planned_writes"].extend({"path": path, "action": "create-new-blocked"}
                                       for path in (prefix["compatdata"], str(work), str(private_home)))
    report["input_digest"] = digest_json({"config": config, "target_pin": pin.digest,
        "installation": report.get("installation_plan", {}).get("input_digest"), "prefix": prefix,
        "private_paths": report["private_paths"]})
    _verify_catalog(environment, source, source_digest)
    pin.verify()
    require(_prefix_state(steam, key) == prefix, "prefix state changed during planning")
    report["prelaunch_context"] = collected_context if collected_context is not None else inspect_prelaunch_context(
        steam=steam, settings=settings, home=home, environment=environment, runtime_root=runtime_root)
    report["inspection_summary"] = summarize_inspection(report)
    return report


def summarize_inspection(report):
    """Distinguish failed checks, observations needing attention and future work."""
    passed, unexpected, attention = [], [], []
    if "error_class" in report:
        unexpected.append("target-plan")
    if report.get("installation_plan", {}).get("action") == "reuse-verified-tree":
        passed.append("installed-tool-identity")
    binding = report.get("binding_plan", {})
    if binding.get("status") == "blocked":
        unexpected.append("binding-inputs")
    elif binding:
        passed.append("binding-plan")
    if "archive-missing-or-ambiguous" in report.get("blockers", []):
        attention.append("archive-location")
    for name, value in report.get("initialization_inputs", {}).get("checks", {}).items():
        if value["status"] == "rejected":
            unexpected.append(name)
        elif name == "process-observation" and not value.get("clear_in_view", False):
            attention.append("target-processes-active-or-unreadable")
        else:
            passed.append(name)
    context = report.get("prelaunch_context", {})
    for name, value in context.get("checks", {}).items():
        if value["status"] == "rejected":
            unexpected.append(name)
        else:
            passed.append(name)
            if name.startswith("filesystem-"):
                if value["read_only"]:
                    attention.append(name + "-read-only")
                if value["ancestor_other_writer"] or not value["ancestor_owner_matches_self"]:
                    attention.append(name + "-ownership-or-permissions")
                if value["available_bytes"] == 0 or value["available_inodes"] == 0:
                    attention.append(name + "-space-or-inodes-unavailable")
                if name == "filesystem-tool-parent" and value["noexec"]:
                    attention.append("tool-filesystem-noexec")
            if name == "system-python" and not value["executable"]:
                attention.append("system-python-unavailable")
    if any(not value["present"] for value in report.get("native_wine_layout", {}).get("inputs", {}).values()):
        attention.append("native-wine-layout-missing")
    capacity = report.get("prefix_capacity", {})
    baseline = capacity.get("template_allocation_estimate_bytes")
    if baseline is not None and capacity["available_bytes"] < baseline:
        attention.append("insufficient-template-baseline-space")
    if context.get("copy_prefix_requested"):
        attention.append("copy-prefix-requested")
    return {"status": "unexpected-findings" if unexpected else "attention-needed" if attention else "collected-checks-passed",
            "passed_checks": passed, "unexpected_findings": unexpected, "attention_items": attention,
            "dependent_checks_not_run": [name for name, present in (
                ("initialization-inputs", "initialization_inputs" in report),
                ("binding-plan", "binding_plan" in report)) if not present],
            "deferred_steps": ["dedicated-prefix-initialization", "dependency-installation", "unauthenticated-template-and-cloning",
                               "binding-application-and-real-game-validation"],
            "unverified_limits": ["other-process-namespaces-and-external-launchers", "actual-write-and-execution-permissions",
                                  "gui-connection-and-wine-runtime", "prefix-and-dependency-growth"],
            "execution_authorized": False, "preparation_complete": False}


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


def interactive_selection(directory, renderer, config=None, *, input_stream=None, output_stream=None, environment=None,
                          steam=None, settings=None, home=None, runtime_root=Path("/")):
    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    directory = safe_path(directory)
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    protected_roots = [steam, settings]
    stage, selected, report = "configuration", None, None
    selected_exe = None
    context = None
    try:
        config_path, config_hash = None, None
        if config is None:
            config_path = safe_path(directory / "prepare-plan.json", directory)
            config, config_hash = load_json(config_path)
        config = validate_selection_config(copy.deepcopy(config))
        stage = "registration-catalog"
        source, source_digest, games = registration_catalog(environment)
        print("計画の表示と結果保存だけを行います。prefixや設定は変更しません。", file=output)
        keys = list(games)
        for index, key in enumerate(keys, 1):
            print(f"{index}. {_text(games[key]['title'])}  [ID {key}]", file=output)
            print("   " + _text(games[key]["exe"]), file=output)
        print("対象の番号を入力（qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32)
        if not answer or answer.strip().lower() == "q":
            print("取り消しました。", file=output)
            return 0, None
        require(re.fullmatch(r"[1-9][0-9]{0,3}\s*", answer) and int(answer) <= len(keys), "invalid selection")
        selected = keys[int(answer) - 1]
        selected_exe = Path(games[selected]["exe"])
        protected_roots.append(selected_exe.parent)
        print("使用するProton（計画）: " + _text(config["payload"]["root"]), file=output)
        context = inspect_prelaunch_context(steam=steam, settings=settings, home=home,
                                            environment=environment, runtime_root=runtime_root)
        stage = "selected-plan"
        report = selected_plan(directory, config, selected, source, source_digest, games, steam, settings, home, renderer,
                               environment, runtime_root, collected_context=context)
        if config_path is not None:
            require(load_json(config_path)[1] == config_hash, "configuration changed")
        print("prefix: " + _text(report["prefix"]["compatdata"]), file=output)
        print("既存prefixを保護します。" if report["prefix"]["exists"] else "新規作成の計画です。まだ作成しません。", file=output)
        if "archive-missing-or-ambiguous" in report["blockers"]:
            print("配布物が見つからないか複数あります。必要なファイル: " + _text(config["payload"]["archive"]), file=output)
        if "installation_plan" in report:
            installation = report["installation_plan"]
            action = "新規配置（未実行）" if installation["action"] == "install-new" else "全体照合済みの既存版を再利用する計画"
            print("Proton: " + action, file=output)
            print("配置先: " + _text(installation["destination"]), file=output)
            if installation.get("legacy_tool_observation") is not None:
                print("既存のProtonはそのまま保持し、準備用の別配置を計画します。", file=output)
            capacity = installation["capacity"]
            print(f"tool配置の見積: {capacity['estimated_additional_bytes'] / 1024**2:.1f} MiB / 空き {capacity['available_bytes'] / 1024**3:.1f} GiB", file=output)
            baseline = report["prefix_capacity"]["template_allocation_estimate_bytes"]
            if baseline is not None:
                print(f"prefixの出荷時ひな形分の見積: {baseline / 1024**2:.1f} MiB", file=output)
        if not report["prefix"]["exists"]:
            print("専用作業場所（計画）: " + _text(report["private_paths"]["work"]), file=output)
            print("専用HOME（計画）: " + _text(report["private_paths"]["home"]), file=output)
        print("必要容量のうち、初期化・依存導入で増える分は未確定です。", file=output)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        report = {"schema_version": 1, "tool_version": VERSION, "mode": "selected-preparation-plan", "status": "input-rejected",
                  "stage": stage, "check": getattr(error, "preparation_check", stage), "selected_app_id": selected, "error_class": type(error).__name__, "errno": getattr(error, "errno", None),
                  "reason": {"existing installation differs from approved generated trees": "installed-tool-differs",
                             "payload archive checksum mismatch": "archive-checksum-mismatch",
                             "runtime source/library/label changed since audit": "runtime-identity-changed",
                             "registration source changed": "registration-changed",
                             "registration or executable changed": "target-changed",
                             "single-link regular file required": "input-link-metadata-rejected"}.get(str(error), "input-rejected"),
                  "preparation_complete": False, "writes": [], **input_change(error)}
        if hasattr(error, "installed_tree_diagnostic"):
            report["installed_tree_diagnostic"] = error.installed_tree_diagnostic
        if hasattr(error, "probe_registration_diagnostic"):
            report["probe_registration_diagnostic"] = error.probe_registration_diagnostic
        if hasattr(error, "incomplete_probe_material"):
            report["incomplete_probe_material"] = error.incomplete_probe_material
        if selected_exe is not None:
            report["selected_exe_metadata"] = _input_metadata(selected_exe)
        print("検査停止: " + _text(report["check"]) + " / " + report["reason"] +
              " / " + report["error_class"] + " / errno=" + str(report["errno"]), file=output)
        print("診断結果を保存します。prefixや設定は変更していません。", file=output)
    if context is not None:
        report["prelaunch_context"] = context
    report["inspection_summary"] = summarize_inspection(report)
    summary = report["inspection_summary"]
    label = {"unexpected-findings": "想定外の検査失敗あり", "attention-needed": "観測結果に要確認あり",
             "collected-checks-passed": "今回収集した検査は通過"}[summary["status"]]
    print("検査の集計: " + label, file=output)
    print(f"通過 {len(summary['passed_checks'])} / 想定外 {len(summary['unexpected_findings'])} / 要確認 {len(summary['attention_items'])}", file=output)
    for name in summary["unexpected_findings"]:
        print("  検査失敗: " + _text(name), file=output)
    for name in summary["attention_items"]:
        print("  要確認: " + _text(name), file=output)
    print("未確認の範囲: 他namespaceの停止・GUI/Wine動作・実書込/実行権限・初期化後の増分", file=output)
    print("未実施の後工程: prefix初期化 → 依存導入 → 未認証ひな形・複製 → 割り当て反映・実ゲーム検証", file=output)
    print("検査通過は実行許可ではありません。Wine・設定・prefixの変更は行っていません。", file=output)
    try:
        saved_path, private_copy = save_selection_result(directory, home, report, protected_roots)
    except (OSError, ValueError):
        print("結果を保存できませんでした。画面の検査停止理由を確認してください。prefixや設定は変更していません。", file=output)
        return 1, None
    label = saved_path.name if saved_path.parent == directory else str(saved_path)
    print("結果を保存しました: " + _text(label), file=output)
    if private_copy is not None:
        print("Linux側の専用領域にも原本を保存しました。", file=output)
    elif saved_path.parent != directory:
        print("共有側へコピーできなかったため、上記のLinux側ファイルを戻してください。", file=output)
    return 2, str(saved_path) if saved_path.parent != directory else saved_path.name


def selection_script(config=None):
    """Embed only trusted distribution sources and optional validated local data."""
    if config is not None:
        validate_selection_config(config)
        require(len(json.dumps(config).encode()) <= MAX_REPORT, "bundle configuration too large")
    parent = Path(__file__).resolve().parent
    names = ("preparation_common", "preparation_assets", "preparation_vdf", "preparation_binding", "preparation_target",
             "preparation_payload", "preparation_runtime", "preparation_customization", "preparation_runtime_context",
             "preparation_installation", "preparation_processes", "preparation_publication", "preparation_execution",
             "preparation_tool_writer", "preparation_store", "preparation_slot_manifest", "preparation_probe", "preparation_probe_recovery", "preparation_static_placement", "preparation_trial", "preparation_trial_audit", "preparation_recheck", "preparation_softdenchi_recipe",
             "preparation_dependency_state", "preparation_vc_record", "preparation_installer_log", "preparation_dependency_install", "preparation_prefix_dll", "preparation_game_prefix",
             "preparation_one_pass", "preparation_proton_update", "preparation_status", "preparation_batch",
             "preparation_selection")
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
            "    status, _ = sys.modules['preparation_probe'].interactive_workflow(\n"
            "        sys.argv[1], sys.modules['preparation_distributed_installer'].render_installation,\n"
            "        config=" + ascii(config) + ", input_stream=selection_input)\n"
            "raise SystemExit(status)\n")
    compile(code, "selection-launcher", "exec")
    delimiter = "DROIDDECK_SELECTION_" + hashlib.sha256(code.encode()).hexdigest()[:16]
    return ("#!/bin/bash\n# Plans and explicitly confirmed dedicated operations; default planning never executes Wine.\n"
            "if (( $# != 0 )); then echo 'この起動にはオプションは不要です。' >&2; exit 1; fi\n"
            'script_parent=.\nif [[ ${BASH_SOURCE[0]} == */* ]]; then script_parent=${BASH_SOURCE[0]%/*}; fi\n'
            'script_dir=$(CDPATH=\'\' cd -- "$script_parent" && pwd -P) || exit 1\n'
            '/usr/bin/python3 -I -B - "$script_dir" 3<&0 <<\'' + delimiter + "'\n" + code + delimiter + "\n")
