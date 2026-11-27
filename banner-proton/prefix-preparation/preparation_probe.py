"""Common entry of the four scripts, and the read-only checks of a dedicated registration probe.

The tool no longer creates probe material (removed in 1.0.1). Probe receipts written by earlier
versions are only read: a probe registration is verified, never executed, and its files are kept.
"""

import hashlib
import os
import re
import stat
from pathlib import Path

from preparation_assets import exe_identity
from preparation_common import (
    app_id,
    checked,
    fields,
    load_json,
    require,
    safe_path,
)
from preparation_store import PrivateStore
from preparation_target import registrations

MEMBER = "files/lib/wine/i386-windows/cmd.exe"
EXE = "prefix-probe.exe"
MARKER = "probe.json"
MAX_PROBE = 2 * 1024**2
ID = re.compile(r"probe-[0-9a-f]{32}\Z")
CREATION_STAGES = frozenset(("open-parent", "mkdir", "open-destination", "directory-guard", "open-exe", "write-exe", "sync-exe",
                             "open-marker", "write-marker", "sync-marker", "verify-exe", "verify-marker", "sync-directory", "sync-parent", "record-ready"))


def _record_valid(record):
    fields(record, ("schema_version", "tool_version", "probe_id", "probe_revision", "status", "destination", "steam",
                    "registration_source", "baseline_ids", "registration_sha256", "archive_sha512", "inventory_digest",
                    "member", "exe_identity", "preparation_complete"), ("revalidation", "creation_failure"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and type(record["probe_revision"]) is int and record["probe_revision"] == 1,
            "unknown probe receipt schema/revision")
    require(type(record["tool_version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", record["tool_version"]), "invalid creation version")
    require(type(record["probe_id"]) is str and ID.fullmatch(record["probe_id"]), "invalid probe ID")
    require(record["member"] == MEMBER and record["status"] in ("creating", "probe-ready", "probe-failed") and
            record["preparation_complete"] is False, "invalid probe receipt state")
    for name, length in (("archive_sha512", 128), ("inventory_digest", 64), ("registration_sha256", 64)):
        require(type(record[name]) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", record[name]), "invalid probe digest")
    for name in ("destination", "steam", "registration_source"):
        safe_path(record[name])
    require(Path(record["destination"]).name == "DroidDeck Prefix Test-" + record["probe_id"][6:], "probe destination identity differs")
    ids = record["baseline_ids"]
    require(type(ids) is list and len(ids) <= 4096 and all(type(key) is str and app_id(key) == key for key in ids) and len(set(ids)) == len(ids), "invalid baseline IDs")
    identity = record["exe_identity"]
    fields(identity, ("sha256", "size", "pe_machine", "provenance"))
    require(type(identity["size"]) is int and 0 < identity["size"] <= MAX_PROBE and identity["pe_machine"] == "x86" and
            identity["provenance"] == "local-measurement-only" and re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]), "invalid probe executable")


    if "creation_failure" in record:
        failure = record["creation_failure"]
        fields(failure, ("stage", "kind", "errno"))
        require(type(failure["stage"]) is str and failure["stage"] in CREATION_STAGES and
                failure["kind"] in ("invalid", "os-error", "interrupted"), "invalid creation failure code")
        require(failure["errno"] is None or type(failure["errno"]) is int and 0 < failure["errno"] < 4096,
                "invalid creation failure errno")
        require(record["status"] == "probe-failed" or record["status"] == "probe-ready" and "revalidation" in record,
                "invalid creation failure state")
    if "revalidation" in record:
        evidence = record["revalidation"]
        fields(evidence, ("schema_version", "tool_version", "previous_state", "previous_receipt_sha256", "history_record",
                          "archive_sha512", "inventory_digest", "registration_id", "registration_sha256", "context_digest"))
        require(type(evidence["schema_version"]) is int and evidence["schema_version"] == 1 and record["status"] == "probe-ready",
                "invalid revalidation schema/state")
        require(type(evidence["tool_version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", evidence["tool_version"]) and
                evidence["previous_state"] in ("creating", "probe-failed"), "invalid revalidation version/state")
        for name in ("previous_receipt_sha256", "registration_sha256", "context_digest"):
            require(type(evidence[name]) is str and re.fullmatch(r"[0-9a-f]{64}", evidence[name]), "invalid revalidation digest")
        require(evidence["archive_sha512"] == record["archive_sha512"] and evidence["inventory_digest"] == record["inventory_digest"],
                "revalidation archive differs")
        require(type(evidence["registration_id"]) is str and app_id(evidence["registration_id"]) == evidence["registration_id"] and
                evidence["registration_id"] not in ids, "invalid revalidation registration ID")
        require(evidence["history_record"] == record["probe_id"] + "-" + evidence["previous_receipt_sha256"] + ".json",
                "invalid revalidation history reference")


def _verify_revalidation_history(record, store_root):
    if "revalidation" not in record:
        return
    evidence = record["revalidation"]
    with PrivateStore(store_root) as store:
        previous, digest = store.read_record("probe-history", evidence["history_record"])
    _record_valid(previous)
    require(previous["status"] == evidence["previous_state"] and digest == evidence["previous_receipt_sha256"],
            "revalidation history hash/state differs")
    expected = {name: value for name, value in record.items() if name != "revalidation"}
    expected["status"] = evidence["previous_state"]
    require(previous == expected, "revalidation history content differs")


def _marker(record):
    return {"schema_version": 1, "purpose": "registration-only-probe", "probe_id": record["probe_id"],
            "member": MEMBER, "archive_sha512": record["archive_sha512"], "exe_sha256": record["exe_identity"]["sha256"]}


def inspect_incomplete_material(record, exe, key, source, steam, store_root, receipt_digest):
    """Observe every bounded postcondition; never finalize or repair failed material."""
    _record_valid(record)
    destination = safe_path(record["destination"])
    observations = []

    def observe(name, function):
        try:
            value = function()
            item = {"check": name, "result": "mismatch" if value is False else "passed"}
            if type(value) is dict:
                item["result"] = "observed"
                item["metadata"] = value
        except (OSError, ValueError, TypeError, KeyError) as error:
            item = {"check": name, "result": "unavailable", "error_class": type(error).__name__,
                    "errno": getattr(error, "errno", None)}
        observations.append(item)

    def metadata(path, directory=False):
        path = safe_path(path)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)
        fd = os.open(path, flags)
        try:
            info, current = os.fstat(fd), path.stat()
            return {"regular": stat.S_ISREG(info.st_mode), "directory": stat.S_ISDIR(info.st_mode),
                    "single_link": info.st_nlink == 1, "owner_matches_self": info.st_uid == os.getuid(),
                    "mode": f"{stat.S_IMODE(info.st_mode):04o}", "size_bytes": info.st_size,
                    "fd_path_same_inode": (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)}
        finally:
            os.close(fd)

    def directory_guards():
        parent_fd = os.open(safe_path(destination.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                parent_info, parent_path = os.fstat(parent_fd), destination.parent.stat()
                current, descriptor = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False), os.fstat(fd)
                path_info = destination.stat()
                return {"parent_fd_path_match": (parent_info.st_dev, parent_info.st_ino) == (parent_path.st_dev, parent_path.st_ino),
                        "child_dirfd_fd_match": (current.st_dev, current.st_ino) == (descriptor.st_dev, descriptor.st_ino),
                        "child_path_fd_match": (path_info.st_dev, path_info.st_ino) == (descriptor.st_dev, descriptor.st_ino)}
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

    def private_state():
        with PrivateStore(store_root) as store:
            current, digest = store.read_record("probe-runs", record["probe_id"] + ".json")
            return {"receipt_unchanged": current == record and digest == receipt_digest}

    def locks():
        from preparation_store import private
        with PrivateStore(store_root) as store, store.directory(("locks",)) as fd:
            result = {}
            names = {"global": "global.lock", "target": "prefix-" + hashlib.sha256(str(destination).encode()).hexdigest() + ".lock"}
            for label, name in names.items():
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    info = os.fstat(descriptor)
                    private(info)
                    current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    private(current)
                    result[label + "_fd_path_match"] = (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)
                finally:
                    os.close(descriptor)
            return result

    def registration_state():
        document, digest = load_json(source)
        games = registrations(document)
        selected = app_id(key)
        matches = []
        for game in games.values():
            try:
                if os.path.samefile(safe_path(game["exe"]), exe):
                    matches.append(game["app_id"])
            except FileNotFoundError:
                pass
        return {"selected_id_present": selected in games, "matching_exe_count": len(matches),
                "unique_match_is_selected": matches == [selected], "source_stable": load_json(source)[1] == digest}

    def prefix_state():
        base = safe_path(steam / "steamapps/compatdata", steam)
        require(not base.exists() or base.is_dir(), "invalid compatdata base")
        selected = app_id(key)
        count_aliases = 0
        if base.exists():
            with os.scandir(base) as children:
                for count, child in enumerate(children):
                    require(count < 4096, "too many prefix entries")
                    if re.fullmatch(r"-?[0-9]+", child.name) and int(child.name) % 2**32 == int(selected):
                        count_aliases += 1
        return {"canonical_exists": os.path.lexists(base / selected), "numeric_alias_count": count_aliases,
                "all_numeric_aliases_absent": count_aliases == 0}

    observe("created-parent-metadata", lambda: metadata(destination.parent, True))
    observe("created-folder-metadata", lambda: metadata(destination, True))
    observe("created-directory-guards-now", directory_guards)
    observe("created-exe-metadata", lambda: metadata(destination / EXE))
    observe("created-marker-metadata", lambda: metadata(destination / MARKER))
    observe("created-exe-matches-receipt", lambda: exe_identity(destination / EXE) == record["exe_identity"])
    observe("created-marker-matches-receipt", lambda: load_json(destination / MARKER)[0] == _marker(record))
    observe("registered-exe-samefile", lambda: os.path.samefile(exe, destination / EXE))
    observe("registered-folder-samefile", lambda: os.path.samefile(exe.parent, destination))
    observe("registered-exe-matches-receipt", lambda: exe_identity(exe) == record["exe_identity"])
    observe("steam-context-matches", lambda: record["steam"] == str(steam))
    observe("registration-source-context-matches", lambda: record["registration_source"] == str(source))
    observe("new-id-relative-to-baseline", lambda: app_id(key) not in record["baseline_ids"])
    observe("registration-current-state", registration_state)
    observe("prefix-current-state", prefix_state)
    observe("private-lock-files-now", locks)
    observe("private-receipt-stable", private_state)
    return {"receipt_state": record["status"],
            "original_failure_detail": "recorded-in-private-receipt" if "creation_failure" in record else "not-recorded-by-creator",
            "creation_failure": record.get("creation_failure"),
            "scope": "current-read-only-observations-not-historical-replay", "checks": observations,
            "directory_fsync": "not-retested-read-only", "locks_acquired": False,
            "material_modified": False, "receipt_finalized": False, "preparation_complete": False}


def verify_probe_registration(exe, key, source, steam, store_root):
    return _probe_registration(exe, key, source, steam, store_root)


def inspect_existing_probe_registration(exe, key, source, steam, store_root):
    evidence = _probe_registration(exe, key, source, steam, store_root, allow_existing=True)
    require(not evidence["prefix_absent"], "existing managed prefix required")
    evidence["purpose"] = "existing-managed-probe-inspection"
    return evidence


def _probe_registration(exe, key, source, steam, store_root, allow_existing=False):
    """Read only. Fixed step diagnostics never include raw receipts/paths/data."""
    history = []

    def step(name, function, *args):
        try:
            result = checked(name, function, *args)
        except (OSError, ValueError, TypeError, KeyError) as error:
            error.probe_registration_diagnostic = {"checks": history + [{"check": name, "result": "failed"}],
                                                   "read_only": True, "raw_record_included": False}
            raise
        history.append({"check": name, "result": "passed"})
        return result

    def receipt():
        with PrivateStore(store_root) as store:
            return store.read_record("probe-runs", marker["probe_id"] + ".json")

    exe, source, steam = [step("probe-input-paths", safe_path, path) for path in (exe, source, steam)]
    step("probe-exe-name", require, exe.name == EXE, "not a registration probe executable")
    marker, _ = step("probe-marker-read", load_json, exe.parent / MARKER)
    step("probe-marker-schema", require,
         type(marker) is dict and type(marker.get("probe_id")) is str and ID.fullmatch(marker["probe_id"]), "invalid probe marker")
    record, receipt_digest = step("probe-private-receipt-read", receipt)
    step("probe-private-receipt-schema", _record_valid, record)
    step("probe-revalidation-history", _verify_revalidation_history, record, store_root)
    if record["status"] != "probe-ready":
        observation = inspect_incomplete_material(record, exe, key, source, steam, store_root, receipt_digest)
        try:
            step("probe-private-receipt-ready", require, False, "probe receipt not ready")
        except ValueError as error:
            error.incomplete_probe_material = observation
            raise
    step("probe-private-receipt-ready", require, True, "probe receipt not ready")
    return _verify_registered_context(record, marker, exe, key, source, steam, receipt_digest, step, allow_existing=allow_existing)


def _verify_registered_context(record, marker, exe, key, source, steam, receipt_digest, step=checked, allow_existing=False):
    """Shared read-only conditions; readiness is enforced separately by each caller."""
    step("probe-steam-context", require, record["steam"] == str(steam), "probe Steam context differs")
    step("probe-registration-source-context", require, record["registration_source"] == str(source), "probe registration source context differs")
    step("probe-marker-receipt-match", require, marker == _marker(record), "probe marker differs from private receipt")
    destination = step("probe-created-path", safe_path, record["destination"])
    same_exe = step("probe-exe-samefile-read", os.path.samefile, exe, destination / EXE)
    step("probe-exe-path-identity", require, same_exe, "registered probe EXE path identity differs")
    same_directory = step("probe-folder-samefile-read", os.path.samefile, exe.parent, destination)
    step("probe-folder-path-identity", require, same_directory, "registered probe folder identity differs")
    identity = step("probe-exe-identity-read", exe_identity, exe)
    step("probe-exe-content-match", require, identity == record["exe_identity"], "registered probe bytes changed")
    document, source_digest = step("probe-registration-read", load_json, source)
    games = step("probe-registration-schema", registrations, document)
    key = step("probe-selected-id", app_id, key)
    step("probe-selected-id-present", require, key in games, "selected registration absent")
    step("probe-new-id-baseline", require, key not in record["baseline_ids"], "registration is not new relative to staging baseline")
    if "revalidation" in record:
        step("probe-revalidated-registration-id", require, record["revalidation"]["registration_id"] == key,
             "revalidated registration ID differs")

    def matching_ids():
        matches = []
        for game in games.values():
            try:
                same = os.path.samefile(safe_path(game["exe"]), exe)
            except FileNotFoundError:
                same = False  # Unrelated stale entries are not this existing probe inode.
            if same:
                matches.append(game["app_id"])
        return matches

    matches = step("probe-registration-path-scan", matching_ids)
    step("probe-registration-unique", require, matches == [key], "ambiguous probe registration")
    base = step("probe-compatdata-path", safe_path, steam / "steamapps/compatdata", steam)
    step("probe-compatdata-base", require, not base.exists() or base.is_dir(), "invalid compatdata base")
    names = (key, str(int(key) - 2**32)) if int(key) >= 2**31 else (key,)
    for name in names:
        if not allow_existing or name != key:
            step("probe-prefix-absent", require, not os.path.lexists(base / name), "probe prefix already exists; preserve it")

    def aliases_absent():
        if base.exists():
            with os.scandir(base) as children:
                for count, child in enumerate(children):
                    require(count < 4096, "too many prefix entries")
                    if allow_existing and child.name == key:
                        continue
                    if re.fullmatch(r"-?[0-9]+", child.name) and int(child.name) % 2**32 == int(key):
                        require(False, "probe prefix alias already exists; preserve it")

    step("probe-prefix-aliases-absent", aliases_absent)
    observed = step("probe-registration-reread", load_json, source)[1]
    step("probe-registration-stable", require, observed == source_digest, "registration changed during probe verification")
    return {"purpose": "registration-only-probe", "probe_id": record["probe_id"], "receipt_sha256": receipt_digest,
            "new_id_relative_to_baseline": True, "exe_matches_private_receipt": True, "prefix_absent": not os.path.lexists(base / key),
            "observed_registration_sha256": source_digest, "source_archive_sha512": record["archive_sha512"],
            "source_inventory_digest": record["inventory_digest"], "preparation_complete": False}


def interactive_workflow(directory, renderer, config=None, *, input_stream=None, output_stream=None, environment=None,
                         steam=None, settings=None, home=None, runtime_root=Path("/"), entry="prepare"):
    """Common entry of the four scripts (1.0.0): prepare, status, diagnose or recovery.

    Only an operational bundle is accepted; the earlier screens were removed in 1.0.1.
    """
    import sys

    import preparation_selection as selection
    from preparation_batch import interactive_entry

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    options = {"input_stream": stream, "output_stream": output, "environment": environment,
               "steam": steam, "settings": settings, "home": home, "runtime_root": runtime_root}
    require(selection.operational_layout(config), "operational bundle required")
    selection.validate_selection_config(config)
    return interactive_entry(entry, directory, renderer, config, **options)
