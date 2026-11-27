"""Test-only builders for the dedicated registration probe, its trial and the legacy slot writer (removed from the tool in 1.0.1).

The tool no longer creates probe material, plans a probe trial or places through a probe registration.
The tests still build their disposable worlds this way, so these builders live here, copied from 1.0.0
(``dfd3eb81``). Never part of an emitted script.
"""

import gzip
import hashlib
import io
import json
import os
import secrets
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import preparation_trial as trial
from preparation_assets import digest_json, exe_identity, pe_machine
from preparation_common import (
    MAX_JSON,
    VERSION,
    checked,
    fields,
    load_json,
    regular_open,
    require,
    safe_path,
    unchanged,
)
from preparation_execution import _aliases
from preparation_installation import InstallationPlan
from preparation_payload import CHUNK, MAX_ARCHIVE, MAX_EXPANDED, _Reader, _TarInfo, inspect_archive
from preparation_processes import ProcessStopCheck
from preparation_probe import EXE, ID, MARKER, MAX_PROBE, MEMBER, _marker, _record_valid
from preparation_static_placement import StaticPlacementPlan, _plan_placement, _private_xalia_context, _proof
from preparation_target import registrations
from preparation_tool_writer import _write_installation_tree
from preparation_trial import SCOPE, TrialPlan


def _capture_probe(archive, inventory):
    expected = inventory.entries.get(MEMBER)
    require(expected is not None and expected["kind"] == "file" and 0 < expected["size"] <= MAX_PROBE,
            "bounded x86 cmd member required")
    raw, count = None, 0
    digest = hashlib.sha512()
    with regular_open(archive, MAX_ARCHIVE) as source:
        before = os.fstat(source.fileno())
        compressed = _Reader(source, MAX_ARCHIVE, digest)
        with gzip.GzipFile(fileobj=compressed, mode="rb") as unpacked:
            reader = _Reader(unpacked, MAX_EXPANDED + 128 * CHUNK)
            with tarfile.open(fileobj=reader, mode="r|", tarinfo=_TarInfo) as package:
                for member in package:
                    if member.name != inventory.root + "/" + MEMBER:
                        continue
                    count += 1
                    require(count == 1 and member.isfile() and member.size == expected["size"] and not member.issparse(), "probe member changed")
                    with package.extractfile(member) as data:
                        raw = data.read(member.size + 1)
                        require(len(raw) == member.size, "probe member truncated")
            while reader.read(CHUNK):
                pass
        while compressed.read(CHUNK):
            pass
        unchanged(before, os.fstat(source.fileno()))
        require(compressed.count == before.st_size and digest.hexdigest() == inventory.archive_sha512, "probe archive changed")
    require(raw is not None and hashlib.sha256(raw).hexdigest() == expected["sha256"] and
            pe_machine(io.BytesIO(raw), len(raw)) == "x86", "probe executable identity mismatch")
    return raw


@dataclass(frozen=True)
class ProbeMaterialPlan:
    digest: str
    record: dict = field(repr=False)
    archive: object = field(repr=False)
    archive_root: str
    raw: bytes = field(repr=False)

    def summary(self):
        record = self.record
        return {"mode": "probe-material-plan", "input_digest": self.digest, "probe_id": record["probe_id"],
                "destination": record["destination"], "exe": str(Path(record["destination"]) / EXE),
                "source_member": MEMBER, "exe_identity": dict(record["exe_identity"]),
                "baseline_registration_count": len(record["baseline_ids"]), "registration_action": "manual-or-app-rescan-not-performed",
                "planned_files": [EXE, MARKER], "private_receipt_required": True, "prefix_created": False,
                "exe_executed": False, "preparation_complete": False, "writes": []}


def plan_probe_material(archive, sha512, archive_root, source, steam, base, *, probe_id=None):
    archive, source, steam, base = map(safe_path, (archive, source, steam, base))
    require(steam.is_dir() and base.is_dir(), "existing Steam and probe base required")
    require(not (base == steam or base.is_relative_to(steam)), "probe base is inside Steam")
    document, source_digest = load_json(source)
    games = registrations(document)
    probe_id = "probe-" + secrets.token_hex(16) if probe_id is None else probe_id
    require(type(probe_id) is str and ID.fullmatch(probe_id), "invalid probe ID")
    destination = safe_path(base / ("DroidDeck Prefix Test-" + probe_id[6:]), base)
    require(not os.path.lexists(destination), "probe destination already exists")
    for game in games.values():
        protected = Path(game["exe"]).parent
        require(not (destination == protected or destination.is_relative_to(protected) or protected.is_relative_to(destination)),
                "probe destination overlaps registered game")
    inventory = checked("probe-archive-inspection", inspect_archive, archive, sha512, archive_root)
    raw = checked("probe-member-capture", _capture_probe, archive, inventory)
    identity = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "pe_machine": "x86", "provenance": "local-measurement-only"}
    record = {"schema_version": 1, "tool_version": VERSION, "probe_id": probe_id, "probe_revision": 1, "status": "creating",
              "destination": str(destination), "steam": str(steam), "registration_source": str(source),
              "baseline_ids": sorted(games, key=int), "registration_sha256": source_digest,
              "archive_sha512": sha512, "inventory_digest": inventory.digest, "member": MEMBER,
              "exe_identity": identity, "preparation_complete": False}
    _record_valid(record)
    fs = os.statvfs(base)
    require(fs.f_bavail * (fs.f_frsize or fs.f_bsize) >= len(raw) + 2 * MAX_JSON, "insufficient probe material space")
    require(load_json(source)[1] == source_digest, "registration changed before probe plan completed")
    return ProbeMaterialPlan(digest_json(record), record, archive, archive_root, raw)


def create_probe_material(plan, refresh, store):
    require(isinstance(plan, ProbeMaterialPlan) and callable(refresh), "trusted probe plan required")
    store._guard()
    record = dict(plan.record)
    _record_valid(record)
    destination = safe_path(record["destination"])
    require(store._held_target == hashlib.sha256(str(destination).encode()).hexdigest(), "matching probe material lock required")
    require(not (store.root == destination or store.root.is_relative_to(destination) or destination.is_relative_to(store.root)), "probe store overlaps destination")
    fresh = refresh()
    require(isinstance(fresh, ProbeMaterialPlan) and fresh.digest == plan.digest and fresh.record == record and fresh.raw == plan.raw,
            "probe material plan changed")
    require(plan.digest == digest_json(record) and hashlib.sha256(plan.raw).hexdigest() == record["exe_identity"]["sha256"], "probe plan mutated")
    filename = record["probe_id"] + ".json"
    record_hash = store.write_record("probe-runs", filename, record)
    parent_fd, fd = None, None
    phase = "open-parent"
    try:
        parent = safe_path(destination.parent)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_identity = os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino
        phase = "mkdir"
        os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
        phase = "open-destination"
        fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        identity = os.fstat(fd).st_dev, os.fstat(fd).st_ino
        def guard():
            store._guard()
            parent_now = safe_path(parent).stat()
            current = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            require((parent_now.st_dev, parent_now.st_ino) == parent_identity and (current.st_dev, current.st_ino) == identity,
                    "probe directory changed")
        for name, raw in ((EXE, plan.raw), (MARKER, (json.dumps(_marker(record), ensure_ascii=True, indent=2) + "\n").encode())):
            phase = "directory-guard"
            guard()
            phase = "open-exe" if name == EXE else "open-marker"
            out_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(out_fd, "wb") as output:
                info = os.fstat(output.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "invalid new probe file")
                phase = "write-exe" if name == EXE else "write-marker"
                output.write(raw)
                output.flush()
                phase = "sync-exe" if name == EXE else "sync-marker"
                os.fsync(output.fileno())
        phase = "directory-guard"
        guard()
        phase = "verify-exe"
        require(exe_identity(destination / EXE) == record["exe_identity"], "copied probe identity changed")
        phase = "verify-marker"
        require(load_json(destination / MARKER)[0] == _marker(record), "probe marker changed")
        phase = "sync-directory"
        os.fsync(fd)
        phase = "sync-parent"
        os.fsync(parent_fd)
        phase = "record-ready"
        record["status"] = "probe-ready"
        store.write_record("probe-runs", filename, record, record_hash)
        return {"mode": "probe-material-created", "probe_id": record["probe_id"], "destination": str(destination),
                "exe": str(destination / EXE), "exe_identity": record["exe_identity"],
                "selection_hint": {"base": "same-folder-as-prepare.sh", "relative_exe": destination.name + "/" + EXE},
                "writes": [{"path": str(destination), "scope": "new-registration-probe-files-only"},
                           {"path": str(store.root), "scope": "private-probe-receipt-and-locks"}],
                "prefix_created": False, "exe_executed": False, "registration_written": False, "preparation_complete": False}
    except BaseException as error:
        if not hasattr(error, "preparation_check"):
            error.preparation_check = "probe-create-" + phase
        code = getattr(error, "errno", None)
        record["status"] = "probe-failed"
        record["creation_failure"] = {"stage": phase,
            "kind": "invalid" if isinstance(error, ValueError) else "os-error" if isinstance(error, OSError) else "interrupted",
            "errno": code if type(code) is int and 0 < code < 4096 else None}
        try:
            store.write_record("probe-runs", filename, record, record_hash)
        except (OSError, ValueError):
            pass
        raise  # Preserve partial files and private creating/failed receipt; never delete user data.
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def plan_static_placement(installation, review, store_root, probe_store_root, settings):
    return _plan_placement(installation, review, store_root, probe_store_root, settings, "probe")


def plan_trial(placement, home):
    require(isinstance(placement, StaticPlacementPlan), "trusted reviewed placement required")
    installation = placement.installation
    trial._live_runtime(installation)
    report = installation.summary()
    require(report["action"] == "reuse-verified-tree", "verified installed preparation tool required")
    require(report["tool_slot"] == "preparation" and not report["prefix"]["exists"], "new dedicated prefix required")
    require(_proof(installation, placement.probe_store_root) == placement.probe, "dedicated probe changed")
    inventory = installation.inventory
    require(inventory.external_links == 0, "external payload links forbidden")
    require(not any(name in inventory.entries for name in ("dist", "dist.lock", "steampipe_fixups.json")),
            "mutable distribution maintenance path not supported for trial")
    require(inventory.entries.get("files/share/default_pfx_arm64", {}).get("kind") == "directory",
            "shipped arm64 default prefix required")
    home = safe_path(home)
    key = installation.target.registration_id
    work = safe_path(home / ".local/share/droiddeck-preparation-work" / key / "work", home)
    private_home = safe_path(work.parent / "home", home)
    compatdata = safe_path(installation.target.steam / "steamapps/compatdata" / key, installation.target.steam)
    _aliases(installation.target.steam, key)
    require(not os.path.lexists(compatdata) and not os.path.lexists(work.parent), "new trial paths required")
    for path in (work.parent, placement.store_root):
        for protected in (installation.target.steam, placement.settings, installation.target.exe.parent):
            require(path != protected and not path.is_relative_to(protected) and not protected.is_relative_to(path),
                    "trial paths overlap protected inputs")
    policy = _private_xalia_context(installation, placement.review)
    if policy is not None:
        policy.guard()
    files = [value for name, value in inventory.entries.items() if name.startswith("files/share/default_pfx_arm64/")]
    fs = os.statvfs(compatdata.parent)
    block = fs.f_frsize or fs.f_bsize
    require(block > 0 and files, "prefix allocation baseline unavailable")
    baseline = block + sum(((entry["size"] + block - 1) // block) * block if entry["kind"] == "file" else block for entry in files)
    require(fs.f_bavail * block >= baseline + trial.RESERVE, "insufficient prefix baseline and trial reserve")
    require(os.environ.get("COPYPREFIX") != "1", "COPYPREFIX=1 forbidden")
    signature = {"scope": SCOPE, "version": VERSION, "placement": placement.digest,
                 "home": str(home), "work": str(work), "compatdata": str(compatdata), "baseline": baseline}
    return TrialPlan(digest_json(signature), placement, home, work, private_home, compatdata, baseline)


def apply_installation(plan, refresh, store, settings, ready, stop_check):
    """Internal only. Identity is not provenance, and clear proc view is not stop scope.

    ready must independently establish target freshness, payload provenance, runtime
    suitability and the complete stopped scope. No CLI flags can supply readiness.
    Failure preserves staging/published trees; journal errors never trigger rollback.
    """
    require(isinstance(plan, InstallationPlan) and callable(refresh) and callable(ready), "trusted installation inputs required")
    store._guard()
    steam = safe_path(plan.target.steam)
    compatdata = safe_path(steam / "steamapps/compatdata" / plan.target.registration_id, steam)
    require(store._held_target == hashlib.sha256(str(compatdata).encode()).hexdigest(), "matching target lock required")
    require(isinstance(stop_check, ProcessStopCheck), "process observation required")
    settings = safe_path(settings)
    require(settings.is_dir(), "existing DroidDeck settings required")
    for root in (steam, settings, plan.target.exe.parent):
        require(not (store.root == root or store.root.is_relative_to(root) or root.is_relative_to(store.root)), "store overlaps installation inputs")
    require(steam != settings and not steam.is_relative_to(settings) and not settings.is_relative_to(steam), "settings overlap Steam")
    if plan.runtime.view != "current-root":
        require(all(path.is_relative_to(plan.runtime.root) and path != plan.runtime.root
                    for path in (steam, settings, store.root)), "snapshot writer must remain inside snapshot")
        require(safe_path(stop_check.proc_root).is_relative_to(plan.runtime.root), "snapshot proc scope outside snapshot")
    else:
        require(str(plan.runtime.root) == "/", "live runtime root required")
        require(safe_path(stop_check.proc_root) == safe_path("/proc"), "live installation requires live proc observation")

    def check_ready(published=False):
        store._guard()
        checks = ready()
        fields(checks, ("target", "payload", "runtime", "stopped"))
        require(all(value is True for value in checks.values()), "installation prerequisites unverified")
        require(isinstance(stop_check, ProcessStopCheck) and safe_path(stop_check.compatdata) == compatdata,
                "matching process observation required")
        require(stop_check.check()["clear_in_view"], "active or unknown prefix process")
        plan.target.verify()
        plan.runtime.verify()

    return _write_installation_tree(plan, refresh, store, settings, check_ready)
