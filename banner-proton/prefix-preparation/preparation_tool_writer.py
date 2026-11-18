"""Internal Linux tool installation: private staging, full verification, no replacement.

No Wine/helper/user_settings execution. The caller supplies trusted readiness and
refresh functions, holds private global/target locks, and owns the DroidDeck roots.
Snapshot writes are confined to that snapshot; they never authorize a live launch.
"""

import contextlib
import gzip
import hashlib
import os
import secrets
import stat
import tarfile

from preparation_binding import droiddeck_lock
from preparation_common import (
    VERSION,
    fields,
    regular_open,
    require,
    safe_path,
    unchanged,
)
from preparation_installation import InstallationPlan
from preparation_payload import (
    CHUNK,
    MAX_ARCHIVE,
    MAX_EXPANDED,
    _Reader,
    _relative,
    _TarInfo,
    verify_tree,
)
from preparation_processes import ProcessStopCheck
from preparation_publication import _publish, _rename_function


@contextlib.contextmanager
def _parent(root_fd, name):
    require(_relative(name) == name, "noncanonical extraction path")
    parts = name.split("/")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd, parts[-1]
    finally:
        os.close(fd)


def _owned_directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022,
            "installation directory must be owned and not writable by others")
    return info.st_dev, info.st_ino


def _stream_tree(archive, inventory, root_fd, guard):
    """Materialize only pinned entries through directory FDs, never extractall."""
    entries = inventory.entries
    require(not inventory.root_mode & 0o022 and inventory.root_mode & 0o500 == 0o500,
            "unsupported payload root permissions")
    for entry in entries.values():
        if entry["kind"] in ("file", "directory", "hardlink"):
            require(not entry["mode"] & 0o022 and entry["mode"] & 0o400,
                    "unsupported payload permissions")
        if entry["kind"] == "directory":
            require(entry["mode"] & 0o100, "unsearchable payload directory")
    directories = sorted((name for name in entries if entries[name]["kind"] == "directory"), key=lambda name: (name.count("/"), name))
    for name in directories:
        guard()
        with _parent(root_fd, name) as (fd, leaf):
            os.mkdir(leaf, 0o700, dir_fd=fd)
    seen, root_seen = set(), False
    digest = hashlib.sha512()
    with regular_open(archive, MAX_ARCHIVE) as source:
        before = os.fstat(source.fileno())
        compressed = _Reader(source, MAX_ARCHIVE, digest)
        with gzip.GzipFile(fileobj=compressed, mode="rb") as unpacked:
            reader = _Reader(unpacked, MAX_EXPANDED + 128 * CHUNK)
            with tarfile.open(fileobj=reader, mode="r|", tarinfo=_TarInfo) as package:
                for member in package:
                    guard()
                    name = _relative(member.name)
                    require(not member.mode & 0o7000 and not member.issparse(), "unsafe archive member")
                    if name == inventory.root:
                        require(not root_seen and member.isdir() and member.mode & 0o777 == inventory.root_mode,
                                "archive root changed")
                        root_seen = True
                        continue
                    require(name.startswith(inventory.root + "/"), "archive root changed")
                    name = name[len(inventory.root) + 1:]
                    require(name in entries and name not in seen, "archive entry changed")
                    seen.add(name)
                    expected = entries[name]
                    if expected["kind"] == "file":
                        require(member.isfile() and member.size == expected["size"] and member.mode & 0o777 == expected["mode"],
                                "archive regular member changed")
                        measured, remaining = hashlib.sha256(), member.size
                        with _parent(root_fd, name) as (fd, leaf), package.extractfile(member) as data:
                            output_fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                            with os.fdopen(output_fd, "wb") as output:
                                while remaining:
                                    raw = data.read(min(CHUNK, remaining))
                                    require(raw and len(raw) <= remaining, "truncated archive member")
                                    output.write(raw)
                                    measured.update(raw)
                                    remaining -= len(raw)
                                require(measured.hexdigest() == expected["sha256"], "archive bytes changed")
                                output.flush()
                                os.fchmod(output.fileno(), expected["mode"])
                                os.fsync(output.fileno())
                    elif expected["kind"] == "directory":
                        require(member.isdir() and member.size == 0 and member.mode & 0o777 == expected["mode"], "archive directory changed")
                    else:
                        hard = expected["kind"] == "hardlink"
                        require((member.islnk() if hard else member.issym()) and member.size == 0 and
                                member.linkname == (inventory.root + "/" if hard else "") + expected["target"], "archive link changed")
            while reader.read(CHUNK):
                pass
        while compressed.read(CHUNK):
            pass
        unchanged(before, os.fstat(source.fileno()))
        require(root_seen and seen == entries.keys() and compressed.count == before.st_size and
                digest.hexdigest() == inventory.archive_sha512, "archive changed during staging")
    # Defer all links until every regular member is present. Payload parents are
    # prevalidated directories; no archived link is ever traversed while writing.
    for name, entry in entries.items():
        if entry["kind"] not in ("hardlink", "symlink"):
            continue
        guard()
        with _parent(root_fd, name) as (fd, leaf):
            if entry["kind"] == "symlink":
                os.symlink(entry["target"], leaf, dir_fd=fd)
            else:
                with _parent(root_fd, entry["target"]) as (source_fd, source_leaf):
                    os.link(source_leaf, leaf, src_dir_fd=source_fd, dst_dir_fd=fd, follow_symlinks=False)
    return directories


def _customize(root_fd, plan, directories):
    for name, raw in plan.customization.files.items():
        with _parent(root_fd, name) as (fd, leaf):
            if name in plan.inventory.entries:
                os.unlink(leaf, dir_fd=fd)  # Only the pinned member inside our new private tree.
            output_fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(output_fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fchmod(output.fileno(), plan.customization.overlays[name]["mode"])
                os.fsync(output.fileno())
    for name in reversed(directories):
        with _parent(root_fd, name + "/placeholder") as (fd, _):
            os.fchmod(fd, plan.inventory.entries[name]["mode"])
            os.fsync(fd)
    os.fchmod(root_fd, plan.inventory.root_mode)
    os.fsync(root_fd)


def validate_installation_record(record):
    fields(record, ("schema_version", "tool_version", "installation_id", "app_id", "input_digest", "status",
                    "phase", "staging_name", "directory", "published", "preparation_complete"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and record["tool_version"] == VERSION,
            "unknown installation record version")
    token = record["installation_id"]
    require(type(token) is str and token.startswith("installation-") and len(token) == 45 and
            all(c in "0123456789abcdef" for c in token[13:]), "invalid installation ID")
    from preparation_common import SHA256, app_id
    require(app_id(record["app_id"]) == record["app_id"] and type(record["input_digest"]) is str and
            SHA256.fullmatch(record["input_digest"]), "invalid installation identity")
    require(record["staging_name"] == ".prefix-preparation-staging-" + token[13:] and
            type(record["directory"]) is str and _relative(record["directory"]) == record["directory"] and
            "/" not in record["directory"], "invalid installation names")
    require(record["status"] in ("running", "failed", "needs-inspection", "installed-tree-verified", "reused-tree-verified") and
            record["phase"] in ("planned", "staging", "tree-verified", "publish-intent", "published", "post-verified") and
            type(record["published"]) is bool and record["preparation_complete"] is False, "invalid installation status")

    status, phase, published = record["status"], record["phase"], record["published"]
    require(not published or phase in ("published", "post-verified"), "inconsistent publication phase")
    require(phase != "published" or published, "publication outcome missing")
    if status == "installed-tree-verified":
        require(phase == "post-verified" and published, "installation verification incomplete")
    elif status == "reused-tree-verified":
        require(phase == "post-verified" and not published, "reuse cannot publish")
    elif status == "failed":
        require(not published and phase in ("planned", "staging", "tree-verified"), "uncertain publication requires inspection")
    elif status == "running":
        require(phase != "post-verified", "running record cannot claim completion")


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

    def check_ready():
        store._guard()
        checks = ready()
        fields(checks, ("target", "payload", "runtime", "stopped"))
        require(all(value is True for value in checks.values()), "installation prerequisites unverified")
        require(isinstance(stop_check, ProcessStopCheck) and safe_path(stop_check.compatdata) == compatdata,
                "matching process observation required")
        require(stop_check.check()["clear_in_view"], "active or unknown prefix process")
        plan.target.verify()
        plan.runtime.verify()

    def refreshed():
        current = refresh()
        require(isinstance(current, InstallationPlan) and current.digest == plan.digest and current.target == plan.target and
                current.inventory == plan.inventory and current.customization == plan.customization and
                current.runtime.identity_digest == plan.runtime.identity_digest, "installation plan changed")
        return current

    check_ready()
    with droiddeck_lock(settings) as check_lock:
        current = refreshed()
        check_ready()
        token = secrets.token_hex(16)
        record = {"schema_version": 1, "tool_version": VERSION, "installation_id": "installation-" + token,
                  "app_id": plan.target.registration_id, "input_digest": plan.digest, "status": "running", "phase": "planned",
                  "staging_name": ".prefix-preparation-staging-" + token, "directory": current.customization.directory,
                  "published": False, "preparation_complete": False}
        validate_installation_record(record)
        record_hash = store.write_record("installations", record["installation_id"] + ".json", record)

        def save():
            nonlocal record_hash
            record_hash = store.write_record("installations", record["installation_id"] + ".json", record, record_hash)

        try:
            if current.summary()["action"] == "reuse-verified-tree":
                check_lock()
                check_ready()
                record.update(status="reused-tree-verified", phase="post-verified")
                save()
                return dict(record)
            rename = _rename_function()  # No platform fallback, before installation writes.
            require(current.summary()["capacity"]["estimate_fits"], "insufficient estimated installation space")
            with contextlib.ExitStack() as stack:
                steam_fd = os.open(steam, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                stack.callback(os.close, steam_fd)
                steam_identity = _owned_directory(steam_fd)
                try:
                    os.mkdir("compatibilitytools.d", 0o700, dir_fd=steam_fd)
                    os.fsync(steam_fd)
                except FileExistsError:
                    pass
                tools = safe_path(steam / "compatibilitytools.d", steam)
                tools_fd = os.open("compatibilitytools.d", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=steam_fd)
                stack.callback(os.close, tools_fd)
                tools_identity = _owned_directory(tools_fd)

                def anchor():
                    store._guard()
                    check_lock()
                    for path, identity in ((steam, steam_identity), (tools, tools_identity)):
                        info = safe_path(path).stat()
                        require((info.st_dev, info.st_ino) == identity and info.st_uid == os.getuid() and not info.st_mode & 0o022,
                                "installation parent changed")

                anchor()
                os.mkdir(record["staging_name"], 0o700, dir_fd=tools_fd)
                stage_fd = os.open(record["staging_name"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=tools_fd)
                stack.callback(os.close, stage_fd)
                os.fchmod(stage_fd, 0o700)
                stage_identity = _owned_directory(stage_fd)
                os.fsync(tools_fd)
                os.mkdir("tree", 0o700, dir_fd=stage_fd)
                tree_fd = os.open("tree", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
                stack.callback(os.close, tree_fd)
                tree_identity = _owned_directory(tree_fd)

                def guard():
                    anchor()
                    info = os.stat(record["staging_name"], dir_fd=tools_fd, follow_symlinks=False)
                    require((info.st_dev, info.st_ino) == stage_identity and stat.S_IMODE(info.st_mode) == 0o700,
                            "staging directory changed")
                    info = os.stat("tree", dir_fd=stage_fd, follow_symlinks=False)
                    require((info.st_dev, info.st_ino) == tree_identity, "staging tree changed")

                record["phase"] = "staging"
                save()
                # Refresh source archive path is caller-bound by the same inventory.
                # The plan carries the exact original path privately.
                directories = _stream_tree(current.archive, current.inventory, tree_fd, guard)
                _customize(tree_fd, current, directories)
                stage = tools / record["staging_name"]
                verify_tree(stage / "tree", current.inventory, current.customization.overlays)
                os.fsync(stage_fd)
                record["phase"] = "tree-verified"
                save()
                refreshed()
                check_ready()
                guard()
                record["phase"] = "publish-intent"
                save()
                guard()
                _publish(rename, stage_fd, tools_fd, current.customization.directory)
                record.update(published=True, phase="published")
                os.fsync(tools_fd)
                os.fsync(stage_fd)
                save()
                anchor()
                check_ready()
                verify_tree(tools / current.customization.directory, current.inventory, current.customization.overlays)
                info = os.stat(record["staging_name"], dir_fd=tools_fd, follow_symlinks=False)
                require((info.st_dev, info.st_ino) == stage_identity, "staging directory replaced after publication")
                os.rmdir(record["staging_name"], dir_fd=tools_fd)  # Only our own empty wrapper; no recursive deletion.
                os.fsync(tools_fd)
                record.update(status="installed-tree-verified", phase="post-verified")
                save()
                return dict(record)
        except BaseException:
            record["status"] = "needs-inspection" if record["published"] or record["phase"] == "publish-intent" else "failed"
            try:
                save()
            except (OSError, ValueError):
                pass  # Preserve the original error; last durable phase requires reinspection.
            raise
