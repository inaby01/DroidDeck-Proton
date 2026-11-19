"""Read-only archive/installed-tree identity. Never extracts, imports or executes.

An operator-provided checksum establishes identity, not authenticity. Runtime
and external link targets remain separate from this inventory.
"""

import gzip
import hashlib
import os
import posixpath
import stat
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from preparation_assets import digest_json
from preparation_common import (
    Invalid,
    fields,
    regular_open,
    require,
    safe_path,
    unchanged,
)

MAX_ARCHIVE = 2 * 1024**3
MAX_MEMBER = 1024**3
MAX_EXPANDED = 8 * 1024**3
MAX_MEMBERS = 100000
CHUNK = 1024**2
OVERLAY_NAMES = frozenset(("compatibilitytool.vdf", "toolmanifest.vdf", "user_settings.py",
                           "softdenchi-install.json", "droiddeck-proton-wrap", "toolmanifest.vdf.droiddeck-orig"))


def _relative(name):
    require(type(name) is str and 0 < len(name.encode()) <= 1024 and
            not any(c in name for c in "\0\\\r\n"), "invalid payload path")
    parts = name.rstrip("/").split("/")
    require(all(part and part not in (".", "..") and part != ".env" and not part.startswith(".env.")
                for part in parts), "noncanonical or environment payload path")
    return "/".join(parts)


class _Reader:
    """Bound both streamed bytes and single parser read requests before allocating."""

    def __init__(self, stream, limit, digest=None):
        self.stream, self.limit, self.digest = stream, limit, digest
        self.count = 0

    def read(self, size):
        require(type(size) is int and 0 <= size <= CHUNK, "excessive archive parser request")
        raw = self.stream.read(size)
        self.count += len(raw)
        require(self.count <= self.limit, "archive stream limit exceeded")
        if self.digest is not None:
            self.digest.update(raw)
        return raw


class _TarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # Extended headers are consumed by tarfile before iteration yields them.
        # Bound them before its parser can request a large in-memory allocation.
        if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            require(self.size <= 64 * 1024, "excessive extended payload header")
        require(self.type != tarfile.GNUTYPE_SPARSE, "sparse payload forbidden")
        return super()._proc_member(archive)


def _hash(stream, expected):
    digest, total = hashlib.sha256(), 0
    while chunk := stream.read(CHUNK):
        total += len(chunk)
        require(total <= expected, "payload file grew")
        digest.update(chunk)
    require(total == expected, "truncated payload file")
    return digest.hexdigest()


def _link(name, target, hard=False):
    require(type(target) is str and 0 < len(target.encode()) <= 1024 and not any(c in target for c in "\0\\\r\n"),
            "invalid payload link")
    joined = posixpath.normpath(target if hard else posixpath.join(posixpath.dirname(name), target))
    return joined if not joined.startswith(("/", "../")) and joined != ".." else None


@dataclass(frozen=True)
class PayloadInventory:
    root: str
    archive_sha512: str
    root_mode: int
    entries: dict = field(repr=False)
    digest: str
    expanded_bytes: int
    external_links: int
    captured: dict = field(default_factory=dict, repr=False)

    def summary(self):
        kinds = {kind: sum(item["kind"] == kind for item in self.entries.values())
                 for kind in ("file", "directory", "symlink", "hardlink")}
        blockers = ["payload-provenance-unreviewed", "runtime-equivalence-unverified", "execution-not-exposed"]
        if self.external_links:
            blockers.append("external-link-targets-unverified")
        return {"archive_sha512": self.archive_sha512, "checksum_matches": True, "checksum_source": "operator-declared",
                "archive_root": self.root, "root_mode": self.root_mode, "inventory_digest": self.digest, "members": len(self.entries),
                "kinds": kinds, "expanded_file_bytes": self.expanded_bytes, "external_links": self.external_links,
                "blockers": blockers, "preparation_complete": False, "writes": []}


def inspect_archive(path, expected_sha512, root, capture=()):
    require(type(expected_sha512) is str and len(expected_sha512) == 128 and
            all(c in "0123456789abcdef" for c in expected_sha512), "expected SHA-512 required")
    require(path is not None, "payload archive required")
    require(_relative(root) == root and "/" not in root, "single archive root required")
    require(type(capture) in (tuple, list) and len(capture) <= 16 and len(set(capture)) == len(capture), "invalid capture selection")
    for name in capture:
        require(_relative(name) == name, "invalid capture path")
    captured, capture_bytes = {}, 0
    entries, expanded, root_seen, root_mode = {}, 0, False, None
    digest = hashlib.sha512()
    try:
        with regular_open(path, MAX_ARCHIVE) as source:
            before = os.fstat(source.fileno())
            compressed = _Reader(source, MAX_ARCHIVE, digest)
            with gzip.GzipFile(fileobj=compressed, mode="rb") as unpacked:
                reader = _Reader(unpacked, MAX_EXPANDED + 128 * CHUNK)
                with tarfile.open(fileobj=reader, mode="r|", tarinfo=_TarInfo) as package:
                    for member in package:
                        require(len(entries) < MAX_MEMBERS, "too many payload entries")
                        name = _relative(member.name)
                        require(name == root or name.startswith(root + "/"), "unexpected archive root")
                        name = name[len(root) + 1:] if name != root else ""
                        if not name:
                            require(not root_seen and member.isdir(), "invalid archive root entry")
                            require(not member.mode & 0o7000, "privileged archive root mode")
                            root_mode = member.mode & 0o777
                            root_seen = True
                            continue
                        require(name not in entries, "duplicate payload path")
                        require(0 <= member.size <= MAX_MEMBER and not member.issparse(), "excessive or sparse payload member")
                        entry = {"kind": "directory", "mode": member.mode & 0o777}
                        require(not member.mode & 0o7000, "privileged payload mode")
                        if member.isfile():
                            expanded += member.size
                            require(expanded <= MAX_EXPANDED, "expanded payload too large")
                            stream = package.extractfile(member)
                            with stream:
                                if name in capture:
                                    capture_bytes += member.size
                                    require(capture_bytes <= CHUNK, "captured metadata too large")
                                    raw = stream.read(member.size + 1)
                                    require(len(raw) == member.size, "truncated captured member")
                                    captured[name] = raw
                                    measured = hashlib.sha256(raw).hexdigest()
                                else:
                                    measured = _hash(stream, member.size)
                                entry.update(kind="file", size=member.size, sha256=measured)
                        elif member.issym() or member.islnk():
                            require(member.size == 0, "nonempty payload link")
                            target = member.linkname
                            if member.islnk():
                                require(target.startswith(root + "/"), "hardlink outside payload")
                                target = _relative(target[len(root) + 1:])
                            _link(name, target, member.islnk())
                            entry.update(kind="hardlink" if member.islnk() else "symlink", target=target)
                            if member.issym():
                                entry.pop("mode")  # Link text/type are compared; no target is followed.
                        else:
                            require(member.isdir(), "special payload file forbidden")
                        entries[name] = entry
                # Validate gzip trailer, account for trailing data and bound decompression.
                while reader.read(CHUNK):
                    pass
            while compressed.read(CHUNK):
                pass
            unchanged(before, os.fstat(source.fileno()))
            require(compressed.count == before.st_size and digest.hexdigest() == expected_sha512,
                    "payload archive checksum mismatch")
    except (tarfile.TarError, EOFError, gzip.BadGzipFile, zlib.error) as error:
        raise Invalid("invalid payload archive") from error
    require(root_seen and entries, "empty payload archive")
    for name, entry in entries.items():
        parent = str(PurePosixPath(name).parent)
        require(parent == "." or parent in entries and entries[parent]["kind"] == "directory", "missing or linked payload parent")
        if entry["kind"] == "hardlink":
            require(entry["target"] in entries and entries[entry["target"]]["kind"] == "file", "hardlink must target a regular member")
            target = entries[entry["target"]]
            entry.update(size=target["size"], sha256=target["sha256"], mode=target["mode"])
    external = sum(entry["kind"] == "symlink" and _link(name, entry["target"]) is None
                   for name, entry in entries.items())
    return PayloadInventory(root, expected_sha512, root_mode, entries,
                            digest_json({"root_mode": root_mode, "entries": entries}), expanded, external, captured)


class TreeMismatch(Invalid):
    """Fixed metadata-only discrepancy; no raw settings, link text or file bytes."""

    def __init__(self, check, relative_path=None, differing_fields=(), expected_mode=None, actual_mode=None):
        super().__init__("installed payload differs from archive/overlay")
        self.tree_diagnostic = {"check": check, "relative_path": relative_path, "differing_fields": list(differing_fields)}
        if expected_mode is not None:
            self.tree_diagnostic["expected_mode"] = format(expected_mode, "04o")
        if actual_mode is not None:
            self.tree_diagnostic["actual_mode"] = format(actual_mode, "04o")


def verify_tree(root, inventory, overlays=None):
    """Compare every installed object, including extras and hardlink topology.

    Allowed overlays must be generated by trusted installation/registration code;
    reading modified files and declaring those same hashes is not verification.
    No CLI overlay override exists. External symlink destinations are never read.
    """
    require(isinstance(inventory, PayloadInventory) and inventory.digest ==
            digest_json({"root_mode": inventory.root_mode, "entries": inventory.entries}), "payload inventory changed")
    root = safe_path(root)
    require(root.is_dir(), "installed payload absent")
    expected = {key: dict(value) for key, value in inventory.entries.items()}
    overlays = {} if overlays is None else overlays
    require(type(overlays) is dict and overlays.keys() <= OVERLAY_NAMES, "unsupported payload overlay")
    for name, entry in overlays.items():
        fields(entry, ("kind", "mode", "size", "sha256"))
        require(entry["kind"] == "file" and type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o777
                and type(entry["size"]) is int and 0 <= entry["size"] <= CHUNK
                and type(entry["sha256"]) is str and len(entry["sha256"]) == 64
                and all(c in "0123456789abcdef" for c in entry["sha256"]), "invalid generated overlay")
        expected[name] = dict(entry)
    seen, identities, total = {}, {}, 0

    def walk(directory_fd, relative=""):
        nonlocal total
        before = os.fstat(directory_fd)
        with os.scandir(directory_fd) as children:
            for child in children:
                require(len(seen) < MAX_MEMBERS, "too many installed payload objects")
                name = _relative(relative + child.name)
                if name not in expected or name in seen:
                    raise TreeMismatch("unexpected-object")
                info = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
                entry = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
                require(not info.st_mode & 0o7000, "privileged installed payload mode")
                identities[name] = (info.st_dev, info.st_ino, info.st_nlink)
                if stat.S_ISREG(info.st_mode):
                    require(info.st_size <= MAX_MEMBER, "installed payload file too large")
                    total += info.st_size
                    require(total <= MAX_EXPANDED, "installed payload too large")
                    fd = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                    with os.fdopen(fd, "rb") as stream:
                        unchanged(info, os.fstat(stream.fileno()))
                        entry.update(kind="file", size=info.st_size, sha256=_hash(stream, info.st_size))
                        unchanged(info, os.fstat(stream.fileno()))
                elif stat.S_ISLNK(info.st_mode):
                    entry.update(kind="symlink", target=os.readlink(child.name, dir_fd=directory_fd))
                    entry.pop("mode")
                else:
                    require(stat.S_ISDIR(info.st_mode), "special installed payload object")
                unchanged(info, os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False))
                want = dict(expected[name])
                if want["kind"] == "hardlink":
                    want.pop("target")
                    want["kind"] = "file"
                if entry != want:
                    changed = sorted(key for key in entry.keys() | want.keys() if entry.get(key) != want.get(key))
                    raise TreeMismatch("entry-differs", name, changed, want.get("mode"), entry.get("mode"))
                seen[name] = entry
                if entry["kind"] == "directory":
                    fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        unchanged(info, os.fstat(fd))
                        walk(fd, name + "/")
                    finally:
                        os.close(fd)
                    unchanged(info, os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False))
        unchanged(before, os.fstat(directory_fd))

    before = root.lstat()
    if stat.S_IMODE(before.st_mode) != inventory.root_mode:
        raise TreeMismatch("root-mode", expected_mode=inventory.root_mode, actual_mode=stat.S_IMODE(before.st_mode))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        unchanged(before, os.fstat(fd))
        walk(fd)
        safe_path(root)
        unchanged(before, root.lstat())
    finally:
        os.close(fd)
    if seen.keys() != expected.keys():
        raise TreeMismatch("missing-objects")
    groups = {}
    for name, entry in expected.items():
        if entry["kind"] == "file":
            groups.setdefault(name, [name])
        elif entry["kind"] == "hardlink":
            groups.setdefault(entry["target"], [entry["target"]]).append(name)
    for names in groups.values():
        actual = [identities[name] for name in names]
        if len(set(actual)) != 1 or actual[0][2] != len(names):
            raise TreeMismatch("hardlink-topology", names[0])
    return {"tree_matches": True, "inventory_digest": inventory.digest, "overlay_digest": digest_json(overlays),
            "checked_members": len(seen), "external_link_targets_checked": False,
            "payload_trust": "not-established-by-identity-check", "preparation_complete": False, "writes": []}


def inspect_tree_differences(root, inventory, overlays=None, limit=128):
    """Bounded diagnostic only: never adopts changes or reads unexpected objects.

    Known source paths may be disclosed; unknown names and link targets are not.
    Unexpected directories are reported at their boundary and never traversed.
    The strict verifier and all writer/launch predicates remain unchanged.
    """
    require(type(limit) is int and 1 <= limit <= 256, "invalid tree diagnostic limit")
    require(isinstance(inventory, PayloadInventory) and inventory.digest ==
            digest_json({"root_mode": inventory.root_mode, "entries": inventory.entries}), "payload inventory changed")
    expected = {name: dict(value) for name, value in inventory.entries.items()}
    overlays = {} if overlays is None else overlays
    require(type(overlays) is dict and overlays.keys() <= OVERLAY_NAMES, "unsupported payload overlay")
    expected.update(overlays)
    root = safe_path(root)
    result = {"scope": "read-only-tree-differences", "differences": [], "difference_count": 0,
              "truncated": False, "unknown_contents_read": False, "unexpected_subtrees_traversed": False,
              "execution_authorized": False, "preparation_complete": False, "writes": []}
    seen, identities = set(), {}
    total, entries = 0, 0

    def add(check, name=None, **data):
        result["difference_count"] += 1
        if len(result["differences"]) < limit:
            result["differences"].append({"check": check, **({"relative_path": name} if name is not None else {}), **data})
        else:
            result["truncated"] = True

    def walk(fd, prefix=""):
        nonlocal total, entries
        before = os.fstat(fd)
        with os.scandir(fd) as children:
            for child in children:
                entries += 1
                require(entries <= MAX_MEMBERS, "too many installed payload objects")
                name = prefix + child.name
                info = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                mode = stat.S_IMODE(info.st_mode)
                if name not in expected:
                    category = "distribution-lock" if name == "dist.lock" else "python-bytecode-cache" if child.name == "__pycache__" else "unknown-object"
                    add("unexpected-object", category=category, path_sha256=hashlib.sha256(os.fsencode(name)).hexdigest(),
                        kind="directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special",
                        mode=format(mode, "04o"), size=info.st_size, link_count=info.st_nlink)
                    continue
                seen.add(name)
                want = dict(expected[name])
                if want["kind"] == "hardlink":
                    want.pop("target")
                    want["kind"] = "file"
                actual = {"kind": "directory", "mode": mode}
                identities[name] = (info.st_dev, info.st_ino, info.st_nlink)
                if stat.S_ISREG(info.st_mode):
                    require(info.st_size <= MAX_MEMBER, "installed payload file too large")
                    total += info.st_size
                    require(total <= MAX_EXPANDED, "installed payload too large")
                    source = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    with os.fdopen(source, "rb") as stream:
                        unchanged(info, os.fstat(stream.fileno()))
                        actual.update(kind="file", size=info.st_size, sha256=_hash(stream, info.st_size))
                        unchanged(info, os.fstat(stream.fileno()))
                elif stat.S_ISLNK(info.st_mode):
                    actual = {"kind": "symlink", "target": os.readlink(child.name, dir_fd=fd)}
                elif not stat.S_ISDIR(info.st_mode):
                    actual["kind"] = "special"
                differing = sorted(key for key in actual.keys() | want.keys() if actual.get(key) != want.get(key))
                if differing:
                    add("entry-differs", name, differing_fields=differing,
                        expected_mode=None if "mode" not in want else format(want["mode"], "04o"), actual_mode=format(mode, "04o"))
                if stat.S_ISDIR(info.st_mode) and want["kind"] == "directory":
                    nested = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        unchanged(info, os.fstat(nested))
                        walk(nested, name + "/")
                    finally:
                        os.close(nested)
                unchanged(info, os.stat(child.name, dir_fd=fd, follow_symlinks=False))
        unchanged(before, os.fstat(fd))

    before = root.lstat()
    require(stat.S_ISDIR(before.st_mode), "installed payload absent")
    if stat.S_IMODE(before.st_mode) != inventory.root_mode:
        add("root-mode", expected_mode=format(inventory.root_mode, "04o"), actual_mode=format(stat.S_IMODE(before.st_mode), "04o"))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        unchanged(before, os.fstat(fd))
        walk(fd)
        unchanged(before, safe_path(root).stat())
    finally:
        os.close(fd)
    for name in sorted(expected.keys() - seen):
        add("missing-object", name)
    groups = {}
    for name, entry in expected.items():
        if entry["kind"] == "file":
            groups.setdefault(name, [name])
        elif entry["kind"] == "hardlink":
            groups.setdefault(entry["target"], [entry["target"]]).append(name)
    for names in groups.values():
        actual = [identities[name] for name in names if name in identities]
        if len(actual) == len(names) and (len(set(actual)) != 1 or actual[0][2] != len(names)):
            add("hardlink-topology", names[0])
    result.update(expected_members=len(expected), observed_entries=entries, known_members_observed=len(seen),
                  observed_tree_matches=result["difference_count"] == 0)
    return result
