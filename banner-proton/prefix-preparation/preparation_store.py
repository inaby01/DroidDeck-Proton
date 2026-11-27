"""Private, bounded cache and journal primitives. Never writes a game or prefix."""

import contextlib
import fcntl
import hashlib
import itertools
import json
import os
import re
import secrets
import stat

from preparation_assets import (
    INPUT_LIMITS,
    asset_blockers,
    digest_json,
    measure_stream,
    sha256,
    source_path,
    validate_manifest,
)
from preparation_binding import validate_binding_record
from preparation_common import (
    MAX_JSON,
    VERSION,
    Invalid,
    bounded,
    fields,
    identifier,
    pairs,
    regular_open,
    require,
    safe_path,
)
from preparation_tool_writer import validate_installation_record

MAX_OBJECTS = 4096
MARKER = {"schema_version": 1, "application": "droiddeck-prefix-preparation"}
STEP_STATES = ("pending", "running", "succeeded", "failed", "needs-user")
COMPONENT = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z", re.ASCII)


def private(info, directory=False):
    require(info.st_uid == os.getuid(), "managed object has another owner")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "invalid managed object type")
    require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), "managed object is not private")
    require(directory or info.st_nlink == 1, "managed file has multiple links")


def decode(raw):
    require(len(raw) <= MAX_JSON, "record too large")
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        bounded(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid private record") from error
    return value


def valid_marker(raw):
    value = decode(raw)
    require(type(value) is dict and type(value.get("schema_version")) is int and value == MARKER, "unknown store schema")


def encode(value):
    bounded(value)
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    require(len(raw) <= MAX_JSON, "record too large")
    return raw


class PrivateStore:
    """One explicit management root, anchored directory FDs, no automatic deletion."""

    def __init__(self, root, create=False):
        self.root = safe_path(root)
        require(len(self.root.parts) >= 4, "management root must be a dedicated subdirectory")
        if create:
            try:
                self.root.mkdir(mode=0o700)  # Parent must already exist; never chmod arbitrary parents.
            except FileExistsError:
                pass
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._held_target = None
        try:
            private(os.fstat(self.fd), True)
            self._identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino)
            marker = self._read(self.fd, "store.json", missing=True)
            if marker is None:
                require(create and not self._names(self.fd), "unrecognized management root")
                with self._new(self.fd, "store.json") as stream:
                    stream.write(encode(MARKER))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(self.fd)
            else:
                valid_marker(marker)
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def _anchor(self):
        safe_path(self.root)
        info = self.root.stat()
        private(info, True)
        require((info.st_dev, info.st_ino) == self._identity, "management root replaced")
        valid_marker(self._read(self.fd, "store.json"))

    @staticmethod
    def _names(fd):
        with os.scandir(fd) as entries:
            names = [entry.name for entry in itertools.islice(entries, MAX_OBJECTS + 1)]
        require(len(names) <= MAX_OBJECTS, "management object limit reached")
        return names

    @contextlib.contextmanager
    def directory(self, parts, create=False):
        self._anchor()
        fd = os.dup(self.fd)
        try:
            for name in parts:
                require(type(name) is str and COMPONENT.fullmatch(name), "invalid managed component")
                if create:
                    self._capacity(fd)
                    try:
                        os.mkdir(name, mode=0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    private(os.fstat(following), True)
                except BaseException:
                    os.close(following)
                    raise
                os.close(fd)
                fd = following
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def _capacity(fd):
        require(len(PrivateStore._names(fd)) < MAX_OBJECTS, "management object limit reached")

    @staticmethod
    @contextlib.contextmanager
    def _new(fd, name):
        require(type(name) is str and COMPONENT.fullmatch(name), "invalid managed filename")
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(descriptor, "wb") as stream:
            private(os.fstat(stream.fileno()))
            yield stream

    @staticmethod
    @contextlib.contextmanager
    def _existing(fd, name, limit=MAX_JSON):
        require(type(name) is str and COMPONENT.fullmatch(name), "invalid managed filename")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            private(info)
            require(info.st_size <= limit, "managed input too large")
            yield stream

    @staticmethod
    def _read(fd, name, missing=False):
        try:
            with PrivateStore._existing(fd, name) as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read(MAX_JSON + 1)
                after = os.fstat(stream.fileno())
                require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "record changed during read")
                require(len(raw) <= MAX_JSON, "record too large")
                return raw
        except FileNotFoundError:
            require(missing, "managed record missing")
            return None

    def _guard(self):
        self._anchor()
        require(self._held_target is not None, "global and target locks required")
        with self.directory(("locks",)) as fd:
            info = os.fstat(fd)
            pinned = os.fstat(self._lock_directory)
            require((info.st_dev, info.st_ino) == (pinned.st_dev, pinned.st_ino), "lock directory replaced")
            for name, descriptor in self._lock_files:
                locked = os.fstat(descriptor)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                private(current)
                require((locked.st_dev, locked.st_ino) == (current.st_dev, current.st_ino), "held lock replaced")

    @contextlib.contextmanager
    def locked(self, key):
        sha256(key)
        require(self._held_target is None, "nested locking forbidden")
        handles = []
        self._lock_files = []
        with self.directory(("locks",), create=True) as fd:
            try:
                # Fixed order: global -> prefix. Lock files persist and are never unlinked.
                for name in ("global.lock", "prefix-" + key + ".lock"):
                    self._capacity(fd)
                    descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
                    handles.append(descriptor)
                    self._lock_files.append((name, descriptor))
                    info = os.fstat(descriptor)
                    private(info)
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as error:
                        raise Invalid("preparation already locked") from error
                    current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), "lock file replaced")
                self._lock_directory = fd
                self._held_target = key
                yield self
            finally:
                self._held_target = None
                for descriptor in reversed(handles):
                    os.close(descriptor)  # Closing also releases flock, including after exceptions.

    def write_record(self, directory, name, value, expected_hash=None, before_commit=None):
        self._guard()
        require(COMPONENT.fullmatch(name), "invalid record filename")
        raw = encode(value)
        with self.directory((directory,), create=True) as fd:
            old = self._read(fd, name, missing=True)
            require((None if old is None else hashlib.sha256(old).hexdigest()) == expected_hash, "record changed since read")
            self._capacity(fd)
            temporary = "tmp-" + secrets.token_hex(16) + ".json"
            try:
                with self._new(fd, temporary) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                if before_commit is not None:
                    before_commit()
                self._guard()
                require(self._read(fd, name, missing=True) == old, "record changed before atomic write")
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
            finally:
                # Only our own transient JSON file, never user data or interrupted cache contents.
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
        return hashlib.sha256(raw).hexdigest()

    def retire_record(self, directory, name, destination):
        """Move one record to retired/<destination>/<directory>/ (1.0.0 redo). Never deletes or replaces;
        readers of ``directory`` no longer see it."""
        self._guard()
        require(COMPONENT.fullmatch(name) and not name.startswith("tmp-"), "invalid record filename")
        with self.directory((directory,)) as source, \
                self.directory(("retired", destination, directory), create=True) as target:
            raw = self._read(source, name)
            try:
                os.stat(name, dir_fd=target, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                require(False, "retired record already exists")
            self._guard()
            os.rename(name, name, src_dir_fd=source, dst_dir_fd=target)
            os.fsync(target)
            os.fsync(source)
        return hashlib.sha256(raw).hexdigest()

    def write_new_large(self, directory, name, value, limit):
        """Create a large private JSON record once; an existing name is never replaced.

        Written to a temporary file and published with a non-replacing rename, so a
        reader sees either nothing or the complete record. Returns the SHA-256 of the bytes.
        """
        from preparation_publication import _rename_function, rename_noreplace
        self._guard()
        require(type(name) is str and COMPONENT.fullmatch(name) and name.endswith(".json") and not name.startswith("tmp-"),
                "invalid record filename")
        bounded(value)
        raw = (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
        require(len(raw) <= limit, "record too large")
        rename = _rename_function()
        with self.directory((directory,), create=True) as fd:
            self._capacity(fd)
            temporary = "tmp-" + secrets.token_hex(16) + ".json"
            try:
                with self._new(fd, temporary) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._guard()
                rename_noreplace(rename, fd, temporary, fd, name)
                os.fsync(fd)
            finally:
                # Only our own transient file.
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
        return hashlib.sha256(raw).hexdigest()

    def read_large(self, directory, name, limit):
        """A large private JSON record and its SHA-256, or None when it does not exist."""
        try:
            with self.directory((directory,)) as fd, self._existing(fd, name, limit) as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
        except FileNotFoundError:
            return None
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and len(raw) <= limit,
                "record changed during read")
        try:
            value = json.loads(raw, object_pairs_hook=pairs)
            bounded(value)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Invalid("invalid private record") from error
        return value, hashlib.sha256(raw).hexdigest()

    def read_record(self, directory, name):
        with self.directory((directory,)) as fd:
            raw = self._read(fd, name)
        return decode(raw), hashlib.sha256(raw).hexdigest()

    @staticmethod
    def cache_name(spec):
        return identifier(spec["asset_id"]) + "-r" + str(spec["revision"])

    def verify_asset(self, spec):
        validate_manifest({"schema_version": 1, "assets": [spec]})
        with self.directory(("assets", self.cache_name(spec))) as fd:
            receipt = decode(self._read(fd, "receipt.json"))
            fields(receipt, ("schema_version", "tool_version", "spec", "spec_digest", "measured"))
            require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1, "unknown cache schema")
            validate_manifest({"schema_version": 1, "assets": [receipt["spec"]]})
            require(receipt["spec"] == spec and receipt["spec_digest"] == digest_json(spec), "same asset revision has different metadata")
            with self._existing(fd, "payload.bin", INPUT_LIMITS[spec["format"]]) as stream:
                measured = measure_stream(stream, INPUT_LIMITS[spec["format"]], spec["format"])
            require(measured == receipt["measured"] and not asset_blockers(spec, measured), "cached asset modified or blocked")
        return measured

    def cache_asset(self, spec, source_root, timestamps=True):
        """Copy a declared asset into the private cache. ``timestamps=False`` is only for the
        operator's asset folder (the folder of prepare.sh); other callers keep the strict read."""
        self._guard()
        validate_manifest({"schema_version": 1, "assets": [spec]})
        require(not asset_blockers(spec, {"sha256": spec["expected_sha256"], "size": spec["expected_size"],
                                          "pe_machine": spec["pe_machine"]}), "asset evidence incomplete")
        path = source_path(source_root, spec)
        with self.directory(("assets",), create=True) as parent:
            name = self.cache_name(spec)
            if name in self._names(parent):
                # Missing receipt, incompatible metadata or modified bytes fail; never overwrite.
                return {"action": "reused", "measured": self.verify_asset(spec)}
            # Open and validate the source before reserving a new incomplete cache slot.
            with regular_open(path, INPUT_LIMITS[spec["format"]]) as source:
                self._capacity(parent)
                os.mkdir(name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
                with self.directory(("assets", name)) as fd:
                    with self._new(fd, "payload.bin") as destination:
                        # From the operator's asset folder its timestamps are not compared; the copy is
                        # hashed here and the private copy is measured again strictly below.
                        measured = measure_stream(source, INPUT_LIMITS[spec["format"]], spec["format"], destination,
                                                  timestamps=timestamps)
                        destination.flush()
                        os.fsync(destination.fileno())
                    require(not asset_blockers(spec, measured), "copied bytes do not match expected asset")
                    with self._existing(fd, "payload.bin", INPUT_LIMITS[spec["format"]]) as stream:
                        require(measure_stream(stream, INPUT_LIMITS[spec["format"]], spec["format"]) == measured,
                                "cached copy changed")
                    receipt = {"schema_version": 1, "tool_version": VERSION, "spec": spec,
                               "spec_digest": digest_json(spec), "measured": measured}
                    # A receipt is the commit marker; failures before it remain explicitly incomplete.
                    self._guard()
                    with self._new(fd, "receipt.json") as stream:
                        stream.write(encode(receipt))
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fsync(fd)
        self.verify_asset(spec)
        return {"action": "created", "measured": measured}

    def inventory(self):
        """Read-only bounded inventory. Incomplete objects remain visible, never deleted."""
        result = {"assets": [], "bindings": [], "installations": [], "dependency_installs": [], "game_prefixes": [], "prefix_dlls": [], "backups": [], "temporary_records": []}
        for directory in ("assets", "bindings", "installations", "dependency-installs", "game-prefixes",
                          "prefix-dlls", "backups"):
            try:
                with self.directory((directory,)) as fd:
                    names = self._names(fd)
            except FileNotFoundError:
                continue
            for name in sorted(names):
                require(COMPONENT.fullmatch(name), "unknown managed object name")
                if directory == "backups":
                    try:
                        with self.directory(("backups", name)) as fd:
                            files = self._names(fd)
                            require(all(COMPONENT.fullmatch(item) for item in files), "invalid backup name")
                        result["backups"].append({"backup_id": name, "files": sorted(files), "contents": "private"})
                    except (OSError, Invalid):
                        result["backups"].append({"object": name, "status": "invalid"})
                elif directory == "bindings" and not name.startswith("tmp-"):
                    try:
                        record, _ = self.read_record("bindings", name)
                        validate_binding_record(record)
                        result["bindings"].append({"binding_id": record["binding_id"], "status": record["status"],
                                                  "completed_files": record["completed_files"], "preparation_complete": False})
                    except (OSError, Invalid, TypeError, KeyError):
                        result["bindings"].append({"object": name, "status": "invalid"})
                elif directory == "game-prefixes" and not name.startswith("tmp-"):
                    try:
                        from preparation_game_prefix import ID_PREFIX
                        from preparation_game_prefix import SCOPE as GAME_SCOPE
                        from preparation_trial import validate_trial_record
                        record, _ = self.read_record("game-prefixes", name)
                        validate_trial_record(record, GAME_SCOPE, ID_PREFIX)
                        result["game_prefixes"].append({key: record[key] for key in
                            ("trial_id", "app_id", "scope", "status", "phase", "exit_code", "preparation_complete")})
                        result["game_prefixes"][-1]["profile_id"] = record.get("profile", {}).get("profile_id")
                        result["game_prefixes"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["game_prefixes"].append({"object": name, "status": "invalid"})
                elif directory == "dependency-installs" and not name.startswith("tmp-"):
                    try:
                        from preparation_dependency_install import (
                            validate_install_record,
                        )
                        record, _ = self.read_record("dependency-installs", name)
                        validate_install_record(record)
                        result["dependency_installs"].append({key: record[key] for key in
                            ("install_id", "created_ns", "app_id", "trial_id", "status", "phase", "post_state", "preparation_complete")})
                        result["dependency_installs"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["dependency_installs"].append({"object": name, "status": "invalid"})
                elif directory == "prefix-dlls" and not name.startswith("tmp-"):
                    try:
                        from preparation_prefix_dll import validate_prefix_dll_record
                        record, _ = self.read_record("prefix-dlls", name)
                        validate_prefix_dll_record(record)
                        result["prefix_dlls"].append({key: record[key] for key in
                            ("record_id", "created_ns", "app_id", "trial_id", "dependency_id", "name", "phase", "preparation_complete")})
                        result["prefix_dlls"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["prefix_dlls"].append({"object": name, "status": "invalid"})
                elif directory == "installations" and not name.startswith("tmp-"):
                    try:
                        record, _ = self.read_record("installations", name)
                        validate_installation_record(record)
                        result["installations"].append({key: record[key] for key in
                            ("installation_id", "status", "phase", "published", "staging_name", "directory", "preparation_complete")})
                        result["installations"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["installations"].append({"object": name, "status": "invalid"})
                elif directory == "assets":
                    try:
                        with self.directory((directory, name)) as fd:
                            receipt = self._read(fd, "receipt.json", missing=True)
                            if receipt is None:
                                status = "incomplete"
                            else:
                                receipt = decode(receipt)
                                require(type(receipt) is dict and "spec" in receipt, "invalid receipt")
                                self.verify_asset(receipt["spec"])
                                status = "integrity-checked"
                    except (OSError, Invalid, TypeError, KeyError):
                        status = "invalid"
                    result["assets"].append({"object": name, "status": status})
                elif name.startswith("tmp-"):
                    result["temporary_records"].append(name)
        return result
