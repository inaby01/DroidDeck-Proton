"""Private, bounded cache and journal primitives. Never writes a game or prefix."""

import contextlib
import copy
import fcntl
import hashlib
import itertools
import json
import os
import re
import secrets
import stat
import time

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
    load_json,
    pairs,
    regular_open,
    require,
    revision,
    safe_path,
    string,
)
from preparation_execution import validate_launch_record
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


def target_key(report):
    return hashlib.sha256(str(safe_path(report["prefix"]["compatdata"])).encode()).hexdigest()


def check_results(value):
    require(type(value) is list and 0 < len(value) <= 128, "nonempty bounded checks required")
    seen = set()
    for item in value:
        fields(item, ("check_id", "result"))
        key = identifier(item["check_id"])
        require(key not in seen and item["result"] in ("passed", "failed", "uninspected"), "invalid check result")
        seen.add(key)
    return all(item["result"] == "passed" for item in value)


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
        result = {"assets": [], "runs": [], "bindings": [], "launches": [], "trials": [], "rechecks": [], "installations": [], "dependency_installs": [], "game_prefixes": [], "prefix_dlls": [], "backups": [], "temporary_records": []}
        for directory in ("assets", "runs", "bindings", "launches", "trials", "rechecks", "installations", "dependency-installs", "game-prefixes",
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
                elif directory == "rechecks" and not name.startswith("tmp-"):
                    try:
                        from preparation_recheck import validate_recheck_record
                        record, _ = self.read_record("rechecks", name)
                        validate_recheck_record(record)
                        result["rechecks"].append({key: record[key] for key in
                            ("recheck_id", "trial_id", "app_id", "status", "exit_code", "preparation_complete")})
                        result["rechecks"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["rechecks"].append({"object": name, "status": "invalid"})
                elif directory == "trials" and not name.startswith("tmp-"):
                    try:
                        from preparation_trial import validate_trial_record
                        record, _ = self.read_record("trials", name)
                        validate_trial_record(record)
                        result["trials"].append({key: record[key] for key in
                            ("trial_id", "app_id", "scope", "status", "phase", "exit_code", "preparation_complete")})
                        result["trials"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["trials"].append({"object": name, "status": "invalid"})
                elif directory == "launches" and not name.startswith("tmp-"):
                    try:
                        record, _ = self.read_record("launches", name)
                        validate_launch_record(record)
                        result["launches"].append({key: record[key] for key in
                                                   ("launch_id", "app_id", "operation", "status", "preparation_complete")})
                        result["launches"][-1]["reinspection_required"] = True
                    except (OSError, Invalid, TypeError, KeyError):
                        result["launches"].append({"object": name, "status": "invalid"})
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
                else:
                    try:
                        record, _ = self.read_record("runs", name)
                        validate_run(record)
                        result["runs"].append({"run_id": record["run_id"], "stored_status": record["status"],
                                               "created_ns": record["created_ns"], "updated_ns": record["updated_ns"],
                                               "reinspection_required": True, "preparation_complete": False})
                    except (OSError, Invalid, TypeError, KeyError):
                        result["runs"].append({"object": name, "stored_status": "invalid",
                                               "reinspection_required": True, "preparation_complete": False})
        return result


def run_context(report):
    return {
        "profile": {key: report["profile"][key] for key in ("profile_id", "revision")},
        "recipes": {item["dependency_id"]: item["revision"] for item in report["dependencies"]},
        "assets": {item["asset_id"]: {"revision": item["revision"], "spec_digest": item["spec_digest"],
                                      "sha256": item["measured"]["sha256"] if item["measured"] else None}
                   for item in report.get("assets", [])},
        "compatibility": report["compatibility"],
        "target": {"app_id": report["target"]["app_id"], "exe_sha256": report["target"]["identity"]["sha256"],
                   "exe_size": report["target"]["identity"]["size"]},
        "template": None,
    }


def validate_run(record):
    bounded(record)
    fields(record, ("schema_version", "tool_version", "run_id", "created_ns", "updated_ns", "target_key", "input_digest", "input_hashes",
                    "profile", "recipes", "assets", "compatibility", "target", "template", "status", "steps", "preparation_complete"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1, "unknown run schema")
    require(record["tool_version"] == VERSION and record["preparation_complete"] is False, "incompatible run")
    identifier(record["run_id"])
    for name in ("created_ns", "updated_ns"):
        require(type(record[name]) is int and record[name] > 0, "invalid run timestamp")
    sha256(record["target_key"])
    sha256(record["input_digest"])
    require(type(record["input_hashes"]) is dict, "invalid input hash map")
    for key, value in record["input_hashes"].items():
        require(key in ("registrations", "games", "config", "profile", "recipes", "assets", "binding"), "unknown input hash")
        sha256(value)
    fields(record["profile"], ("profile_id", "revision"))
    identifier(record["profile"]["profile_id"])
    revision(record["profile"]["revision"])
    require(type(record["recipes"]) is dict and len(record["recipes"]) <= 128, "invalid recipe revisions")
    for key, value in record["recipes"].items():
        identifier(key)
        revision(value)
    require(type(record["assets"]) is dict and len(record["assets"]) <= 128, "invalid asset history")
    for key, value in record["assets"].items():
        identifier(key)
        fields(value, ("revision", "spec_digest", "sha256"))
        revision(value["revision"])
        sha256(value["spec_digest"])
        if value["sha256"] is not None:
            sha256(value["sha256"])
    fields(record["compatibility"], ("status", "droiddeck", "proton", "version_source"))
    require(record["compatibility"]["status"] == "unverified" and
            record["compatibility"]["version_source"] == "operator-declared", "unsupported compatibility claim")
    for key in ("droiddeck", "proton"):
        if record["compatibility"][key] is not None:
            string(record["compatibility"][key])
    fields(record["target"], ("app_id", "exe_sha256", "exe_size"))
    require(type(record["target"]["app_id"]) is str and record["target"]["app_id"].isascii()
            and record["target"]["app_id"].isdigit() and 0 < int(record["target"]["app_id"]) <= 0xFFFFFFFF,
            "invalid target registration")
    sha256(record["target"]["exe_sha256"])
    require(type(record["target"]["exe_size"]) is int and record["target"]["exe_size"] > 0, "invalid EXE length")
    require(record["template"] is None, "templates not implemented")
    require(record["status"] in ("pending", "running", "failed", "needs-user"), "invalid run status")
    require(type(record["steps"]) is dict and set(record["steps"]) == {"asset-cache", "prefix-preparation"}, "unknown steps")
    for name, step in record["steps"].items():
        identifier(name)
        fields(step, ("status", "attempt", "checks", "exit_code", "started_ns", "finished_ns", "last_checked_ns"))
        for timestamp in ("started_ns", "finished_ns", "last_checked_ns"):
            require(step[timestamp] is None or type(step[timestamp]) is int and step[timestamp] > 0,
                    "invalid step timestamp")
        require(step["status"] in STEP_STATES and type(step["attempt"]) is int and 0 <= step["attempt"] <= 10000,
                "invalid step state")
        require(step["exit_code"] is None or type(step["exit_code"]) is int and -255 <= step["exit_code"] <= 255,
                "invalid exit code")
        require(type(step["checks"]) is list, "invalid step checks")
        if step["checks"]:
            check_results(step["checks"])
        if step["status"] == "succeeded":
            require(step["exit_code"] == 0 and check_results(step["checks"]), "success without postconditions")


class RunJournal:
    """Trusted callers supply reinspection callbacks; loaded markers are never enough."""

    def __init__(self, store, report, refresh, run_id=None):
        store._guard()
        self.store = store
        self.refresh = refresh
        resumed = run_id is not None
        self.expected_digest = sha256(report["input_digest"])
        require(store._held_target == target_key(report), "wrong target lock")
        self._fresh()
        context = run_context(report)
        if run_id is None:
            run_id = "run-" + secrets.token_hex(16)
            now = time.time_ns()
            self.record = {"schema_version": 1, "tool_version": VERSION, "run_id": run_id,
                           "created_ns": now, "updated_ns": now,
                           "target_key": target_key(report), "input_digest": self.expected_digest,
                           "input_hashes": report["input_hashes"],
                           **copy.deepcopy(context),
                           "status": "pending", "preparation_complete": False,
                           "steps": {key: {"status": "pending", "attempt": 0, "checks": [], "exit_code": None,
                                           "started_ns": None, "finished_ns": None, "last_checked_ns": None}
                                     for key in ("asset-cache", "prefix-preparation")}}
            self.record_hash = None
            self._save()
        else:
            identifier(run_id)
            self.record, self.record_hash = store.read_record("runs", run_id + ".json")
            validate_run(self.record)
            require(self.record["run_id"] == run_id and self.record["input_digest"] == self.expected_digest
                    and self.record["target_key"] == target_key(report), "run inputs or target changed")
            require(digest_json({key: self.record[key] for key in context}) == digest_json(context), "run provenance changed")
        self.run_id = run_id
        self._needs_reinspection = resumed

    def _fresh(self):
        self.store._guard()
        current = self.refresh()
        require(current["input_digest"] == self.expected_digest and target_key(current) == self.store._held_target,
                "inputs changed; discard plan and reinspect")

    def _save(self, record=None):
        self._fresh()
        candidate = self.record if record is None else record
        candidate["updated_ns"] = time.time_ns()
        validate_run(candidate)
        record_hash = self.store.write_record("runs", candidate["run_id"] + ".json", candidate, self.record_hash, before_commit=self._fresh)
        self.record, self.record_hash = candidate, record_hash

    def transition(self, step_id, status, verify=None, exit_code=None):
        require(not self._needs_reinspection, "loaded run must be reinspected first")
        self._fresh()
        require(step_id in self.record["steps"], "unknown step")
        candidate = copy.deepcopy(self.record)
        step = candidate["steps"][step_id]
        require((status == "running" and step["status"] in ("pending", "failed", "needs-user")) or
                (step["status"] == "running" and status in ("succeeded", "failed", "needs-user")) or
                (step["status"] == "pending" and status == "needs-user"), "invalid transition")
        checks = []
        if status == "succeeded":
            require(callable(verify) and exit_code == 0, "postcondition callback and zero exit required")
            checks = verify()
            require(check_results(checks), "postconditions failed or uninspected")
        now = time.time_ns()
        step.update(status=status, attempt=step["attempt"] + int(status == "running"), checks=checks, exit_code=exit_code,
                    started_ns=now if status == "running" else step["started_ns"],
                    finished_ns=None if status == "running" else now,
                    last_checked_ns=now if checks else None)
        self._status(candidate)
        self._save(candidate)

    @staticmethod
    def _status(record):
        values = [step["status"] for step in record["steps"].values()]
        record["status"] = next((value for value in ("running", "failed", "needs-user") if value in values),
                                     "pending" if "pending" in values else "needs-user")

    def reinspect(self, verifiers):
        """Convert interrupted steps and recheck successes before reuse; no automatic execution."""
        self._fresh()
        candidate = copy.deepcopy(self.record)
        for name, step in candidate["steps"].items():
            if step["status"] == "running":
                step.update(status="needs-user", checks=[{"check_id": "interrupted", "result": "uninspected"}],
                            exit_code=None, finished_ns=time.time_ns(), last_checked_ns=time.time_ns())
            elif step["status"] == "succeeded":
                verifier = verifiers.get(name)
                try:
                    checks = verifier() if callable(verifier) else [{"check_id": "postconditions", "result": "uninspected"}]
                except (OSError, Invalid):
                    checks = [{"check_id": "postconditions", "result": "failed"}]
                passed = check_results(checks)
                step.update(status="succeeded" if passed else "failed", checks=checks, exit_code=0 if passed else None,
                            last_checked_ns=time.time_ns())
        self._status(candidate)
        self._save(candidate)
        self._needs_reinspection = False
        return self.record


def stage_local(args, refresh):
    """Cache declared assets and pause a journal; never execute prefix preparation."""
    require(args.assets is not None and args.asset_root is not None and args.profile is not None
            and args.recipes is not None and args.app_id is not None, "stage requires assets and selected profile")
    report = refresh()
    require(report.get("assets") and not any(item["blockers"] for item in report["assets"]), "asset checks blocked")
    root = safe_path(args.management_root)
    # The management root must be disjoint from every protected/source tree and input file.
    for other in (args.steam_root, args.settings_root, args.exe_root, args.asset_root,
                  args.registrations, args.profile, args.recipes, args.assets):
        other = safe_path(other)
        require(not (root == other or root.is_relative_to(other) or other.is_relative_to(root)), "management root overlaps inputs")
    document, _ = load_json(args.assets)
    specs = validate_manifest(document)
    expected = {entry["asset_id"]: entry["spec_digest"] for entry in report["assets"]}
    require({key: digest_json(spec) for key, spec in specs.items()} == expected, "asset manifest changed")
    with PrivateStore(root, create=True) as store, store.locked(target_key(report)):
        journal = RunJournal(store, report, refresh, args.resume_run)

        def verify_cache():
            for spec in specs.values():
                store.verify_asset(spec)
            return [{"check_id": "cache-integrity", "result": "passed"}]

        actions = []
        if args.resume_run is not None:
            journal.reinspect({"asset-cache": verify_cache})
        if journal.record["steps"]["asset-cache"]["status"] != "succeeded":
            journal.transition("asset-cache", "running")
            try:
                for key, spec in specs.items():
                    journal._fresh()
                    cached = store.cache_asset(spec, args.asset_root)
                    actions.append({"asset_id": key, "action": cached["action"]})
                journal.transition("asset-cache", "succeeded", verify_cache, exit_code=0)
            except (OSError, Invalid):
                # A stale plan may prevent even a failure update. Its stored running state
                # remains interrupted, never success; inventory/resume exposes it later.
                journal.transition("asset-cache", "failed", exit_code=1)
                raise
        else:
            actions = [{"asset_id": key, "action": "revalidated"} for key in specs]
        if journal.record["steps"]["prefix-preparation"]["status"] == "pending":
            journal.transition("prefix-preparation", "needs-user")
        return {"schema_version": 1, "tool_version": VERSION, "mode": "stage-local", "run_id": journal.run_id,
                "preparation_complete": False, "status": journal.record["status"], "cached_assets": actions,
                "blockers": report["blockers"], "writes": [str(root / name) for name in ("store.json", "locks", "assets", "runs")]}
