"""Bounded readers and validators shared by the offline planner and private store."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

VERSION = "0.22.0"
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


def checked(stage, function, *args, **kwargs):
    """Attach a fixed caller-defined diagnostic stage without echoing input data."""
    try:
        return function(*args, **kwargs)
    except (OSError, ValueError, TypeError, KeyError) as error:
        if not hasattr(error, "preparation_check"):
            error.preparation_check = stage
        raise


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
