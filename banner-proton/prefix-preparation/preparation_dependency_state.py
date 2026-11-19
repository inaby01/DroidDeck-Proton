"""Offline, bounded inspection of one dependency's state inside a stopped prefix.

No Wine process is started. Only recipe-listed registry keys/value names and
recipe-listed files are interpreted; nothing else is retained or exported.
Callers must establish the process stop observation before and after.
"""

import hashlib
import os
import re
import stat

from preparation_assets import pe_machine
from preparation_common import Invalid, regular_open, require, safe_path, unchanged
from preparation_softdenchi_recipe import validate_recipe

MAX_REGISTRY = 256 * 1024**2
MAX_LOGICAL_LINE = 1024**2
MAX_KEY_HEADERS = 4_000_000
MAX_DIRECTORY_ENTRIES = 65536
MAX_FILE = 64 * 1024**2
STATES = ("uninspected", "absent", "partial", "incompatible", "present-unverified", "present-verified")
GROUPS = ("product-registration-and-version", "installed-files-hashes-pe-versions",
          "ucmansvc-service-image-and-start-type", "x86-com-registration", "x64-com-registration")
SERVICE_ROOTS = ("System\\ControlSet001\\Services\\", "System\\CurrentControlSet\\Services\\")
SESSION_MANAGERS = ("System\\ControlSet001\\Control\\Session Manager", "System\\CurrentControlSet\\Control\\Session Manager")
COM_ROOTS = {"x64": "Software\\Classes\\CLSID\\", "x86": "Software\\Classes\\Wow6432Node\\CLSID\\"}
_ESCAPES = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t", "0": "\0"}


def _unescape(text):
    out, index = [], 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        require(index + 1 < len(text), "dangling registry escape")
        code = text[index + 1]
        if code == "x":
            match = re.match(r"[0-9a-fA-F]{1,4}", text[index + 2:index + 6])
            require(match is not None, "invalid registry hex escape")
            out.append(chr(int(match.group(0), 16)))
            index += 2 + len(match.group(0))
        else:
            require(code in _ESCAPES, "unknown registry escape")
            out.append(_ESCAPES[code])
            index += 2
    return "".join(out)


def _quoted(text, start):
    """Return (unescaped string, index after closing quote) for text[start] == '"'."""
    require(text[start] == '"', "quoted registry string expected")
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return _unescape(text[start + 1:index]), index + 1
        index += 1
    raise Invalid("unterminated registry string")


def normal_key(key):
    return key.casefold()


def _data(raw):
    if raw.startswith('"'):
        value, end = _quoted(raw, 0)
        require(not raw[end:].strip(), "trailing registry data")
        return "sz", value
    match = re.fullmatch(r"str\((\d{1,2})\):(.*)", raw, re.DOTALL)
    if match:
        value, end = _quoted(match.group(2), 0)
        require(not match.group(2)[end:].strip(), "trailing registry data")
        return ("expand_sz" if match.group(1) == "2" else "str(" + match.group(1) + ")"), value
    match = re.fullmatch(r"dword:([0-9a-fA-F]{8})", raw.strip())
    if match:
        return "dword", int(match.group(1), 16)
    match = re.fullmatch(r"hex(?:\((\d{1,2})\))?:([0-9a-fA-F,\s]*)", raw.strip())
    if match:
        body = bytes(int(part, 16) for part in re.sub(r"\s", "", match.group(2)).split(",") if part)
        if match.group(1) in ("1", "2"):
            require(len(body) % 2 == 0, "odd UTF-16 registry data")
            return ("sz" if match.group(1) == "1" else "expand_sz"), body.decode("utf-16-le").rstrip("\0")
        return "hex(" + (match.group(1) or "3") + ")", len(body)
    raise Invalid("unsupported registry value format")


def _logical_lines(stream):
    pending = ""
    for raw in stream:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if pending:
            line = pending + line.lstrip()
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending = line[:-1]
            require(len(pending) <= MAX_LOGICAL_LINE, "registry line too long")
            continue
        pending = ""
        require(len(line) <= MAX_LOGICAL_LINE, "registry line too long")
        yield line
    require(not pending, "unterminated registry continuation")


def read_registry(path, wanted):
    """Read recipe-listed keys and value names from one Wine registry file.

    ``wanted`` maps key paths to value names ('@' is the default value). The
    result maps each normalized wanted key to {"occurrences": n, "values": {...}}
    for keys present in the file. Unlisted keys and values are never kept.
    """
    targets = {normal_key(key): {name.casefold() for name in names} for key, names in wanted.items()}
    found = {}
    headers = 0
    with regular_open(safe_path(path), MAX_REGISTRY) as stream:
        before = os.fstat(stream.fileno())
        first = stream.readline(64)
        require(first.startswith(b"WINE REGISTRY Version 2"), "registry header missing")
        current = None
        for line in _logical_lines(stream):
            if not line or line[0] in ";#":
                continue
            if line[0] == "[":
                headers += 1
                require(headers <= MAX_KEY_HEADERS, "too many registry keys")
                end = 1
                while end < len(line) and line[end] != "]":
                    end += 2 if line[end] == "\\" else 1
                require(end < len(line), "unterminated registry key")
                key = normal_key(_unescape(line[1:end]))
                current = key if key in targets else None
                if current is not None:
                    entry = found.setdefault(current, {"occurrences": 0, "values": {}})
                    entry["occurrences"] += 1
                continue
            # Every value line must be structurally valid so key boundaries are trustworthy;
            # data of unlisted keys is never decoded or kept.
            require(line[0] in '@"', "unsupported registry line")
            if current is None:
                if line[0] == '"':
                    _, end = _quoted(line, 0)
                    require(line[end:].startswith("="), "registry value assignment expected")
                continue
            if line[0] == "@":
                name, rest = "@", line[1:]
            else:
                require(line[0] == '"', "unsupported registry line")
                name, end = _quoted(line, 0)
                name, rest = name.casefold(), line[end:]
            require(rest.startswith("="), "registry value assignment expected")
            if name in targets[current]:
                values = found[current]["values"]
                require(name not in values, "duplicate registry value")
                values[name] = _data(rest[1:])
        unchanged(before, os.fstat(stream.fileno()))
    return found


def _directory(fd, name):
    """Open a child directory without following links; case-insensitive fallback."""
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        alternate = _casefold_entry(fd, name)
        if alternate is None:
            return None
        return os.open(alternate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)


def _casefold_entry(fd, name):
    matches = []
    with os.scandir(fd) as entries:
        for index, entry in enumerate(entries):
            require(index < MAX_DIRECTORY_ENTRIES, "too many directory entries")
            if entry.name.casefold() == name.casefold():
                matches.append(entry.name)
    require(len(matches) <= 1, "ambiguous case-insensitive path")
    return matches[0] if matches else None


def _walk(drive, relative):
    """Return (parent fd, final name) or (None, None) when any parent is absent."""
    parts = relative.split("/")
    fd = os.open(drive, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = _directory(fd, part)
            if child is None:
                return None, None
            os.close(fd)
            fd = child
        name = parts[-1]
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            name = _casefold_entry(fd, name)
        result, fd = (fd, name), None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def inspect_file(drive, relative, size, digest, machine):
    parent, name = _walk(drive, relative)
    if parent is None or name is None:
        if parent is not None:
            os.close(parent)
        return {"result": "absent"}
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            return {"result": "failed", "reason": "symlink-not-followed"}
        if not stat.S_ISREG(info.st_mode):
            return {"result": "failed", "reason": "not-regular-file"}
        if info.st_nlink != 1:
            return {"result": "failed", "reason": "multiple-links"}
        if info.st_size != size:
            return {"result": "failed", "reason": "size-differs"}
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, "file changed type or size")
            measured = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                measured.update(chunk)
            observed_machine = None
            if machine is not None:
                try:
                    observed_machine = pe_machine(stream, before.st_size)
                except Invalid:
                    observed_machine = "not-pe"
            unchanged(before, os.fstat(stream.fileno()))
        if measured.hexdigest() != digest:
            return {"result": "failed", "reason": "sha256-differs"}
        if observed_machine != machine:
            return {"result": "failed", "reason": "pe-machine-differs"}
        return {"result": "passed", "version_check": "covered-by-sha256"}
    finally:
        os.close(parent)


def _path_value(relative):
    return ("c:\\" + relative.replace("/", "\\")).casefold()


def _normal_path(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.replace("/", "\\").casefold()


def _group(items):
    results = {item["result"] for item in items.values()}
    if "uninspected" in results:
        return "uninspected"
    if results == {"passed"}:
        return "passed"
    if results == {"absent"}:
        return "absent"
    return "failed"


def _isolated(function, *args):
    try:
        return function(*args)
    except (OSError, ValueError, UnicodeError) as error:
        return {"result": "uninspected", "error_class": type(error).__name__}


def inspect_dependency_state(compatdata, recipe):
    """Classify a stopped prefix. Every group is collected even if another fails."""
    validate_recipe(recipe)
    compatdata = safe_path(compatdata)
    drive = safe_path(compatdata / "pfx/drive_c", compatdata)
    registry_path = safe_path(compatdata / "pfx/system.reg", compatdata)
    product, service = recipe["product"], recipe["service"]
    uninstall = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + product["product_code"]
    wanted = {uninstall: {"DisplayVersion"}, product["marker_key"]: {product["marker_value"]}}
    for root in SERVICE_ROOTS:
        wanted[root + service["name"]] = {"Type", "Start", "ImagePath"}
    for key in SESSION_MANAGERS:
        wanted[key] = {"PendingFileRenameOperations"}
    for clsid, context, view, _server in recipe["classes"]:
        wanted[COM_ROOTS[view] + clsid + "\\" + context] = {"@"}
    result = {"scope": "offline-recipe-listed-keys-and-files", "groups": {}, "items": {}, "registry_values_exported": False,
              "registry_full_read_retained": False, "wine_started": False}
    try:
        registry = read_registry(registry_path, wanted)
        registry_error = None
    except (OSError, ValueError, UnicodeError) as error:
        registry, registry_error = None, type(error).__name__

    def key_entry(key):
        if registry is None:
            return {"result": "uninspected", "error_class": registry_error}
        entry = registry.get(normal_key(key))
        if entry is None:
            return None
        if entry["occurrences"] != 1:
            return {"result": "uninspected", "reason": "duplicate-key"}
        return entry

    def value_check(key, name, expected_kinds, matches):
        entry = key_entry(key)
        if entry is None:
            return {"result": "absent"}
        if "result" in entry:
            return entry
        value = entry["values"].get(name.casefold())
        if value is None:
            return {"result": "failed", "reason": "value-missing"}
        if value[0] not in expected_kinds:
            return {"result": "failed", "reason": "value-type-differs"}
        return {"result": "passed"} if matches(value[1]) else {"result": "failed", "reason": "value-differs"}

    product_items = {
        "uninstall-display-version": value_check(uninstall, "DisplayVersion", ("sz", "expand_sz"),
                                                 lambda value: value == product["version"]),
        "product-marker": value_check(product["marker_key"], product["marker_value"], ("sz", "expand_sz"),
                                      lambda value: value == product["marker_data"])}
    incompatible = product_items["uninstall-display-version"].get("reason") == "value-differs"

    file_items = {}
    for relative, size, digest, machine in recipe["files"]:
        file_items[relative] = _isolated(inspect_file, drive, relative, size, digest, machine)

    services = [root + service["name"] for root in SERVICE_ROOTS]
    present = [key for key in services if key_entry(key) is not None]
    service_items = {}
    if registry is None:
        service_items["service-key"] = {"result": "uninspected", "error_class": registry_error}
    elif not present:
        service_items["service-key"] = {"result": "absent"}
    elif len(present) > 1:
        service_items["service-key"] = {"result": "uninspected", "reason": "service-defined-in-multiple-control-sets"}
    else:
        key = present[0]
        service_items["service-type"] = value_check(key, "Type", ("dword",), lambda value: value == service["type"])
        service_items["service-start"] = value_check(key, "Start", ("dword",), lambda value: value == service["start"])
        service_items["service-image-path"] = value_check(key, "ImagePath", ("sz", "expand_sz"),
                                                          lambda value: _normal_path(value) == _path_value(service["image"]))
        image = file_items.get(next(path for path, *_ in recipe["files"] if path.casefold() == service["image"].casefold()))
        service_items["service-image-file"] = {"result": image["result"]} if image["result"] != "absent" else {"result": "failed", "reason": "image-file-absent"}

    com = {"x86": {}, "x64": {}}
    for clsid, context, view, server in recipe["classes"]:
        com[view][clsid + "/" + context] = value_check(COM_ROOTS[view] + clsid + "\\" + context, "@", ("sz", "expand_sz"),
                                                       lambda value, server=server: _normal_path(value) == _path_value(server))

    pending = None
    if registry is not None:
        found = [value_check(key, "PendingFileRenameOperations", ("str(7)", "hex(7)", "sz", "expand_sz"),
                             lambda value: True)["result"] for key in SESSION_MANAGERS]
        pending = True if "passed" in found else None if "uninspected" in found else False

    traces = {}
    for directory in recipe["trace_directories"]:
        def trace(directory=directory):
            parent, name = _walk(drive, directory)
            if parent is not None:
                os.close(parent)
            return {"result": "present" if name is not None else "absent"}
        traces[directory] = _isolated(trace)

    for group, items in zip(GROUPS, (product_items, file_items, service_items, com["x86"], com["x64"])):
        result["groups"][group] = _group(items)
        result["items"][group] = {key: value for key, value in items.items() if value["result"] != "passed"}
        result["items"][group + "-passed-count"] = sum(item["result"] == "passed" for item in items.values())
    result["trace_directories"] = traces
    result["pending_file_rename_operations"] = pending
    groups = result["groups"].values()
    trace_states = {item["result"] for item in traces.values()}
    if "uninspected" in groups or "uninspected" in trace_states:
        state = "uninspected"
    elif incompatible:
        state = "incompatible"
    elif set(groups) == {"absent"} and trace_states <= {"absent"}:
        state = "absent"
    elif set(groups) == {"passed"}:
        state = "present-verified" if pending is False else "present-unverified"
    else:
        state = "partial"
    result["state"] = state
    return result
