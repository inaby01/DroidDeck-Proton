"""The inherited "VC++ runtime installed" record (design: inherited VC record).

DroidDeck appends ``VC\\Runtimes`` values to a compatibility tool's template prefix at its first
session with that tool. A prefix created afterwards inherits them, and the SoftDenchi installer
then skips its VC++ 2019 prerequisite (mfc140.dll stays missing). Right before the installer,
the values that came from the template are released from a newly prepared prefix under strict
conditions. Everything here reads files only; the Wine run lives in the installation session.
"""

import hashlib
import io
import json
import os
import re
import stat

from preparation_common import Invalid, regular_open, require, safe_path, unchanged
from preparation_dependency_state import (
    MAX_KEY_HEADERS,
    MAX_LOGICAL_LINE,
    MAX_REGISTRY,
    _data,
    _directory,
    _quoted,
    _unescape,
)

RUNTIMES = "Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\"
# Fixed identifiers of the six keys DroidDeck appends (both registry views, three architectures).
KEYS = {"native-x86": "Software\\" + RUNTIMES + "x86", "native-x64": "Software\\" + RUNTIMES + "x64",
        "native-arm64": "Software\\" + RUNTIMES + "arm64", "wow-x86": "Software\\Wow6432Node\\" + RUNTIMES + "x86",
        "wow-x64": "Software\\Wow6432Node\\" + RUNTIMES + "x64", "wow-arm64": "Software\\Wow6432Node\\" + RUNTIMES + "arm64"}
VALUE_NAMES = ("Bld", "Installed", "Major", "Minor", "Rbld", "Version")
_VALUE_KEYS = {name.casefold(): name for name in VALUE_NAMES}
_NORMAL = {ident: path.casefold() for ident, path in KEYS.items()}
_BY_PATH = {path: ident for ident, path in _NORMAL.items()}


def _ancestors():
    found = set()
    for path in _NORMAL.values():
        parts = path.split("\\")
        for index in range(1, len(parts)):
            found.add("\\".join(parts[:index]))
    return found


ANCESTORS = _ancestors()
UNINSTALL_ROOTS = ("software\\microsoft\\windows\\currentversion\\uninstall",
                   "software\\wow6432node\\microsoft\\windows\\currentversion\\uninstall")
# Real VC++ 14.x installations: the 2015-20xx redistributable bundle or its Minimum/Additional runtime MSIs.
VC14_NAME = re.compile(r"microsoft visual c\+\+ 2015-20\d\d .*redistributable|"
                       r"microsoft visual c\+\+ 20\d\d .*(?:minimum|additional) runtime - 14\.")
STATES = ("not-evaluated", "releasing", "absent", "absent-after-release", "released", "kept-vc-present", "failed")
# Stops the operator cannot clear by running again (design 4, Fable L4): shown as "stops", skipped by the batch.
FINAL_REASONS = ("investigation-required", "no-initial-fingerprint", "initial-fingerprint-unreadable", "template-mismatch",
                 "template-changed", "keys-in-archive", "registry-shape", "values-differ", "vc-registered-without-mfc140",
                 "uninstall-unreadable")
RETRYABLE_REASONS = ("wait-timeout", "wine-start", "values-remain", "keys-remain", "removed-too-much",
                     "persistence-unconfirmed", "registry-unreadable", "template-unreadable", "changed-before-release")
REG = "C:\\windows\\system32\\reg.exe"
REASON = re.compile(r"[a-z0-9-]{1,64}(?::[A-Za-z0-9_]{1,64})?")


def value_hash(value):
    kind, data = value
    return hashlib.sha256(json.dumps([kind, data], ensure_ascii=True).encode()).hexdigest()


def _empty_key():
    return {"occurrences": 0, "values": {}, "duplicate": False, "link": False, "others": [], "subkeys": set()}


def _hex_value(line):
    """A value line whose data is hex: the only lines Wine continues with a trailing backslash."""
    try:
        if line[:1] == "@":
            end = 1
        elif line[:1] == '"':
            _, end = _quoted(line, 0)
        else:
            return False
    except Invalid:
        return False
    return line[end:end + 4].lower() == "=hex"


def wine_lines(stream):
    """Registry text lines as Wine's loader reads them (server/registry.c, Codex final recheck H).

    Wine joins a line ending in a backslash with the next one only inside hex data; comments,
    ``#link`` and other values are lines of their own whatever they end with.
    """
    pending = None
    for raw in stream:
        line = raw.decode("utf-8").rstrip("\r\n")  # Invalid bytes make the registry unreadable.
        require(len(line) <= MAX_LOGICAL_LINE, "registry line too long")
        if pending is not None:
            line = pending + line.lstrip()
            pending = None
            require(len(line) <= MAX_LOGICAL_LINE, "registry line too long")
        if _hex_value(line) and line.rstrip().endswith("\\"):
            pending = line.rstrip()[:-1]
            require(len(pending) <= MAX_LOGICAL_LINE, "registry line too long")
            continue
        yield line
    require(pending is None, "unterminated registry continuation")


def _header_key(line):
    end = 1
    while end < len(line) and line[end] != "]":
        end += 2 if line[end] == "\\" else 1
    require(end < len(line), "unterminated registry key")
    return _unescape(line[1:end]).casefold()


def physical_links(stream):
    """Keys followed by a physical line starting with ``#link``, whatever the lines around it.

    Conservative on purpose (Codex final recheck H): however a value line before it ends, a
    ``#link`` line marks the key of the nearest header above it, so a link is never missed.
    """
    links, current = set(), None
    for raw in stream:
        if raw.startswith(b"["):
            current = _header_key(raw.decode("utf-8").rstrip("\r\n"))
        elif raw.startswith(b"#link") and current is not None:
            links.add(current)
    return links


def _canonical(text):
    """A value as Wine stores it, so equal values written differently compare equal (Codex final recheck M)."""
    lowered = text.strip().lower()
    match = re.match(r"dword:([0-9a-f]*)", lowered)
    if match:
        return ("dword", int(match.group(1) or "0", 16) & 0xFFFFFFFF)  # strtoul reads the leading digits.
    match = re.fullmatch(r"hex(?:\(([0-9a-f]{1,8})\))?:(.*)", lowered, re.DOTALL)
    if match:
        parts = [part.strip() for part in match.group(2).split(",")]
        if parts and parts[-1] == "":
            parts.pop()
        if all(re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts):
            return ("hex(" + (match.group(1) or "3") + ")", bytes(int(part, 16) for part in parts).hex())
        return ("raw", lowered)
    return ("data", _data(text))


def _other_hash(text):
    """Other values of a key, compared before and after Wine rewrote the file (Codex final recheck M4)."""
    try:
        return value_hash(_canonical(text))  # Binary data is compared by its bytes, not only its length.
    except Invalid:
        return value_hash(("raw", text))


def scan_lines(lines, links_seen=frozenset()):
    """Interpret registry text lines for the six keys, their ancestors and the Uninstall entries.

    Only the six keys' values are decoded and kept; other values of those keys are kept as
    hashes. Every other value line is checked for structure only (key boundaries stay
    trustworthy). Uninstall entries contribute only whether a VC++ 14.x display name exists.
    """
    keys = {ident: _empty_key() for ident in KEYS}
    present, links, uninstall = set(), set(), {"vc14": 0, "unreadable": 0}
    headers = 0
    current, current_kind, current_owner = None, None, None
    for line in lines:
        if not line:
            continue
        if line[0] == "#":
            # Wine marks a link by the first five characters (server/registry.c), whatever follows (Codex final H).
            if line.startswith("#link") and current_kind in ("target", "ancestor", "subkey"):
                links.add(current)
                if current_kind == "target":
                    keys[_BY_PATH[current]]["link"] = True
                elif current_kind == "subkey":
                    keys[current_owner]["link"] = True  # reg delete of the key would act through it.
            continue
        if line[0] == ";":
            continue
        if line[0] == "[":
            headers += 1
            require(headers <= MAX_KEY_HEADERS, "too many registry keys")
            end = 1
            while end < len(line) and line[end] != "]":
                end += 2 if line[end] == "\\" else 1
            require(end < len(line), "unterminated registry key")
            key = _unescape(line[1:end]).casefold()
            current, current_kind = key, None
            parts = key.split("\\")
            for index in range(1, len(parts) + 1):
                prefix = "\\".join(parts[:index])
                if prefix in ANCESTORS or prefix in _BY_PATH:
                    present.add(prefix)
            if key in links_seen:
                # Marked by the physical scan: a link of the key itself, an ancestor or a sub-key.
                if key in ANCESTORS:
                    links.add(key)
                for path, ident in _BY_PATH.items():
                    if key == path or key.startswith(path + "\\"):
                        keys[ident]["link"] = True
            if key in _BY_PATH:
                current_kind = "target"
                keys[_BY_PATH[key]]["occurrences"] += 1
            elif key in ANCESTORS:
                current_kind = "ancestor"
            else:
                for path, ident in _BY_PATH.items():
                    if key.startswith(path + "\\"):
                        keys[ident]["subkeys"].add(key[len(path) + 1:])
                        current_kind, current_owner = "subkey", ident
                for root in UNINSTALL_ROOTS:
                    if key.startswith(root + "\\") and "\\" not in key[len(root) + 1:]:
                        current_kind = "uninstall"
            continue
        require(line[0] in '@"', "unsupported registry line")
        if line[0] == "@":
            name, rest = "@", line[1:]
        else:
            name, end = _quoted(line, 0)
            rest = line[end:]
        require(rest.startswith("="), "registry value assignment expected")
        if current_kind == "target":
            entry = keys[_BY_PATH[current]]
            folded = name.casefold()
            if folded in _VALUE_KEYS:
                canonical = _VALUE_KEYS[folded]
                if canonical in entry["values"]:
                    entry["duplicate"] = True
                try:
                    entry["values"][canonical] = _data(rest[1:])
                except Invalid:
                    entry["values"][canonical] = ("raw", rest[1:])  # Never equal to the template's values.
            else:
                if any(item[0] == folded for item in entry["others"]):
                    entry["duplicate"] = True
                # Hashed as written: any type Wine saves (hex(b): for QWORD too) is kept (Codex final M4).
                entry["others"].append((folded, _other_hash(rest[1:])))
        elif current_kind == "uninstall" and name.casefold() == "displayname":
            try:
                kind, text = _data(rest[1:])
            except Invalid:
                uninstall["unreadable"] += 1
                continue
            if kind not in ("sz", "expand_sz"):
                uninstall["unreadable"] += 1
            elif VC14_NAME.search(text.casefold()):
                uninstall["vc14"] += 1
    for ident, path in _NORMAL.items():
        keys[ident]["exists"] = path in present
        keys[ident]["subkeys"] = sorted(keys[ident]["subkeys"])
        keys[ident]["others"] = sorted(keys[ident]["others"])
    return {"keys": keys, "ancestor_links": sorted(link for link in links if link in ANCESTORS),
            "runtimes_present": {view: path.rsplit("\\", 1)[0] in present for view, path in
                                 (("native", _NORMAL["native-x86"]), ("wow", _NORMAL["wow-x86"]))},
            "uninstall": uninstall}


def scan_file(path):
    with regular_open(safe_path(path), MAX_REGISTRY) as stream:
        before = os.fstat(stream.fileno())
        require(stream.readline(64).startswith(b"WINE REGISTRY Version 2"), "registry header missing")
        links = physical_links(stream)
        stream.seek(0)
        stream.readline(64)
        result = scan_lines(wine_lines(stream), links)
        unchanged(before, os.fstat(stream.fileno()))
    return result


def kept_hash(entry):
    """Everything of a key that is not released: other values and sub-key names."""
    return hashlib.sha256(json.dumps([entry["others"], entry["subkeys"]], ensure_ascii=True).encode()).hexdigest()


def fingerprint(scan):
    """Per key, per released value name: hash of type and data (the init record and resume use the same form)."""
    return {ident: {name: value_hash(value) for name, value in sorted(entry["values"].items())}
            for ident, entry in scan["keys"].items() if entry["values"]}


def read_template(registry, archive_size, expected_tail_sha256):
    """DroidDeck's appended Runtimes values, read from the same bytes whose hash the tool verified.

    Returns {"keys": {ident: {name: (type, data)}}, "version": str, "archive_has_keys": bool,
    "tail_sha256": str}. Raises Invalid when the template cannot be interpreted.
    """
    require(type(archive_size) is int and archive_size > 0 and type(expected_tail_sha256) is str, "template contract missing")
    with regular_open(safe_path(registry), MAX_REGISTRY) as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(MAX_REGISTRY + 1)
        unchanged(before, os.fstat(stream.fileno()))
    require(len(data) > archive_size, "template has no appended tail")
    tail = data[archive_size:]
    digest = hashlib.sha256(tail).hexdigest()
    require(digest == expected_tail_sha256, "template tail changed")
    archive = data[:archive_size]
    require(archive.startswith(b"WINE REGISTRY Version 2"), "registry header missing")
    body = archive.split(b"\n", 1)[1] if b"\n" in archive else b""
    archive_scan = scan_lines(wine_lines(io.BytesIO(body)), physical_links(io.BytesIO(body)))
    tail_scan = scan_lines(wine_lines(io.BytesIO(tail)), physical_links(io.BytesIO(tail)))
    keys, versions = {}, set()
    for ident, entry in tail_scan["keys"].items():
        if entry["occurrences"] == 0:
            continue
        require(entry["occurrences"] == 1 and not entry["duplicate"] and not entry["others"] and not entry["link"],
                "template key shape")
        require("Version" in entry["values"] and entry["values"]["Version"][0] == "sz", "template version missing")
        versions.add(entry["values"]["Version"][1])
        keys[ident] = dict(entry["values"])
    require(keys and len(versions) == 1, "template versions differ")
    return {"keys": keys, "version": versions.pop(), "tail_sha256": digest,
            "archive_has_keys": any(entry["occurrences"] or entry["subkeys"] for entry in archive_scan["keys"].values())}


def _windows_dir(compatdata, name):
    """Open drive_c/windows/<name> without following links (case-insensitive like Wine); None when absent."""
    fd = os.open(safe_path(compatdata), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ("pfx", "drive_c", "windows", name):
            child = _directory(fd, part)
            os.close(fd)
            fd = child
            if fd is None:
                return None
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def mfc140(compatdata):
    """{"syswow64": kind, "system32": kind}: absent / native / wine-builtin / wine-placeholder / other."""
    result = {}
    for directory in ("syswow64", "system32"):
        fd = _windows_dir(compatdata, directory)
        if fd is None:
            result[directory] = "absent"
            continue
        try:
            names = [entry.name for entry in os.scandir(fd) if entry.name.casefold() == "mfc140.dll"]
            if not names:
                result[directory] = "absent"
                continue
            if len(names) > 1:
                result[directory] = "other"  # Any entry of that name counts as present (design 3.2, Fable L4).
                continue
            try:
                file_fd = os.open(names[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except OSError:
                result[directory] = "other"  # A link or special entry still counts as present (design 3.2).
                continue
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    result[directory] = "other"
                    continue
                head = os.read(file_fd, 0x80)
            finally:
                os.close(file_fd)
            stub = head[0x40:0x80]
            result[directory] = ("wine-builtin" if b"Wine builtin DLL" in stub else
                                 "wine-placeholder" if b"Wine placeholder DLL" in stub else
                                 "native" if head[:2] == b"MZ" else "other")
        finally:
            os.close(fd)
    return result


def failed(reason, **extra):
    require(REASON.fullmatch(reason) is not None, "invalid reason")
    head = reason.split(":", 1)[0]
    require(head in FINAL_REASONS or head in RETRYABLE_REASONS, "unknown release reason")
    return {"state": "failed", "reason": reason, "retryable": head in RETRYABLE_REASONS, **extra}


def evaluate(scan, mfc, template, initial, current_tail_sha256):
    """Decide before the installer (design 3). Returns a decision dict.

    ``initial`` is the init record's fingerprint entry (None for records written before 0.32.0).
    ``template`` is read_template()'s result or an Invalid instance when it could not be read.
    """
    targets = {ident: entry for ident, entry in scan["keys"].items() if entry["values"]}
    count = sum(len(entry["values"]) for entry in targets.values())
    if not targets:
        return {"state": "absent", "values": 0}
    if any(kind != "absent" for kind in mfc.values()):
        return {"state": "kept-vc-present", "values": count}
    if scan["uninstall"]["unreadable"]:
        return failed("uninstall-unreadable", values=count)
    if scan["uninstall"]["vc14"]:
        return failed("vc-registered-without-mfc140", values=count)
    if isinstance(template, OSError):
        # A read error may pass; a mismatch does not (Fable code review L6).
        return failed("template-unreadable:" + type(template).__name__, values=count)
    if isinstance(template, Exception) or template is None:
        return failed("template-mismatch", values=count)
    if template["archive_has_keys"]:
        return failed("keys-in-archive", values=count)
    if initial is None:
        return failed("no-initial-fingerprint", values=count)
    if initial.get("state") != "captured":
        return failed("initial-fingerprint-unreadable" if initial.get("state") == "unreadable" else "values-differ",
                      values=count)
    if initial.get("template_tail_sha256") != current_tail_sha256 or template["tail_sha256"] != current_tail_sha256:
        return failed("template-changed", values=count)
    if scan["ancestor_links"] or any(entry["occurrences"] > 1 or entry["duplicate"] or entry["link"]
                                     for entry in scan["keys"].values()):
        return failed("registry-shape", values=count)
    current = fingerprint(scan)
    expected = {ident: {name: value_hash(value) for name, value in values.items()}
                for ident, values in template["keys"].items()}
    if any(expected.get(ident) != values for ident, values in current.items()) or current != initial.get("keys"):
        return failed("values-differ", values=count)
    plan = {ident: {"values": current[ident], "delete_key": not entry["others"] and not entry["subkeys"],
                    "kept": kept_hash(entry)} for ident, entry in targets.items()}
    return {"state": "release", "values": count, "version": template["version"], "keys": plan}


def resume(scan, mfc, previous):
    """Continue a release a previous attempt began (design 4 resume). ``previous`` is its record's keys."""
    if any(kind != "absent" for kind in mfc.values()):
        return {"state": "kept-vc-present", "values": sum(len(entry["values"]) for entry in scan["keys"].values())}
    # Condition 2 holds for a resume as well (design 4, Codex final M1).
    if scan["uninstall"]["unreadable"]:
        return failed("uninstall-unreadable")
    if scan["uninstall"]["vc14"]:
        return failed("vc-registered-without-mfc140")
    if scan["ancestor_links"] or any(entry["occurrences"] > 1 or entry["duplicate"] or entry["link"]
                                     for entry in scan["keys"].values()):
        return failed("investigation-required")
    if not scan["runtimes_present"]["native"] or not scan["runtimes_present"]["wow"]:
        return failed("investigation-required")  # Something beyond the plan is gone (Fable code review M1).
    remaining = {}
    for ident, entry in scan["keys"].items():
        original = previous.get(ident)
        if original is not None and not original["delete_key"] and not entry["exists"]:
            return failed("investigation-required")  # A key that had to stay is gone.
        if original is None:
            if entry["values"]:
                return failed("investigation-required")
            continue
        now = {name: value_hash(value) for name, value in entry["values"].items()}
        if any(original["values"].get(name) != digest for name, digest in now.items()):
            return failed("investigation-required")
        if entry["exists"] and kept_hash(entry) != original["kept"]:
            return failed("investigation-required")
        if now or (original["delete_key"] and entry["exists"]):
            remaining[ident] = {"values": now, "delete_key": original["delete_key"], "kept": original["kept"]}
    count = sum(len(item["values"]) for item in remaining.values())
    if not remaining:
        return {"state": "absent-after-release", "values": 0}
    return {"state": "release", "values": count, "keys": remaining}


def command(plan):
    """cmd.exe arguments: per key '&&' (stop that key at the first failure), keys joined by '&'."""
    tail = []
    for ident, path in KEYS.items():
        item = plan.get(ident)
        if item is None:
            continue
        key = "HKLM\\" + path
        chain = []
        for name in VALUE_NAMES:
            if name in item["values"]:
                chain.append([REG, "delete", key, "/v", name, "/reg:64", "/f"])
        if item["delete_key"]:
            chain.append([REG, "delete", key, "/reg:64", "/f"])
        if not chain:
            continue
        if tail:
            tail.append("&")
        for index, part in enumerate(chain):
            if index:
                tail.append("&&")
            tail.extend(part)
    require(tail, "nothing to release")
    return ("cmd.exe", "/d", "/c", *tail)


def same_state(before, after):
    """What the decision was made on is still there: values, kept data, links and duplicates (design 4)."""
    def shape(found):
        return (fingerprint(found), found["ancestor_links"], found["runtimes_present"],
                {ident: (kept_hash(entry), entry["exists"], entry["link"], entry["duplicate"], entry["occurrences"])
                 for ident, entry in found["keys"].items()})
    return shape(before) == shape(after)


def verify(plan, scan):
    """The re-read after the Wine run (design 4): returns None when it passed, else a retryable reason."""
    if not scan["runtimes_present"]["native"] or not scan["runtimes_present"]["wow"]:
        return "removed-too-much"
    if any(entry["values"] for entry in scan["keys"].values()):
        return "values-remain"
    for ident, item in plan.items():
        entry = scan["keys"][ident]
        if entry["values"]:
            return "values-remain"
        if item["delete_key"]:
            if entry["exists"]:
                return "keys-remain"
        elif not entry["exists"] or kept_hash(entry) != item["kept"]:
            return "removed-too-much"
    return None


def validate_initial(value):
    """The init record's fingerprint (design 3, Codex M4): captured / none / unreadable."""
    require(type(value) is dict and value.get("state") in ("captured", "none", "unreadable"), "invalid VC fingerprint")
    allowed = {"captured": {"state", "keys", "template_tail_sha256"}, "none": {"state", "template_tail_sha256"},
               "unreadable": {"state", "error_class"}}[value["state"]]
    require(set(value) == allowed, "invalid VC fingerprint fields")
    if value["state"] != "unreadable":
        require(value["template_tail_sha256"] is None or (type(value["template_tail_sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", value["template_tail_sha256"])), "invalid template hash")
    else:
        require(type(value["error_class"]) is str and len(value["error_class"]) <= 64, "invalid error class")
    if value["state"] == "captured":
        _validate_values(value["keys"])
    return value


def _validate_values(keys):
    require(type(keys) is dict and keys and set(keys) <= set(KEYS), "invalid VC keys")
    for values in keys.values():
        require(type(values) is dict and values and set(values) <= set(VALUE_NAMES) and
                all(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) for digest in values.values()),
                "invalid VC values")


def capture_initial(compatdata, tail_sha256):
    """Right after a successful initialization: never raises (a failure is recorded as unreadable)."""
    try:
        scan = scan_file(safe_path(compatdata) / "pfx/system.reg")
        keys = fingerprint(scan)
        if not keys:
            return {"state": "none", "template_tail_sha256": tail_sha256}
        return validate_initial({"state": "captured", "keys": keys, "template_tail_sha256": tail_sha256})
    except (OSError, Invalid, ValueError, UnicodeError) as error:
        return {"state": "unreadable", "error_class": type(error).__name__}


def validate_record(value):
    """``inherited_vc_record`` of an installation record (optional field; strict when present)."""
    require(type(value) is dict and value.get("state") in STATES, "invalid VC record state")
    allowed = {"state", "reason", "retryable", "values", "version", "keys", "resumed_from", "exit_code",
               "wineserver_observed", "wineserver_gone_before_read"}
    require(set(value) <= allowed, "invalid VC record fields")
    reason = value.get("reason")
    require(reason is None or (type(reason) is str and REASON.fullmatch(reason)), "invalid VC record reason")
    require((value["state"] == "failed") == (reason is not None), "reason only for a failed release")
    # Per state (Codex final L1): a failed release says whether running again can clear it; a release in
    # progress or done carries what a resume compares with; nothing else is set before an evaluation.
    require((value["state"] == "failed") == (type(value.get("retryable")) is bool), "retryable only for a failed release")
    if value["state"] == "failed":
        require(value["retryable"] == (reason.split(":", 1)[0] in RETRYABLE_REASONS), "retryable flag differs from reason")
    require(value["state"] not in ("releasing", "released") or value.get("keys"), "release without its keys")
    require(value["state"] != "not-evaluated" or set(value) == {"state"}, "not-evaluated carries no data")
    by_state = {"absent": {"state", "values", "resumed_from", "version"},
                "absent-after-release": {"state", "values", "resumed_from", "version"},
                "kept-vc-present": {"state", "values", "resumed_from", "version"},
                "releasing": {"state", "values", "version", "keys", "resumed_from"}}
    if value["state"] in by_state:
        # No Wine ran in these states: no exit code or observation (Codex final recheck L1).
        require(set(value) <= by_state[value["state"]], "fields do not fit the state")
    require(value.get("values") is None or (type(value["values"]) is int and 0 <= value["values"] <= 36), "invalid count")
    require(value.get("version") is None or (type(value["version"]) is str and len(value["version"]) <= 40), "invalid version")
    if value.get("keys") is not None:
        require(type(value["keys"]) is dict and set(value["keys"]) <= set(KEYS), "invalid VC record keys")
        for item in value["keys"].values():
            require(type(item) is dict and set(item) == {"values", "delete_key", "kept"} and
                    type(item["delete_key"]) is bool and type(item["kept"]) is str and
                    re.fullmatch(r"[0-9a-f]{64}", item["kept"]) is not None, "invalid VC record key")
            require(type(item["values"]) is dict and set(item["values"]) <= set(VALUE_NAMES) and
                    all(type(d) is str and re.fullmatch(r"[0-9a-f]{64}", d) for d in item["values"].values()),
                    "invalid VC record values")
    resumed = value.get("resumed_from")
    require(resumed is None or (type(resumed) is str and re.fullmatch(r"depinstall-[0-9a-f]{32}", resumed)), "invalid resume ID")
    require(value.get("exit_code") is None or type(value["exit_code"]) is int, "invalid exit code")
    for name in ("wineserver_observed", "wineserver_gone_before_read"):
        require(value.get(name) is None or type(value[name]) is bool, "invalid observation flag")
    return value


def unfinished(history):
    """The newest evaluated release of one initialization when it is unfinished, else None (design 4, Fable M).

    ``history``: the installation records of the same trial_id, oldest first.
    """
    evaluated = [record for record in history if record.get("inherited_vc_record", {}).get("state") not in
                 (None, "not-evaluated") and not _undecided(record["inherited_vc_record"])]
    if not evaluated:
        return None
    last = evaluated[-1]
    item = last["inherited_vc_record"]
    if item["state"] == "releasing" or (item["state"] == "failed" and item.get("keys")):
        return last
    return None


def _undecided(item):
    """A stop that read nothing reliable (a read error before any decision): it hides no earlier release (Codex final M2)."""
    return item["state"] == "failed" and item.get("retryable") is True and not item.get("keys") and \
        (item.get("reason") or "").split(":", 1)[0] in ("registry-unreadable", "template-unreadable")


def final_stop(history):
    """The reason of a stop that running again cannot clear (design: status display), or None."""
    evaluated = [record for record in history if record.get("inherited_vc_record", {}).get("state") not in
                 (None, "not-evaluated")]
    if not evaluated:
        return None
    item = evaluated[-1]["inherited_vc_record"]
    if item["state"] == "failed" and item.get("retryable") is False:
        return item["reason"]
    return None


RELEASE_TEXT = "導入の前に、ひな形から受け継いだ『VC++ 14.51導入済み』の記録（DroidDeckが書き足したもの）を、このprefixから外します（VC++の実体がない場合だけ。ほかのゲーム・ひな形は変えません）。"


def text_reason(reason):
    head = (reason or "").split(":", 1)[0]
    return {
        "investigation-required": "前回途中まで外した記録と今の状態が合わないため、調査が必要です",
        "no-initial-fingerprint": "このprefixは0.32.0より前に初期化されていて、受け継いだ記録かどうかを確かめられません",
        "initial-fingerprint-unreadable": "初期化のときの記録を読めなかったため、受け継いだ記録かどうかを確かめられません",
        "template-mismatch": "準備用Protonのひな形の書き足し部分を確かめられません",
        "template-changed": "初期化のあとに準備用Protonのひな形が変わっています",
        "keys-in-archive": "VC++の記録がひな形のもとの部分にあり、DroidDeckが書き足したものではありません",
        "registry-shape": "VC++の記録のキーの形が想定と違います（重複・リンクなど）",
        "values-differ": "VC++の記録の値が、ひな形または初期化のときと違います",
        "vc-registered-without-mfc140": "VC++の登録はありますが mfc140.dll がありません",
        "uninstall-unreadable": "アンインストールの登録の表示名を読めません",
        "wait-timeout": "Wineの終了を待ちきれませんでした",
        "wine-start": "Wineを起動できませんでした",
        "values-remain": "外したはずの値が残っています",
        "keys-remain": "外したはずのキーが残っています",
        "removed-too-much": "残すはずのキーや値が変わっています",
        "persistence-unconfirmed": "Wineがレジストリを書き出したことを確かめられません",
        "registry-unreadable": "prefixのレジストリを読めません",
        "template-unreadable": "準備用Protonのひな形を読めませんでした",
        "changed-before-release": "外す直前にVC++の記録が変わりました",
    }.get(head, reason or "")
