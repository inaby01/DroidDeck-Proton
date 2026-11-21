"""Declarative local asset checks. No downloads, extraction, imports or execution."""

import datetime
import hashlib
import io
import json
import os
import struct
from pathlib import Path

from preparation_common import (
    MAX_DEPENDENCIES,
    MAX_EXE,
    Invalid,
    bounded,
    fields,
    identifier,
    regular_open,
    require,
    revision,
    safe_path,
    string,
    unchanged,
)

# Trusted input ceilings; external declarations cannot raise them. No extraction policy exists yet.
INPUT_LIMITS = {"pe": 512 * 1024**2, "opaque": 2 * 1024**3}
MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}


def sha256(value):
    require(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value), "invalid digest")
    return value


def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def pe_machine(stream, size):
    stream.seek(0)
    dos = stream.read(64)
    require(len(dos) == 64 and dos[:2] == b"MZ", "missing DOS header")
    offset = struct.unpack_from("<I", dos, 60)[0]
    require(64 <= offset <= size - 26, "invalid PE offset")
    stream.seek(offset)
    header = stream.read(26)
    require(len(header) == 26 and header[:4] == b"PE\0\0", "missing PE signature")
    optional_size = struct.unpack_from("<H", header, 20)[0]
    require(optional_size >= 2 and offset + 24 + optional_size <= size, "truncated PE optional header")
    machine = struct.unpack_from("<H", header, 4)[0]
    magic = struct.unpack_from("<H", header, 24)[0]
    require((machine, magic) in ((0x14C, 0x10B), (0x8664, 0x20B), (0xAA64, 0x20B)), "unsupported PE architecture")
    return MACHINES[machine]


PE_HEAD_LIMIT = 16 * 1024 * 1024  # bytes kept for the PE header of a loose read (e_lfanew is normally small)


def _pe_head_needed(head):
    """How many leading bytes the PE header check needs, known once the DOS header is read."""
    if len(head) < 64 or head[:2] != b"MZ":
        return 64
    return min(max(64, struct.unpack_from("<I", head, 60)[0] + 26), PE_HEAD_LIMIT)


def measure_stream(stream, limit, kind, destination=None, timestamps=True):
    """Size, SHA-256 and PE machine of a regular file stream.

    ``timestamps=False`` (operator asset-folder reads only) does not compare timestamps and takes
    the PE machine from the same bytes that are hashed, never from a separate read.
    """
    before = os.fstat(stream.fileno())
    machine = pe_machine(stream, before.st_size) if kind == "pe" and timestamps else None
    stream.seek(0)
    digest = hashlib.sha256()
    length, head = 0, bytearray()
    while chunk := stream.read(min(1024 * 1024, limit + 1 - length)):
        length += len(chunk)
        require(length <= before.st_size, "asset grew during read")
        require(length <= limit, "asset exceeds trusted input ceiling")
        digest.update(chunk)
        rest = chunk
        while not timestamps and kind == "pe" and rest and len(head) < _pe_head_needed(head):
            take = _pe_head_needed(head) - len(head)
            head += rest[:take]
            rest = rest[take:]
        if destination is not None:
            destination.write(chunk)
    unchanged(before, os.fstat(stream.fileno()), timestamps)
    require(length == before.st_size, "asset size changed during read")
    if kind == "pe" and not timestamps:
        machine = pe_machine(io.BytesIO(bytes(head)), length)
    return {"sha256": digest.hexdigest(), "size": length, "pe_machine": machine}


def exe_identity(path):
    with regular_open(path, MAX_EXE) as stream:
        measured = measure_stream(stream, MAX_EXE, "pe")
    return {**measured, "provenance": "local-measurement-only"}


def validate_manifest(document):
    bounded(document)
    fields(document, ("schema_version", "assets"))
    require(type(document["schema_version"]) is int and document["schema_version"] == 1, "unknown asset schema")
    entries = document["assets"]
    require(type(entries) is list and 0 < len(entries) <= MAX_DEPENDENCIES, "invalid asset count")
    result = {}
    for item in entries:
        fields(item, ("asset_id", "revision", "version", "purpose", "filename", "format", "pe_machine",
                      "expected_size", "expected_sha256", "hash_kind", "hash_reference", "source_kind",
                      "source_reference", "acquired_on", "provenance_status", "terms_status"))
        key = identifier(item["asset_id"])
        revision(item["revision"])
        require(key not in result, "duplicate asset ID")
        for name in ("version", "purpose", "filename", "source_reference", "acquired_on"):
            string(item[name])
        name = Path(item["filename"])
        require(not name.is_absolute() and ".." not in name.parts and str(name) != ".", "invalid asset filename")
        require(item["format"] in INPUT_LIMITS, "unsupported asset format")
        require(item["pe_machine"] in (None, "x86", "x86_64", "arm64"), "invalid expected PE machine")
        require(item["format"] == "pe" or item["pe_machine"] is None, "PE machine supplied for opaque input")
        length = item["expected_size"]
        require(length is None or type(length) is int and 0 < length <= INPUT_LIMITS[item["format"]], "invalid expected length")
        if item["expected_sha256"] is not None:
            sha256(item["expected_sha256"])
        require(item["hash_kind"] in ("unknown", "local-measurement", "external-reference"), "invalid hash kind")
        if item["hash_reference"] is not None:
            string(item["hash_reference"])
        require(item["source_kind"] in ("unknown", "official", "game-bundled"), "invalid source kind")
        require(item["provenance_status"] in ("unconfirmed", "operator-reviewed"), "invalid provenance status")
        require(item["terms_status"] in ("unconfirmed", "personal-use-reviewed"), "invalid terms status")
        try:
            date = datetime.date.fromisoformat(item["acquired_on"])
        except ValueError as error:
            raise Invalid("invalid acquisition date") from error
        require(date.isoformat() == item["acquired_on"], "noncanonical acquisition date")
        result[key] = item
    return result


def source_path(root, spec):
    root = safe_path(root)
    require(root != Path("/") and root.is_dir(), "asset root must be an existing bounded directory")
    return safe_path(root / spec["filename"], root)


def asset_blockers(spec, measured):
    blockers = []
    if spec["source_kind"] == "unknown" or spec["provenance_status"] != "operator-reviewed":
        blockers.append("provenance-unconfirmed")
    if spec["terms_status"] != "personal-use-reviewed":
        blockers.append("terms-unconfirmed")
    if spec["expected_sha256"] is None:
        blockers.append("expected-hash-unknown")
    if spec["hash_kind"] != "external-reference" or not spec["hash_reference"]:
        blockers.append("independent-hash-reference-unavailable")
    if spec["expected_size"] is None:
        blockers.append("expected-size-unknown")
    if spec["format"] == "pe" and spec["pe_machine"] is None:
        blockers.append("expected-pe-machine-unknown")
    if measured is None:
        blockers.append("asset-missing")
    else:
        if spec["expected_sha256"] is not None and spec["expected_sha256"] != measured["sha256"]:
            blockers.append("hash-mismatch")
        if spec["expected_size"] is not None and spec["expected_size"] != measured["size"]:
            blockers.append("size-mismatch")
        if spec["pe_machine"] is not None and spec["pe_machine"] != measured["pe_machine"]:
            blockers.append("pe-machine-mismatch")
    return blockers


def inspect_assets_from_folder(document, root):
    """The operator's asset folder (shared storage): timestamps are not compared; bytes are hashed."""
    return inspect_assets(document, root, timestamps=False)


def inspect_assets(document, root, timestamps=True):
    specs = validate_manifest(document)
    reports = []
    for key, spec in specs.items():
        path = source_path(root, spec)
        try:
            with regular_open(path, INPUT_LIMITS[spec["format"]]) as stream:
                measured = measure_stream(stream, INPUT_LIMITS[spec["format"]], spec["format"], timestamps=timestamps)
        except FileNotFoundError:
            measured = None
        reports.append({"asset_id": key, "revision": spec["revision"], "spec_digest": digest_json(spec),
                        "measured": measured, "hash_kind": spec["hash_kind"],
                        "provenance": spec["provenance_status"], "terms": spec["terms_status"],
                        "evidence_source": "operator-declared", "version_check": "uninspected",
                        "blockers": asset_blockers(spec, measured), "execution": "not-implemented"})
    return reports
