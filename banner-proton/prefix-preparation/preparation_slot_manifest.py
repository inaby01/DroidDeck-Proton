"""Saved verification data of a placed preparation slot (design: Proton update 4.7).

When this tool has verified a preparation slot against its bundle payload, it keeps the
payload inventory, the generated files it expects (overlays) and the verification rule
versions together, so that a later bundle (which no longer ships that payload) can verify
the slot again before assigning a game back to it. Written once per slot name and never
replaced: a different payload or generated file under the same name, or an unreadable
record, makes the slot unusable as a revert target instead of being overwritten.
"""

import hashlib
import time

from preparation_common import SHA256, VERSION, Invalid, fields, require
from preparation_payload import (
    DROIDDECK_REDIST_CONTRACT,
    FEX_RUNTIME_CONTRACT,
    OVERLAY_NAMES,
    PYTHON_CACHE_CONTRACT,
    PayloadInventory,
)

DIRECTORY = "slot-manifests"
SCHEMA = 1
LIMIT = 32 * 1024 * 1024
SLOT_PREFIX = "SoftDenchi-Prep-Proton "
CONTRACTS = {"fex": FEX_RUNTIME_CONTRACT, "redist": DROIDDECK_REDIST_CONTRACT, "pycache": PYTHON_CACHE_CONTRACT,
             "manifest": SCHEMA}


def slot_name(value):
    """A preparation slot directory name (one path component)."""
    require(type(value) is str and value.startswith(SLOT_PREFIX) and 0 < len(value.encode("utf-8")) <= 128 and
            "/" not in value and value not in (".", "..") and not any(ord(c) < 32 for c in value),
            "invalid preparation slot name")
    return value


def record_name(directory):
    """Store filename for a slot name (slot names have spaces and capitals)."""
    return "m" + hashlib.sha256(slot_name(directory).encode("utf-8")).hexdigest() + ".json"


def build(directory, tool_id, inventory, overlays, version_value):
    """The record content for a slot verified against ``inventory`` (not yet written)."""
    require(isinstance(inventory, PayloadInventory), "verified payload inventory required")
    require(type(overlays) is dict and overlays.keys() <= OVERLAY_NAMES, "unsupported payload overlay")
    require(type(tool_id) is str and 0 < len(tool_id) <= 128, "invalid tool ID")
    require(type(version_value) is str and 0 < len(version_value) <= 256, "invalid Proton version value")
    return {"schema_version": SCHEMA, "kind": "slot-manifest", "tool_version": VERSION, "directory": slot_name(directory),
            "tool_id": tool_id, "version_value": version_value, "contracts": dict(CONTRACTS),
            "inventory": {"root": inventory.root, "archive_sha512": inventory.archive_sha512,
                          "root_mode": inventory.root_mode, "entries": inventory.entries, "digest": inventory.digest,
                          "expanded_bytes": inventory.expanded_bytes, "external_links": inventory.external_links},
            "overlays": overlays, "created_ns": time.time_ns()}


def _identity(record):
    """What must match for two records of the same slot to be the same (not the times or writer)."""
    return {key: record[key] for key in ("schema_version", "kind", "directory", "tool_id", "version_value", "contracts",
                                         "inventory", "overlays")}


def validate(record, directory):
    """Shape of a saved record for ``directory``; raises Invalid when it cannot be used."""
    fields(record, ("schema_version", "kind", "tool_version", "directory", "tool_id", "version_value", "contracts",
                    "inventory", "overlays", "created_ns"))
    require(record["schema_version"] == SCHEMA and record["kind"] == "slot-manifest", "unknown slot manifest")
    require(record["directory"] == slot_name(directory), "slot manifest for another slot")
    require(type(record["tool_version"]) is str and 0 < len(record["tool_version"]) <= 64, "invalid slot manifest writer")
    require(type(record["tool_id"]) is str and 0 < len(record["tool_id"]) <= 128, "invalid tool ID")
    require(type(record["version_value"]) is str and 0 < len(record["version_value"]) <= 256, "invalid Proton version value")
    require(type(record["created_ns"]) is int and record["created_ns"] > 0, "invalid slot manifest time")
    fields(record["contracts"], ("fex", "redist", "pycache", "manifest"))
    inventory = record["inventory"]
    fields(inventory, ("root", "archive_sha512", "root_mode", "entries", "digest", "expanded_bytes", "external_links"))
    require(type(inventory["archive_sha512"]) is str and len(inventory["archive_sha512"]) == 128 and
            SHA256.fullmatch(inventory["digest"] or "") and type(inventory["entries"]) is dict and
            type(inventory["root_mode"]) is int and type(inventory["expanded_bytes"]) is int and
            type(inventory["external_links"]) is int, "invalid slot manifest inventory")
    require(type(record["overlays"]) is dict and record["overlays"].keys() <= OVERLAY_NAMES, "unsupported payload overlay")
    return record


def state(store, directory, expected=None):
    """(state, record): "missing", "same", "mismatch" or "broken" (design 4.7).

    Without ``expected`` an intact record is "same" (usable as saved). Read-only.
    """
    try:
        found = store.read_large(DIRECTORY, record_name(directory), LIMIT)
    except (OSError, Invalid, TypeError, KeyError, ValueError):
        return "broken", None
    if found is None:
        return "missing", None
    record, _ = found
    try:
        validate(record, directory)
    except (Invalid, TypeError, KeyError, ValueError):
        return "broken", None
    if expected is not None and _identity(record) != _identity(expected):
        return "mismatch", record
    return "same", record


def usable(record):
    """Whether this tool can verify a slot with ``record`` (same rule versions)."""
    return record is not None and record["contracts"] == CONTRACTS


def save(store, directory, record):
    """Write ``record`` once under the held store lock. Returns the resulting state.

    "created" when written now, "same" when an identical record exists, "mismatch" or
    "broken" when an existing record differs or cannot be read (never overwritten).
    """
    validate(record, directory)
    found, _ = state(store, directory, record)
    if found != "missing":
        return found
    store.write_new_large(DIRECTORY, record_name(directory), record, LIMIT)
    found, _ = state(store, directory, record)
    require(found == "same", "slot manifest changed after writing")
    return "created"


def inventory_of(record):
    """The saved payload inventory as an object ``verify_fex_runtime_tree`` accepts."""
    saved = record["inventory"]
    return PayloadInventory(saved["root"], saved["archive_sha512"], saved["root_mode"], saved["entries"], saved["digest"],
                            saved["expanded_bytes"], saved["external_links"])


def placed_slots(store):
    """Preparation slots this tool placed, by directory name (design 4.7), from any tool version.

    A directory counts when at least one installation record is ``installed-tree-verified``
    and published, and no record of that directory is ``running`` or ``needs-inspection``.
    Unreadable records are counted per directory only when their directory can be read;
    otherwise they are reported in ``unreadable``. Read-only.
    """
    from preparation_tool_writer import validate_installation_record
    found, unreadable = {}, 0
    try:
        with store.directory(("installations",)) as fd:
            names = sorted(store._names(fd))
    except FileNotFoundError:
        return {}, 0
    for name in names:
        if name.startswith("tmp-"):
            continue
        try:
            record, _ = store.read_record("installations", name)
            validate_installation_record(record, any_version=True)
        except (OSError, Invalid, TypeError, KeyError, ValueError):
            unreadable += 1
            continue
        directory = record["directory"]
        entry = found.setdefault(directory, {"verified": 0, "blocking": 0, "created_ns": None})
        if record["status"] == "installed-tree-verified" and record["published"]:
            entry["verified"] += 1
            if "created_ns" in record:
                entry["created_ns"] = min(filter(None, (entry["created_ns"], record["created_ns"])))
        if record["status"] in ("running", "needs-inspection"):
            entry["blocking"] += 1
    placed = {directory: {"created_ns": entry["created_ns"]} for directory, entry in found.items()
              if entry["verified"] and not entry["blocking"] and directory.startswith(SLOT_PREFIX)}
    return placed, unreadable


def record_for_installation(installation):
    """The record for the bundle slot of a verified installation plan (placement or reuse)."""
    directory = installation.customization.directory
    raw = installation.inventory.captured.get("version")
    require(type(raw) is bytes and 0 < len(raw) <= 256, "captured Proton version required")
    return build(directory, directory.replace(" ", "-", 1), installation.inventory, installation.customization.overlays,
                 raw.decode("utf-8").strip())


def save_after_verification(store, installation):
    """Save the record after the bundle slot was verified; never fails the caller (design 4.7).

    Returns {"state": "created" | "same" | "mismatch" | "broken" | "failed", ...} for the result JSON.
    """
    try:
        return {"state": save(store, installation.customization.directory, record_for_installation(installation))}
    except (OSError, Invalid, TypeError, KeyError, ValueError, UnicodeError) as error:
        return {"state": "failed", "error_class": type(error).__name__, "errno": getattr(error, "errno", None)}

