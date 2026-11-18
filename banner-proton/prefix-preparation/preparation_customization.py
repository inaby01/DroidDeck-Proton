"""Expected installed/adopted metadata from pinned inputs; no helper execution."""

import ast
import hashlib
import json
from dataclasses import dataclass, field

from preparation_assets import digest_json
from preparation_common import read_bytes, require
from preparation_payload import PayloadInventory
from preparation_vdf import Document

HELPER_SHA256 = "9728f4c8c6646335e3f28297e3cae0ea4f8c44c7da83c02a0c2cd46b682bf61e"
SETUPS = ("BL_DRIVER_QUERY_SKIP", "BL_DESKTOP_GPU_SETUP", "BL_DIRECTAUDIO_SETUP", "BL_GAME_CPUS_SETUP",
          "BL_IDTECH3_SETUP", "BL_VACDIAG_SETUP", "BL_COMPONENTS_SETUP", "BL_LIBPATH_SETUP", "BL_STORE_SETUP")


def _captured(inventory, name, optional=False):
    entry = inventory.entries.get(name)
    if entry is None and optional:
        return None
    raw = inventory.captured.get(name)
    require(entry is not None and entry["kind"] == "file" and type(raw) is bytes and len(raw) == entry["size"]
            and hashlib.sha256(raw).hexdigest() == entry["sha256"], "captured source metadata absent or changed")
    return raw


def _templates(raw):
    require(hashlib.sha256(raw).hexdigest() == HELPER_SHA256, "unsupported runtime helper source")
    wanted = set(SETUPS) | {"EXTRA_WRAPPER", "EXTRA_WRAPPER_SH", "EXTRA_COMPAT_TOOL_VDF", "EXTRA_MANIFEST_VDF"}
    values = {}
    for node in ast.parse(raw).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name not in wanted:
            continue
        require(name not in values, "duplicate runtime template")
        value = node.value
        if name == "EXTRA_MANIFEST_VDF":
            require(isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod) and
                    isinstance(value.right, ast.Name) and value.right.id == "EXTRA_WRAPPER", "unsupported manifest template")
            value = value.left
        literal = ast.literal_eval(value)
        require(type(literal) is str, "runtime template must be literal")
        values[name] = literal
    require(values.keys() == wanted and values["EXTRA_WRAPPER"] == "droiddeck-proton-wrap", "runtime templates missing")
    return values


@dataclass(frozen=True)
class CustomizationPlan:
    directory: str
    helper_sha256: str
    label_sha256: object
    files: dict = field(repr=False)
    overlays: dict = field(repr=False)
    digest: str
    tool_slot: str = "legacy"

    def summary(self):
        return {"directory": self.directory, "tool_slot": self.tool_slot, "helper_sha256": self.helper_sha256, "label_sha256": self.label_sha256,
                "expected_files": sorted(self.files), "customization_digest": self.digest,
                "runtime_equivalence": "unverified", "preparation_complete": False, "writes": []}


def plan_customizations(inventory, archive_name, mode, helper_path, renderer, *, label=None, umask=0o022, tool_slot="legacy"):
    """renderer is the trusted installer's pure render_installation function.

    label=None models an absent label file; b'' models an existing empty file.
    The caller must pin actual label presence/content before using the plan.
    """
    require(isinstance(inventory, PayloadInventory) and inventory.digest ==
            digest_json({"root_mode": inventory.root_mode, "entries": inventory.entries}), "source inventory changed")
    require(type(umask) is int and umask in (0o022, 0o077), "unsupported installation umask")
    require(callable(renderer), "trusted installer renderer required")
    require(tool_slot in ("legacy", "preparation"), "unknown tool slot")
    source_version = _captured(inventory, "version")
    original_manifest = _captured(inventory, "toolmanifest.vdf")
    manifest = Document(original_manifest).node(("manifest",)).value
    require("commandline" in manifest and manifest["commandline"].value == "/proton %verb%", "unsupported original launcher")
    files = renderer(archive_name, inventory.archive_sha512, mode, source_version,
                     _captured(inventory, "user_settings.py", optional=True))
    require(type(files) is dict and files.keys() == {"compatibilitytool.vdf", "user_settings.py", "softdenchi-install.json"}
            and all(type(raw) is bytes and len(raw) <= 1024*1024 for raw in files.values()), "invalid installer render result")
    receipt = json.loads(files["softdenchi-install.json"])
    directory = receipt["installed_dir"]
    tools = Document(files["compatibilitytool.vdf"]).node(("compatibilitytools", "compat_tools")).value
    require(type(tools) is dict and len(tools) == 1, "invalid rendered tool catalog")
    tool_id = next(iter(tools))
    if tool_slot == "preparation":
        require(directory.startswith("SoftDenchi-Proton ") and tool_id == directory.replace(" ", "-", 1), "unsupported source tool family")
        version = directory.removeprefix("SoftDenchi-Proton ")
        directory, tool_id = "SoftDenchi-Prep-Proton " + version, "SoftDenchi-Prep-Proton-" + version
        receipt.update(installed_dir=directory, tool_slot="preparation")
        files["softdenchi-install.json"] = (json.dumps(receipt, indent=2) + "\n").encode()
    require(type(label) in (bytes, type(None)) and (label is None or len(label) <= 4096), "invalid runtime label")
    text = "" if label is None else label.decode("utf-8").strip().replace('"', "'").replace("\\", "")
    require(not any(ord(c) < 32 for c in text), "unsupported runtime label control character")
    display = directory + " (" + text + ")" if text else directory
    templates = _templates(read_bytes(helper_path))
    wrapper = (templates["EXTRA_WRAPPER_SH"] % "proton").replace(
        'here=$(dirname "$0")', 'here=$(dirname "$0")\n' + "".join(templates[name] for name in SETUPS), 1)
    files["droiddeck-proton-wrap"] = wrapper.encode("utf-8")
    files["toolmanifest.vdf.droiddeck-orig"] = original_manifest
    files["toolmanifest.vdf"] = (templates["EXTRA_MANIFEST_VDF"] % templates["EXTRA_WRAPPER"]).encode("utf-8")
    files["compatibilitytool.vdf"] = (templates["EXTRA_COMPAT_TOOL_VDF"] % (tool_id, display)).encode("utf-8")
    overlays = {}
    for name, raw in files.items():
        if name == "droiddeck-proton-wrap":
            file_mode = 0o755
        elif name == "toolmanifest.vdf.droiddeck-orig":
            file_mode = inventory.entries["toolmanifest.vdf"]["mode"]
        elif name == "user_settings.py" and name in inventory.entries:
            file_mode = inventory.entries[name]["mode"]
        else:
            file_mode = 0o666 & ~umask
        overlays[name] = {"kind": "file", "mode": file_mode, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    signature = {"archive_sha512": inventory.archive_sha512, "inventory_digest": inventory.digest,
                 "helper_sha256": HELPER_SHA256, "label_sha256": None if label is None else hashlib.sha256(label).hexdigest(),
                 "overlays": overlays}
    return CustomizationPlan(directory, HELPER_SHA256, signature["label_sha256"], files, overlays, digest_json(signature), tool_slot)
