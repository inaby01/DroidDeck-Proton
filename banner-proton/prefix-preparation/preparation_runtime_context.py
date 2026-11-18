"""Pinned minimum preparation environment; never loads hooks or starts programs.

Identity is distinct from runtime compatibility and Android process visibility.
Environment values and label bytes stay private in memory, not public summaries.
"""

import copy
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import digest_json
from preparation_common import read_bytes, require, safe_path
from preparation_runtime import LIBRARIES, SOURCES, inspect_runtime

PARENT_KEYS = frozenset(("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PULSE_SERVER", "DBUS_SESSION_BUS_ADDRESS",
                         "XAUTHORITY", "LANG", "LC_ALL", "TZ", "FEX_ROOTFS", "FEX_APP_CONFIG_LOCATION", "PROOT_FP_KEY"))
HOOK_KEYS = frozenset(("LD_PRELOAD", "LD_AUDIT", "PROOT_FP_KEY", "PROTON_USE_PIPEWIRE"))


def _mask(report):
    basis = report["process_observation_basis"]
    candidates = [basis.get("umask"),basis.get("shell_umask")]
    for name in ("numeric_pid_fd_reader","proc_self_fd_reader"):
        probe = basis.get(name,{})
        if probe.get("status") == "read":
            candidates.append(probe.get("umask"))
    masks = {value for value in candidates if value is not None}
    require(len(masks) == 1 and masks <= {"0022","0077"}, "matching supported runtime umask required")
    return next(iter(masks))


def _identity(report):
    require(report["os_release"] == {"ID":"ubuntu","VERSION_ID":"26.04"}, "unsupported runtime OS")
    sources = report["runtime_sources"]
    require(sources.keys() == SOURCES.keys() and all(sources[name]["status"] == "matched" and
            sources[name]["executable"] is True and sources[name]["sha256"] == digest
            for name,digest in SOURCES.items()), "runtime source identity mismatch")
    libraries = report["libraries"]
    require(libraries.keys() == set(LIBRARIES) and all(libraries[name]["status"] == "measured" and
            libraries[name]["elf_arm64"] is True for name in LIBRARIES), "runtime hook library unavailable")
    return {"os_release":report["os_release"],"sources":{name:sources[name]["sha256"] for name in SOURCES},
            "libraries":{name:libraries[name]["sha256"] for name in LIBRARIES},"label":report["label"]}


@dataclass(frozen=True)
class RuntimeEnvironmentPlan:
    identity_digest: str
    umask: str
    view: str
    root: object = field(repr=False)
    environment: dict = field(repr=False)
    label: object = field(repr=False)
    reference: dict = field(repr=False)
    private_environment_pairs: tuple = field(repr=False)

    def summary(self):
        return {"runtime_identity_digest":self.identity_digest,"view":self.view,"umask":self.umask,
                "environment_names":sorted(self.environment),"environment_values":"private",
                "runtime_execution_verified":False,"device_namespace_verified":False,
                "preparation_complete":False,"writes":[]}

    def verify(self, parent_environment=None):
        fresh = plan_runtime_environment(self.root,self.reference,parent_environment)
        require(fresh.identity_digest == self.identity_digest and fresh.private_environment_pairs == self.private_environment_pairs
                and tuple(sorted(self.environment.items())) == self.private_environment_pairs, "runtime environment changed")
        return True


def plan_runtime_environment(root, audited_report, parent_environment=None):
    root = safe_path(root)
    reference = copy.deepcopy(audited_report)
    require(reference["view"] == "current-root" and reference["auditor_architecture"] == "aarch64", "live arm64 audit reference required")
    expected, mask = _identity(reference), _mask(reference)
    parent = os.environ if parent_environment is None else parent_environment
    fresh = inspect_runtime(root,parent)
    require(_identity(fresh) == expected, "runtime source/library/label changed since audit")
    if root == Path("/"):
        require(fresh["auditor_architecture"] == "aarch64" and _mask(fresh) == mask, "live runtime architecture or umask changed")
    for name in ("DISPLAY","WAYLAND_DISPLAY","XDG_RUNTIME_DIR","PULSE_SERVER","PROOT_FP_KEY"):
        require(bool(parent.get(name)) == reference["environment_presence"][name], "runtime environment presence changed")
    selected = {key:parent[key] for key in PARENT_KEYS if parent.get(key)}
    require(all(type(value) is str and len(value.encode()) <= 4096 and not any(c in value for c in "\0\r\n")
                for value in selected.values()), "invalid selected runtime value")
    input_library = str(root / LIBRARIES[0])
    session_library = str(root / LIBRARIES[1])
    audit_library = str(root / LIBRARIES[2])
    inherited = parent.get("LD_PRELOAD","")
    require(type(inherited) is str and (not inherited or set(inherited.split(":")) <= {input_library,session_library}),
            "unknown inherited preload")
    inherited_audit = parent.get("LD_AUDIT","")
    require(not inherited_audit or selected.get("PROOT_FP_KEY") and inherited_audit == audit_library, "unknown inherited audit hook")
    # Match fixed wrapper prepending order, without forwarding arbitrary loader inputs.
    selected["LD_PRELOAD"] = session_library+":"+input_library
    if selected.get("PROOT_FP_KEY"):
        selected["LD_AUDIT"] = audit_library
    pipewire = parent.get("PROTON_USE_PIPEWIRE","0")
    require(pipewire in ("0","1"), "unsupported PipeWire selection")
    selected["PROTON_USE_PIPEWIRE"] = pipewire
    label = None
    if expected["label"]["status"] == "measured":
        label = read_bytes(root / "etc/steam-compatibility-label",4096)
        require(hashlib.sha256(label).hexdigest() == expected["label"]["sha256"], "runtime label changed")
    else:
        require(expected["label"]["status"] == "missing", "runtime label unreadable")
    signature = {"root":str(root),"identity":expected,"umask":mask,"hook_paths":[session_library,input_library,audit_library]}
    return RuntimeEnvironmentPlan(digest_json(signature),mask,fresh["view"],root,selected,label,reference,tuple(sorted(selected.items())))
