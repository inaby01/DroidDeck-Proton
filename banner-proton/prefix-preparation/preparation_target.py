"""Pinned explicit registration and game identity; never writes or launches."""

from dataclasses import dataclass, field

from preparation_assets import digest_json, exe_identity
from preparation_common import app_id, load_json, require, safe_path, string


def registrations(document):
    """Read the added-games list consumed by DroidDeck 0.7.1's proton-run."""
    require(type(document) is list and len(document) <= 4096, "invalid added-games list")
    result = {}
    for entry in document:
        require(type(entry) is dict, "invalid game registration")
        key = app_id(entry.get("appid"))
        exe = safe_path(string(entry.get("exe")))
        title = string(entry.get("name") or entry.get("title") or exe.name)
        require(key not in result, "duplicate or signed/unsigned alias registration ID")
        result[key] = {"app_id": key, "title": title, "exe": str(exe)}
    return result


@dataclass(frozen=True)
class RegistrationPin:
    registration_id: str
    digest: str
    source: object = field(repr=False)
    exe_root: object = field(repr=False)
    steam: object = field(repr=False)
    exe: object = field(repr=False)

    def verify(self):
        fresh = pin_registration(self.source, self.registration_id, self.exe_root, self.steam)
        require(fresh == self, "registration or executable changed")
        return True


def pin_registration(source, registration_id, exe_root, steam):
    source, exe_root, steam = map(safe_path, (source, exe_root, steam))
    require(exe_root.is_dir() and steam.is_dir(), "existing registration roots required")
    key = app_id(registration_id)
    document, source_digest = load_json(source)
    selected = registrations(document)
    require(key in selected, "registered target absent")
    exe = safe_path(selected[key]["exe"], exe_root)
    identity = exe_identity(exe)
    context = {"source": str(source), "source_sha256": source_digest, "exe_root": str(exe_root),
               "steam": str(steam), "app_id": key, "exe": str(exe), "identity": identity}
    return RegistrationPin(key, digest_json(context), source, exe_root, steam, exe)
