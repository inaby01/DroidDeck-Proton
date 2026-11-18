"""Create registration-only probe material from one pinned Wine archive member.

Never runs the Windows executable, writes Android registration/preferences, or
creates/initializes compatdata. Private receipts distinguish staged material from
a genuinely new registration observed later. No existing destination is reused.
"""

import gzip
import hashlib
import io
import json
import os
import re
import secrets
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import digest_json, exe_identity, pe_machine
from preparation_common import (
    MAX_JSON,
    VERSION,
    app_id,
    checked,
    fields,
    load_json,
    regular_open,
    require,
    safe_path,
    unchanged,
)
from preparation_payload import (
    CHUNK,
    MAX_ARCHIVE,
    MAX_EXPANDED,
    _Reader,
    _TarInfo,
    inspect_archive,
)
from preparation_store import PrivateStore
from preparation_target import registrations

MEMBER = "files/lib/wine/i386-windows/cmd.exe"
EXE = "prefix-probe.exe"
MARKER = "probe.json"
MAX_PROBE = 2 * 1024**2
ID = re.compile(r"probe-[0-9a-f]{32}\Z")


def _record_valid(record):
    fields(record, ("schema_version", "tool_version", "probe_id", "probe_revision", "status", "destination", "steam",
                    "registration_source", "baseline_ids", "registration_sha256", "archive_sha512", "inventory_digest",
                    "member", "exe_identity", "preparation_complete"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and type(record["probe_revision"]) is int and record["probe_revision"] == 1,
            "unknown probe receipt schema/revision")
    require(type(record["tool_version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", record["tool_version"]), "invalid creation version")
    require(type(record["probe_id"]) is str and ID.fullmatch(record["probe_id"]), "invalid probe ID")
    require(record["member"] == MEMBER and record["status"] in ("creating", "probe-ready", "probe-failed") and
            record["preparation_complete"] is False, "invalid probe receipt state")
    for name, length in (("archive_sha512", 128), ("inventory_digest", 64), ("registration_sha256", 64)):
        require(type(record[name]) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", record[name]), "invalid probe digest")
    for name in ("destination", "steam", "registration_source"):
        safe_path(record[name])
    require(Path(record["destination"]).name == "DroidDeck Prefix Test-" + record["probe_id"][6:], "probe destination identity differs")
    ids = record["baseline_ids"]
    require(type(ids) is list and len(ids) <= 4096 and all(type(key) is str and app_id(key) == key for key in ids) and len(set(ids)) == len(ids), "invalid baseline IDs")
    identity = record["exe_identity"]
    fields(identity, ("sha256", "size", "pe_machine", "provenance"))
    require(type(identity["size"]) is int and 0 < identity["size"] <= MAX_PROBE and identity["pe_machine"] == "x86" and
            identity["provenance"] == "local-measurement-only" and re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]), "invalid probe executable")


def _marker(record):
    return {"schema_version": 1, "purpose": "registration-only-probe", "probe_id": record["probe_id"],
            "member": MEMBER, "archive_sha512": record["archive_sha512"], "exe_sha256": record["exe_identity"]["sha256"]}


def _capture_probe(archive, inventory):
    expected = inventory.entries.get(MEMBER)
    require(expected is not None and expected["kind"] == "file" and 0 < expected["size"] <= MAX_PROBE,
            "bounded x86 cmd member required")
    raw, count = None, 0
    digest = hashlib.sha512()
    with regular_open(archive, MAX_ARCHIVE) as source:
        before = os.fstat(source.fileno())
        compressed = _Reader(source, MAX_ARCHIVE, digest)
        with gzip.GzipFile(fileobj=compressed, mode="rb") as unpacked:
            reader = _Reader(unpacked, MAX_EXPANDED + 128 * CHUNK)
            with tarfile.open(fileobj=reader, mode="r|", tarinfo=_TarInfo) as package:
                for member in package:
                    if member.name != inventory.root + "/" + MEMBER:
                        continue
                    count += 1
                    require(count == 1 and member.isfile() and member.size == expected["size"] and not member.issparse(), "probe member changed")
                    with package.extractfile(member) as data:
                        raw = data.read(member.size + 1)
                        require(len(raw) == member.size, "probe member truncated")
            while reader.read(CHUNK):
                pass
        while compressed.read(CHUNK):
            pass
        unchanged(before, os.fstat(source.fileno()))
        require(compressed.count == before.st_size and digest.hexdigest() == inventory.archive_sha512, "probe archive changed")
    require(raw is not None and hashlib.sha256(raw).hexdigest() == expected["sha256"] and
            pe_machine(io.BytesIO(raw), len(raw)) == "x86", "probe executable identity mismatch")
    return raw


@dataclass(frozen=True)
class ProbeMaterialPlan:
    digest: str
    record: dict = field(repr=False)
    archive: object = field(repr=False)
    archive_root: str
    raw: bytes = field(repr=False)

    def summary(self):
        record = self.record
        return {"mode": "probe-material-plan", "input_digest": self.digest, "probe_id": record["probe_id"],
                "destination": record["destination"], "exe": str(Path(record["destination"]) / EXE),
                "source_member": MEMBER, "exe_identity": dict(record["exe_identity"]),
                "baseline_registration_count": len(record["baseline_ids"]), "registration_action": "manual-or-app-rescan-not-performed",
                "planned_files": [EXE, MARKER], "private_receipt_required": True, "prefix_created": False,
                "exe_executed": False, "preparation_complete": False, "writes": []}


def plan_probe_material(archive, sha512, archive_root, source, steam, base, *, probe_id=None):
    archive, source, steam, base = map(safe_path, (archive, source, steam, base))
    require(steam.is_dir() and base.is_dir(), "existing Steam and probe base required")
    require(not (base == steam or base.is_relative_to(steam)), "probe base is inside Steam")
    document, source_digest = load_json(source)
    games = registrations(document)
    probe_id = "probe-" + secrets.token_hex(16) if probe_id is None else probe_id
    require(type(probe_id) is str and ID.fullmatch(probe_id), "invalid probe ID")
    destination = safe_path(base / ("DroidDeck Prefix Test-" + probe_id[6:]), base)
    require(not os.path.lexists(destination), "probe destination already exists")
    for game in games.values():
        protected = Path(game["exe"]).parent
        require(not (destination == protected or destination.is_relative_to(protected) or protected.is_relative_to(destination)),
                "probe destination overlaps registered game")
    inventory = checked("probe-archive-inspection", inspect_archive, archive, sha512, archive_root)
    raw = checked("probe-member-capture", _capture_probe, archive, inventory)
    identity = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "pe_machine": "x86", "provenance": "local-measurement-only"}
    record = {"schema_version": 1, "tool_version": VERSION, "probe_id": probe_id, "probe_revision": 1, "status": "creating",
              "destination": str(destination), "steam": str(steam), "registration_source": str(source),
              "baseline_ids": sorted(games, key=int), "registration_sha256": source_digest,
              "archive_sha512": sha512, "inventory_digest": inventory.digest, "member": MEMBER,
              "exe_identity": identity, "preparation_complete": False}
    _record_valid(record)
    fs = os.statvfs(base)
    require(fs.f_bavail * (fs.f_frsize or fs.f_bsize) >= len(raw) + 2 * MAX_JSON, "insufficient probe material space")
    require(load_json(source)[1] == source_digest, "registration changed before probe plan completed")
    return ProbeMaterialPlan(digest_json(record), record, archive, archive_root, raw)


def create_probe_material(plan, refresh, store):
    require(isinstance(plan, ProbeMaterialPlan) and callable(refresh), "trusted probe plan required")
    store._guard()
    record = dict(plan.record)
    _record_valid(record)
    destination = safe_path(record["destination"])
    require(store._held_target == hashlib.sha256(str(destination).encode()).hexdigest(), "matching probe material lock required")
    require(not (store.root == destination or store.root.is_relative_to(destination) or destination.is_relative_to(store.root)), "probe store overlaps destination")
    fresh = refresh()
    require(isinstance(fresh, ProbeMaterialPlan) and fresh.digest == plan.digest and fresh.record == record and fresh.raw == plan.raw,
            "probe material plan changed")
    require(plan.digest == digest_json(record) and hashlib.sha256(plan.raw).hexdigest() == record["exe_identity"]["sha256"], "probe plan mutated")
    filename = record["probe_id"] + ".json"
    record_hash = store.write_record("probe-runs", filename, record)
    parent_fd, fd = None, None
    try:
        parent = safe_path(destination.parent)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_identity = os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino
        os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
        fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        identity = os.fstat(fd).st_dev, os.fstat(fd).st_ino
        def guard():
            store._guard()
            parent_now = safe_path(parent).stat()
            current = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            require((parent_now.st_dev, parent_now.st_ino) == parent_identity and (current.st_dev, current.st_ino) == identity,
                    "probe directory changed")
        for name, raw in ((EXE, plan.raw), (MARKER, (json.dumps(_marker(record), ensure_ascii=True, indent=2) + "\n").encode())):
            guard()
            out_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(out_fd, "wb") as output:
                info = os.fstat(output.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "invalid new probe file")
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        guard()
        require(exe_identity(destination / EXE) == record["exe_identity"], "copied probe identity changed")
        require(load_json(destination / MARKER)[0] == _marker(record), "probe marker changed")
        os.fsync(fd)
        os.fsync(parent_fd)
        record["status"] = "probe-ready"
        store.write_record("probe-runs", filename, record, record_hash)
        return {"mode": "probe-material-created", "probe_id": record["probe_id"], "destination": str(destination),
                "exe": str(destination / EXE), "exe_identity": record["exe_identity"],
                "writes": [{"path": str(destination), "scope": "new-registration-probe-files-only"},
                           {"path": str(store.root), "scope": "private-probe-receipt-and-locks"}],
                "prefix_created": False, "exe_executed": False, "registration_written": False, "preparation_complete": False}
    except BaseException:
        record["status"] = "probe-failed"
        try:
            store.write_record("probe-runs", filename, record, record_hash)
        except (OSError, ValueError):
            pass
        raise  # Preserve partial files and private creating/failed receipt; never delete user data.
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def verify_probe_registration(exe, key, source, steam, store_root):
    """Read only. Receipt success alone is never proof of a new unstarted prefix."""
    exe, source, steam = map(safe_path, (exe, source, steam))
    require(exe.name == EXE, "not a registration probe executable")
    marker, _ = load_json(exe.parent / MARKER)
    require(type(marker) is dict and type(marker.get("probe_id")) is str and ID.fullmatch(marker["probe_id"]), "invalid probe marker")
    with PrivateStore(store_root) as store:
        record, receipt_digest = store.read_record("probe-runs", marker["probe_id"] + ".json")
    _record_valid(record)
    require(record["status"] == "probe-ready" and record["steam"] == str(steam) and record["registration_source"] == str(source),
            "probe receipt not ready or context differs")
    require(marker == _marker(record), "probe marker differs from private receipt")
    destination = safe_path(record["destination"])
    require(os.path.samefile(exe, destination / EXE) and os.path.samefile(exe.parent, destination), "registered probe path identity differs")
    require(exe_identity(exe) == record["exe_identity"], "registered probe bytes changed")
    document, source_digest = load_json(source)
    games = registrations(document)
    key = app_id(key)
    require(key in games and key not in record["baseline_ids"], "registration is not new relative to staging baseline")
    matches = []
    for game in games.values():
        try:
            same = os.path.samefile(safe_path(game["exe"]), exe)
        except FileNotFoundError:
            same = False  # Unrelated stale entries are not this existing probe inode.
        if same:
            matches.append(game)
    require(len(matches) == 1 and matches[0]["app_id"] == key, "ambiguous probe registration")
    base = safe_path(steam / "steamapps/compatdata", steam)
    require(not base.exists() or base.is_dir(), "invalid compatdata base")
    names = (key, str(int(key) - 2**32)) if int(key) >= 2**31 else (key,)
    for name in names:
        require(not os.path.lexists(base / name), "probe prefix already exists; preserve it")
    if base.exists():
        with os.scandir(base) as children:
            for count, child in enumerate(children):
                require(count < 4096, "too many prefix entries")
                if re.fullmatch(r"-?[0-9]+", child.name) and int(child.name) % 2**32 == int(key):
                    require(False, "probe prefix alias already exists; preserve it")
    require(load_json(source)[1] == source_digest, "registration changed during probe verification")
    return {"purpose": "registration-only-probe", "probe_id": record["probe_id"], "receipt_sha256": receipt_digest,
            "new_id_relative_to_baseline": True, "exe_matches_private_receipt": True, "prefix_absent": True,
            "observed_registration_sha256": source_digest, "preparation_complete": False}


def interactive_workflow(directory, renderer, config=None, *, input_stream=None, output_stream=None, environment=None,
                         steam=None, settings=None, home=None, runtime_root=Path("/")):
    """Common short entry; material creation requires a separate concrete opt-in."""
    import sys

    import preparation_selection as selection

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    options = {"input_stream": stream, "output_stream": output, "environment": environment,
               "steam": steam, "settings": settings, "home": home, "runtime_root": runtime_root}
    if config is None or not config.get("probe_material", False):
        return selection.interactive_selection(directory, renderer, config, **options)
    selection.validate_selection_config(config)
    print("1. 登録済み対象の読み取り検査・計画\n2. 新規登録用の検証ファイルを用意\nq. 取消", file=output)
    answer = stream.readline(32).strip()
    if answer == "1":
        return selection.interactive_selection(directory, renderer, config, **options)
    if answer != "2":
        print("取り消しました。", file=output)
        return 0, None
    directory = safe_path(directory)
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    protected = [steam, settings]
    stage, started, plan = "probe-material-plan", False, None
    try:
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        archive = selection._archive(directory, config["payload"])
        payload = config["payload"]
        plan = plan_probe_material(archive, payload["sha512"], payload["root"], source, steam, home / "Games")
        print("新しく作るフォルダー: " + selection._text(plan.record["destination"]), file=output)
        print(f"内容: {EXE}（{len(plan.raw):,} bytes）と {MARKER}", file=output)
        print("元ファイル: 配布物内 " + MEMBER, file=output)
        print("私有記録: " + selection._text(home / ".local/state/droiddeck-prefix-preparation/probe-store"), file=output)
        print("私有記録・ロック・結果JSONも新規作成します。既存ファイルは上書きしません。", file=output)
        print("EXEは実行しません。ゲーム登録・prefix作成・Proton配置・設定変更は行いません。", file=output)
        print("この内容で新規作成する場合は1、取消はq: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            print("取り消しました。", file=output)
            return 0, None
        stage, started = "probe-material-create", True
        # Only after opt-in. Ancestors are checked, never chmodded or repaired.
        private = selection._private_report_directory(home, protected)
        with PrivateStore(private.parent / "probe-store", create=True) as store:
            key = hashlib.sha256(plan.record["destination"].encode()).hexdigest()
            with store.locked(key):
                report = create_probe_material(plan, lambda: plan_probe_material(
                    archive, payload["sha512"], payload["root"], source, steam, home / "Games", probe_id=plan.record["probe_id"]), store)
        print("検証ファイルを作成しました。DroidDeckで一覧を更新、または新しいprefix-probe.exeを追加してください。", file=output)
        print("追加後も起動せず、このprepare.shの「1」で新しい登録を検査してください。", file=output)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        report = {"mode": "probe-material-stopped", "stage": stage, "check": getattr(error, "preparation_check", stage), "error_class": type(error).__name__,
                  "errno": getattr(error, "errno", None), "writes": [], "partial_files_may_exist": started,
                  "prefix_created": False, "exe_executed": False, "preparation_complete": False}
        if plan is not None:
            report["destination"] = plan.record["destination"]
        print("処理停止: " + report["check"] + " / " + type(error).__name__ + " / errno=" + str(report["errno"]), file=output)
        print("途中のファイルは削除・再利用しません。prefixや設定は変更していません。", file=output)
    report.update(schema_version=1, tool_version=VERSION)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。上記の作成先・停止段階を確認してください。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(saved if saved.parent != directory else saved.name), file=output)
    return 2, str(saved) if saved.parent != directory else saved.name
