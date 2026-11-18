"""Explicit full revalidation of registration material; private receipt writes only.

Never infers success from a prior report or changes EXE/marker/prefix/registration.
The old receipt is retained before an atomic update with new evidence. Historical
creation failure stays unknown; this operation establishes current conditions.
"""

import copy
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from preparation_assets import digest_json, exe_identity, pe_machine
from preparation_common import VERSION, app_id, checked, load_json, require, safe_path
from preparation_payload import inspect_archive
from preparation_probe import (
    EXE,
    MARKER,
    _capture_probe,
    _record_valid,
    _verify_registered_context,
    _verify_revalidation_history,
    verify_probe_registration,
)
from preparation_store import PrivateStore


def _file_pins(exe, destination):
    result = []
    for path in (exe, exe.parent / MARKER, destination / EXE, destination / MARKER):
        info = safe_path(path).stat()
        result.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_nlink))
    for path in (exe.parent, destination, destination.parent):
        info = safe_path(path).stat()
        result.append((info.st_dev, info.st_ino, info.st_mode))
    return result


def _read_record(exe, store_root):
    marker, _ = checked("probe-recovery-marker-read", load_json, exe.parent / MARKER)
    from preparation_probe import ID
    checked("probe-recovery-marker-id", require, type(marker) is dict and type(marker.get("probe_id")) is str and
            ID.fullmatch(marker["probe_id"]), "invalid recovery marker ID")
    with PrivateStore(store_root) as store:
        record, digest = checked("probe-recovery-receipt-read", store.read_record, "probe-runs", marker["probe_id"] + ".json")
    checked("probe-recovery-receipt-schema", _record_valid, record)
    checked("probe-recovery-history-read", _verify_revalidation_history, record, store_root)
    return marker, record, digest


@dataclass(frozen=True)
class ProbeRecoveryPlan:
    digest: str
    inputs: dict = field(repr=False)
    record: dict = field(repr=False)
    context: dict = field(repr=False)
    pins: list = field(repr=False)

    def summary(self):
        ready = self.record["status"] == "probe-ready"
        return {"mode": "probe-recovery-plan", "input_digest": self.digest, "probe_id": self.record["probe_id"],
                "selected_app_id": self.inputs["key"], "exe": self.inputs["exe"], "previous_state": self.record["status"],
                "action": "already-ready-read-only" if ready else "revalidate-private-receipt",
                "full_archive_verified": True, "exe_and_marker_verified": True, "new_id_and_prefix_absence_verified": True,
                "historical_failure": "not-reconstructed", "material_modified": False, "preparation_complete": False,
                "planned_writes": [] if ready else [
                    {"path": str(Path(self.inputs["store_root"]) / "probe-history" / _history_name(self)), "scope": "preserve-original-receipt"},
                    {"path": str(Path(self.inputs["store_root"]) / "probe-runs" / (self.record["probe_id"] + ".json")),
                     "scope": "atomic-private-receipt-update-with-revalidation-evidence"}], "writes": []}


def _history_name(plan):
    return plan.record["probe_id"] + "-" + plan.inputs["receipt_digest"] + ".json"


def _digest(inputs, record, context, pins):
    return digest_json({"tool_version": VERSION, "inputs": inputs, "record": record, "context": context, "pins": pins})


def plan_probe_recovery(archive, sha512, archive_root, exe, key, source, steam, store_root):
    archive, exe, source, steam, store_root = map(safe_path, (archive, exe, source, steam, store_root))
    key = app_id(key)
    checked("probe-recovery-exe-name", require, exe.name == EXE, "not a probe executable")
    marker, record, receipt_digest = _read_record(exe, store_root)
    context = _verify_registered_context(record, marker, exe, key, source, steam, receipt_digest)
    destination = safe_path(record["destination"])
    checked("probe-recovery-store-disjoint", require,
            not (store_root == destination or store_root.is_relative_to(destination) or destination.is_relative_to(store_root)),
            "recovery store overlaps material")
    pins = _file_pins(exe, destination)
    checked("probe-recovery-pinned-archive", require, sha512 == record["archive_sha512"], "recovery archive differs from creation")
    inventory = checked("probe-recovery-full-archive", inspect_archive, archive, sha512, archive_root)
    checked("probe-recovery-inventory", require, inventory.digest == record["inventory_digest"], "recovery inventory differs")
    raw = checked("probe-recovery-member", _capture_probe, archive, inventory)
    import io
    identity = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                "pe_machine": pe_machine(io.BytesIO(raw), len(raw)), "provenance": "local-measurement-only"}
    checked("probe-recovery-source-bytes", require, identity == record["exe_identity"] and exe_identity(destination / EXE) == identity,
            "recovery bytes differ from pinned archive")
    checked("probe-recovery-context-stable", require,
            _verify_registered_context(record, marker, exe, key, source, steam, receipt_digest) == context and
            _file_pins(exe, destination) == pins, "recovery material or registration changed")
    marker_now, record_now, digest_now = _read_record(exe, store_root)
    checked("probe-recovery-receipt-stable", require,
            marker_now == marker and record_now == record and digest_now == receipt_digest, "recovery receipt changed")
    inputs = {"archive": str(archive), "sha512": sha512, "archive_root": archive_root, "exe": str(exe), "key": key,
              "source": str(source), "steam": str(steam), "store_root": str(store_root), "receipt_digest": receipt_digest}
    return ProbeRecoveryPlan(_digest(inputs, record, context, pins), inputs, copy.deepcopy(record), context, pins)


def _verify_before_commit(plan, store):
    store._guard()
    values = plan.inputs
    exe, source, steam = map(safe_path, (values["exe"], values["source"], values["steam"]))
    marker, record, digest = _read_record(exe, store.root)
    checked("probe-recovery-final-receipt-pin", require, record == plan.record and digest == values["receipt_digest"], "recovery receipt changed")
    checked("probe-recovery-final-input-pin", require,
            _verify_registered_context(record, marker, exe, values["key"], source, steam, digest) == plan.context and
            _file_pins(exe, safe_path(record["destination"])) == plan.pins, "recovery input changed before commit")


def apply_probe_recovery(plan, refresh, store):
    require(isinstance(plan, ProbeRecoveryPlan) and callable(refresh), "trusted recovery plan required")
    store._guard()
    checked("probe-recovery-matching-lock", require, store.root == safe_path(plan.inputs["store_root"]) and
            store._held_target == hashlib.sha256(plan.record["destination"].encode()).hexdigest(), "matching recovery lock required")
    checked("probe-recovery-plan-pin", require, plan.digest == _digest(plan.inputs, plan.record, plan.context, plan.pins), "recovery plan mutated")
    fresh = refresh()  # Whole archive and all conditions repeated under the global/target locks.
    checked("probe-recovery-refresh-pin", require, isinstance(fresh, ProbeRecoveryPlan) and fresh == plan, "recovery plan changed")
    if plan.record["status"] == "probe-ready":
        return {**plan.summary(), "mode": "probe-recovery-already-ready", "receipt_revalidated_now": False}
    checked("probe-recovery-final-inputs", _verify_before_commit, plan, store)
    name = _history_name(plan)
    with store.directory(("probe-history",), create=True) as fd:
        old = store._read(fd, name, missing=True)
    if old is None:
        checked("probe-recovery-history-create", store.write_record, "probe-history", name, plan.record)
    historical, historical_digest = store.read_record("probe-history", name)
    checked("probe-recovery-history-identity", require,
            historical == plan.record and historical_digest == plan.inputs["receipt_digest"], "recovery history differs")
    updated = copy.deepcopy(plan.record)
    updated["status"] = "probe-ready"
    updated["revalidation"] = {"schema_version": 1, "tool_version": VERSION, "previous_state": plan.record["status"],
        "previous_receipt_sha256": plan.inputs["receipt_digest"], "history_record": name,
        "archive_sha512": plan.record["archive_sha512"], "inventory_digest": plan.record["inventory_digest"],
        "registration_id": plan.inputs["key"], "registration_sha256": plan.context["observed_registration_sha256"],
        "context_digest": digest_json(plan.context)}
    checked("probe-recovery-new-record-schema", _record_valid, updated)
    digest = checked("probe-recovery-atomic-update", store.write_record, "probe-runs", updated["probe_id"] + ".json", updated,
                     plan.inputs["receipt_digest"], lambda: _verify_before_commit(plan, store))
    current, actual_digest = store.read_record("probe-runs", updated["probe_id"] + ".json")
    checked("probe-recovery-update-readback", require, current == updated and actual_digest == digest, "recovery update readback differs")
    proof = checked("probe-recovery-normal-verification", verify_probe_registration, safe_path(plan.inputs["exe"]), plan.inputs["key"],
                    safe_path(plan.inputs["source"]), safe_path(plan.inputs["steam"]), store.root)
    return {"mode": "probe-recovered", "probe_id": updated["probe_id"], "selected_app_id": plan.inputs["key"],
            "receipt_revalidated_now": True, "previous_state": plan.record["status"], "historical_failure": "unknown-preserved",
            "archive_fully_rechecked": True, "probe_registration": proof,
            "writes": plan.summary()["planned_writes"] if old is None else plan.summary()["planned_writes"][1:],
            "history_created": old is None, "material_modified": False, "prefix_created": False,
            "exe_executed": False, "registration_written": False, "preparation_complete": False}


def interactive_recovery(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                         steam=None, settings=None, home=None, runtime_root=Path("/")):
    import sys

    import preparation_selection as selection

    stream = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    directory = safe_path(directory)
    home = safe_path(home if home is not None else Path.home())
    steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
    settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    store_root = safe_path(home / ".local/state/droiddeck-prefix-preparation/probe-store")
    protected = [steam, settings]
    stage, started, report = "probe-recovery-selection", False, None
    try:
        config = selection.validate_selection_config(copy.deepcopy(config))
        source, _, games = selection.registration_catalog(environment)
        protected.extend(Path(game["exe"]).parent for game in games.values())
        candidates = [key for key in games if Path(games[key]["exe"]).name == EXE]
        require(candidates, "no registered probe material")
        for index, key in enumerate(candidates, 1):
            print(f"{index}. {selection._text(games[key]['title'])}  [ID {key}]", file=output)
            print("   " + selection._text(games[key]["exe"]), file=output)
        print("復帰する検証用登録の番号（qで取消）: ", end="", file=output, flush=True)
        answer = stream.readline(32).strip()
        if not answer or answer.lower() == "q":
            print("取り消しました。", file=output)
            return 0, None
        require(answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(candidates), "invalid probe selection")
        key = candidates[int(answer) - 1]
        exe = safe_path(games[key]["exe"])
        stage = "probe-recovery-plan"
        payload = config["payload"]
        archive = selection._archive(directory, payload)

        def refresh():
            return plan_probe_recovery(archive, payload["sha512"], payload["root"], exe, key, source, steam, store_root)

        print("配布物全体と既存ファイルを検査しています。ファイルは変更しません。", file=output, flush=True)
        plan = refresh()
        preview = plan.summary()
        print("配布物全体・EXE・目印・新規ID・prefix不在を照合しました。", file=output)
        print("対象: " + selection._text(exe), file=output)
        if preview["action"] == "already-ready-read-only":
            print("記録は既に完了しています。読み取り計画へ進みます。", file=output)
            report = {**preview, "mode": "probe-recovery-already-ready", "receipt_revalidated_now": False}
        else:
            print("元の状態: " + preview["previous_state"], file=output)
            for item in preview["planned_writes"]:
                print("私有記録の書込先: " + selection._text(item["path"]), file=output)
            print("元の失敗記録を保全し、全照合の証拠付きで私有記録を完了へ更新します。", file=output)
            print("EXE・目印・登録・prefix・Protonは変更／実行しません。結果JSONも新規保存します。", file=output)
            print("この内容で復帰する場合は1、取消はq: ", end="", file=output, flush=True)
            if stream.readline(32).strip() != "1":
                print("取り消しました。", file=output)
                return 0, None
            stage, started = "probe-recovery-apply", True
            print("ロック下で全体を再検査し、元の私有記録を保全して更新します。", file=output, flush=True)
            with PrivateStore(store_root) as store, store.locked(hashlib.sha256(plan.record["destination"].encode()).hexdigest()):
                report = apply_probe_recovery(plan, refresh, store)
            print("私有記録を全照合の証拠付きで復帰しました。続けて同じ対象の計画を保存します。", file=output)
        stage = "probe-recovery-followup-plan"
        print("続けて同じ対象の読み取り計画を作成しています。", file=output, flush=True)
        source_now, digest_now, games_now = selection.registration_catalog(environment)
        report["followup_plan"] = selection.selected_plan(directory, config, key, source_now, digest_now, games_now,
            steam, settings, home, renderer, environment, runtime_root)
        print("登録・prefix不在を再検査し、準備計画を生成しました。準備の実行はまだ行いません。", file=output)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        failure = {"stage": stage, "check": getattr(error, "preparation_check", stage), "error_class": type(error).__name__,
                   "errno": getattr(error, "errno", None)}
        if report is None:
            report = {"mode": "probe-recovery-stopped", "private_receipt_may_have_changed": started,
                      "material_modified": False, "prefix_created": False, "exe_executed": False,
                      "writes": [{"path": str(store_root), "scope": "private-recovery-attempt-outcome-unknown"}] if started else []}
        report["error"] = failure
        print("処理停止: " + failure["check"] + " / " + failure["error_class"] + " / errno=" + str(failure["errno"]), file=output)
        print("元のファイルはそのまま保持します。新しい結果JSONを確認してください。", file=output)
    report.update(schema_version=1, tool_version=VERSION, preparation_complete=False)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, protected)
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。画面の停止段階を確認してください。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(saved if saved.parent != directory else saved.name), file=output)
    return 2, str(saved) if saved.parent != directory else saved.name
