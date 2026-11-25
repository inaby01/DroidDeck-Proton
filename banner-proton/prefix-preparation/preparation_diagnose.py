"""diagnose.sh (1.0.0): what in DroidDeck differs from what this tool was built against.

Read-only. Measures the same items as the runtime check every write path makes
(``preparation_runtime_context.plan_runtime_environment``), lists each one next to the
bundle's reference and saves the comparison as the result JSON. Nothing is executed.
Values are hashes, OS fields and presence flags; no paths, environment values or game data.
"""

import os
import re
from pathlib import Path

from preparation_common import VERSION, Invalid, safe_path

MODE = "droiddeck-diagnosis"
# The presence the runtime check compares (preparation_runtime_context.plan_runtime_environment);
# LD_PRELOAD and LD_AUDIT are checked there by content, not presence.
PRESENCE = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PULSE_SERVER", "PROOT_FP_KEY")
FAILURES = (Invalid, OSError, ValueError, KeyError, TypeError, AttributeError)


def _word(value):
    """Only short identifier-like text (status words, hex digests, OS fields); anything else is dropped."""
    return value if type(value) is str and len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9._-]*", value) else None


def _flag(value):
    return value if type(value) is bool else None


def _source(item):
    item = item if type(item) is dict else {}
    return {"status": _word(item.get("status")), "sha256": _word(item.get("sha256")), "executable": _flag(item.get("executable"))}


def _library(item):
    item = item if type(item) is dict else {}
    return {"status": _word(item.get("status")), "sha256": _word(item.get("sha256")), "elf_arm64": _flag(item.get("elf_arm64"))}


def _label(item):
    item = item if type(item) is dict else {}
    return {"status": _word(item.get("status")), "sha256": _word(item.get("sha256"))}


def _release(item):
    item = item if type(item) is dict else {}
    return {key: _word(item.get(key)) for key in ("ID", "VERSION_ID")}


def _mapping(value):
    return value if type(value) is dict else {}


def _umask(report):
    from preparation_runtime_context import _mask
    try:
        return _mask(report)
    except FAILURES:
        return None


def compare(reference, fresh, live=True):
    """Items as (group, name, expected, measured, same); groups follow the runtime check, which
    compares the architecture and umask only for the live root."""
    items = [("os", "os_release", _release(reference.get("os_release")), _release(fresh.get("os_release")))]
    if live:
        items += [("os", "architecture", _word(reference.get("auditor_architecture")), _word(fresh.get("auditor_architecture"))),
                  ("os", "umask", _umask(reference), _umask(fresh))]
    for group, key, shape in (("script", "runtime_sources", _source), ("library", "libraries", _library)):
        expected, measured = _mapping(reference.get(key)), _mapping(fresh.get(key))
        # Only the names this tool measures (its pinned files); a bundle cannot put other text into the report.
        for name in sorted(measured):
            items.append((group, name, shape(expected.get(name)) if name in expected else None,
                          shape(measured.get(name)) if name in measured else None))
    items.append(("label", "etc/steam-compatibility-label", _label(reference.get("label")), _label(fresh.get("label"))))
    expected, measured = _mapping(reference.get("environment_presence")), _mapping(fresh.get("environment_presence"))
    for name in PRESENCE:
        items.append(("environment", name, _flag(expected.get(name)), _flag(measured.get(name))))
    return [{"group": group, "name": name, "expected": want, "measured": have, "same": want == have}
            for group, name, want, have in items]


def interactive_diagnose(directory, renderer, config, *, input_stream=None, output_stream=None, environment=None,
                         steam=None, settings=None, home=None, runtime_root=Path("/")):
    import sys

    import preparation_selection as selection
    from preparation_runtime import inspect_runtime
    from preparation_runtime_context import plan_runtime_environment
    output = sys.stdout if output_stream is None else output_stream
    environment = os.environ if environment is None else environment
    try:
        home = safe_path(home if home is not None else Path.home())
        steam = safe_path(steam if steam is not None else home / ".local/share/Steam")
        settings = safe_path(settings if settings is not None else home / ".local/share/droiddeck-compat")
    except FAILURES as error:
        print("ホームのフォルダーを確かめられないため、測りませんでした（" + type(error).__name__ + "）。", file=output)
        return 1, None
    report = {"mode": MODE, "tool_version": VERSION, "scope": "read-only-droiddeck-diagnosis",
              "writes_other_than_result": False, "wine_executed": False, "preparation_complete": False}
    print("DroidDeckの中の環境を測り、このツールが前提にしている値と比べます（何も変更しません）。", file=output, flush=True)
    try:
        reference = config["runtime_reference"]
        if type(reference) is not dict:
            raise Invalid("runtime reference missing")
        fresh = inspect_runtime(runtime_root, environment)
        items = compare(reference, fresh, live=safe_path(runtime_root) == Path("/"))
        report["items"] = items
        try:
            plan_runtime_environment(runtime_root, reference, environment)
            report["tool_check"] = {"result": "passed"}
        except FAILURES as error:
            report["tool_check"] = {"result": "stopped", "error_class": type(error).__name__,
                                    "reason": str(error) if isinstance(error, Invalid) else None}
        different = [item for item in items if not item["same"]]
        report["different"] = len(different)
        if not different and report["tool_check"]["result"] == "passed":
            print("違いはありません。ツールの前提どおりです。", file=output)
        else:
            print(f"前提と違う項目: {len(different)}件（ツールの確認: " +
                  ("通過" if report["tool_check"]["result"] == "passed" else "止まります") + "）", file=output)
            for item in different:
                print("  " + item["group"] + ": " + item["name"], file=output)
            if report["tool_check"]["result"] == "stopped":
                print("  ツールの確認が止まる理由: " + str(report["tool_check"]["reason"] or report["tool_check"]["error_class"]),
                      file=output)
            print("結果のJSONをNASに置いてください。DroidDeckのどこが変わったかを、これで調べます。", file=output)
        report["status"] = "reported"
    except FAILURES as error:
        report.update(status="stopped", error_class=type(error).__name__,
                      reason=str(error) if isinstance(error, Invalid) else None)
        print("測れませんでした（" + type(error).__name__ + "）。", file=output)
    try:
        saved, _ = selection.save_selection_result(directory, home, report, [steam, settings])
    except (OSError, ValueError):
        print("結果JSONを保存できませんでした。", file=output)
        return 1, None
    print("結果を保存しました: " + selection._text(str(saved)), file=output)
    return 2, str(saved)
