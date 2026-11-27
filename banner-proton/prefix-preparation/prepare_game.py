#!/usr/bin/env python3
"""Build-time tool: emits the four scripts of a bundle and measures DroidDeck's runtime.

The scripts themselves (prepare.sh, status.sh, diagnose.sh, recovery.sh) do the preparation.
"""

import argparse
import json
import sys
import unicodedata
from pathlib import Path

# -I excludes script paths; add only the trusted distribution directory, never CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from preparation_common import (
    MAX_REPORT,
    VERSION,
    Invalid,
    load_json,
    require,
    unchanged,
)
from preparation_runtime import inspect_runtime, runtime_audit_command
from preparation_selection import SCRIPT_ENTRIES, selection_script

__all__ = ["Invalid", "unchanged"]


def display(value):
    # JSON escapes C0/newlines; also escape bidi/format controls before terminal display.
    rendered = json.dumps(value, ensure_ascii=False, indent=2)
    rendered = "".join(f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") and char != "\n"
                   or char in "\u2028\u2029" else char for char in rendered)
    require(len(rendered.encode("utf-8")) <= MAX_REPORT, "report exceeds display limit")
    return rendered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit-selection-script", action="store_true", help="emit one of the four scripts of a bundle")
    mode.add_argument("--emit-runtime-audit", action="store_true", help="print a pasteable read-only runtime audit command")
    mode.add_argument("--inspect-runtime", action="store_true", help="read-only runtime source/library/socket inventory")
    parser.add_argument("--selection-config", type=Path, help="the bundle (bundle.json)")
    parser.add_argument("--script-entry", choices=SCRIPT_ENTRIES, help="which script --emit-selection-script writes")
    parser.add_argument("--runtime-root", type=Path)
    args = parser.parse_args()
    try:
        if args.emit_selection_script:
            require(args.selection_config is not None and args.runtime_root is None, "script emission takes a bundle only")
            print(selection_script(load_json(args.selection_config)[0], args.script_entry or "prepare"), end="")
            return 0
        require(args.selection_config is None and args.script_entry is None, "bundle options require script emission")
        if args.emit_runtime_audit:
            require(args.runtime_root is None, "audit emitter accepts no inputs")
            print(runtime_audit_command(), end="")
            return 0
        require(args.runtime_root is not None, "runtime inspection requires an explicit root")
        report = display({"tool_version": VERSION, **inspect_runtime(args.runtime_root)})
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError, KeyError):
        # Do not echo exception text, filesystem paths or unknown input content.
        parser.exit(1, "Input rejected. Check input formats and paths.\n")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
