#!/usr/bin/env python3
"""Read Proton choices for one game, without changing Steam or DroidDeck settings."""

import argparse
import json
import runpy
from pathlib import Path


def read_json(path):
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def inspect(home, app_id, compatibility):
    steam = home / ".local/share/Steam"
    settings = home / ".local/share/droiddeck-compat"
    games = read_json(settings / "games.json").get("games", {})
    state = read_json(settings / "state.json")
    selected = games.get(app_id) if isinstance(games, dict) else None
    recorded = state.get("games_applied")
    mapping = compatibility["read_config_mapping"](str(steam / "config/config.vdf"))
    catalog = compatibility["tool_catalog"](str(steam))
    requested = (compatibility["requested_tool"](selected, catalog)
                 if isinstance(selected, dict) else None)
    # This report intentionally omits the complete config and any account information.
    report = {
        "app_id": app_id,
        "ui_choice": selected,
        "resolved_ui_tool": requested,
        "steam_game_tool": mapping.get(app_id),
        "steam_default_tool": mapping.get("0"),
        "state_default_tool": state.get("default"),
        "has_games_applied": isinstance(recorded, dict),
        "last_applied_game_choice": recorded.get(app_id) if isinstance(recorded, dict) else None,
        "steam_running": compatibility["steam_running"](),
        "live_helper_running": compatibility["live_helper_running"](),
        "installed_tools": catalog,
    }
    if isinstance(selected, dict) and selected.get("valve") is False:
        name = selected.get("dir")
        if isinstance(name, str) and name and Path(name).name == name and name not in {".", ".."}:
            directory = steam / "compatibilitytools.d" / name
            report["ui_tool_real_path"] = str(directory.resolve())
            report["ui_tool_installation"] = read_json(directory / "softdenchi-install.json")
            report["ui_tool_launcher_exists"] = (directory / "proton").is_file()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-id", required=True)
    args = parser.parse_args()
    if not args.app_id.isdigit():
        parser.error("ゲームIDは数字で指定してください。")
    script = Path("/usr/local/bin/steam-compatibility")
    if not script.is_file():
        parser.error("DroidDeck内のLinuxターミナルで実行してください。")
    compatibility = runpy.run_path(str(script))
    report = inspect(Path("/root"), args.app_id, compatibility)
    output = Path("softdenchi-selection.json")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"診断情報を保存しました: {output.resolve()}")
    print("Steam・DroidDeckの設定は変更していません。")


if __name__ == "__main__":
    main()
