#!/usr/bin/env python3
"""Install, select and synchronize a SoftDenchi build for one explicit game."""

import argparse
import json
import os
import runpy
import shutil
import subprocess
import tarfile
import time
from pathlib import Path


def require_stopped(compatibility):
    if compatibility["steam_running"]() or compatibility["live_helper_running"]():
        raise ValueError("ゲーム・Steamセッションを停止してから実行してください。")


def install_or_reuse(archive, tools, mode, installer):
    match = installer["ARCHIVE_NAME"].fullmatch(archive.name)
    if not match:
        raise ValueError("対応するSoftDenchi配布物を指定してください。")
    version = match[1]
    directory = tools / ("SoftDenchi-Proton " + version)
    if not os.path.lexists(directory):
        return installer["install"](archive, tools, mode)
    if directory.is_symlink():
        raise ValueError("導入先がシンボリックリンクのため停止しました。")
    metadata = json.loads((directory / "softdenchi-install.json").read_text())
    if (not isinstance(metadata, dict) or metadata.get("source_archive") != archive.name or metadata.get("mode") != mode
            or metadata.get("sha512") != installer["verify"](archive)):
        raise ValueError("導入済みの版・モード・チェックサムが一致しません。上書きしていません。")
    if (directory / "version").read_text().split()[1:] != ["DroidDeck-Proton-" + version]:
        raise ValueError("導入済みversionが一致しません。")
    if not (directory / "proton").is_file():
        raise ValueError("導入済みのprotonがありません。")
    return directory


def select_game(steam, settings, directory, app_id, compatibility):
    """Write one pending choice using DroidDeck's lock and atomic-write helpers."""
    require_stopped(compatibility)
    with compatibility["locked"](str(settings)):
        require_stopped(compatibility)
        requests, original = compatibility["read_game_requests"](str(settings))
        if original is not None:
            value = json.loads(original)
            if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("games"), dict):
                raise ValueError("既存のgames.jsonの形式が不明なため停止しました。")
        elif (settings / "games.json").exists():
            raise ValueError("既存のgames.jsonを読めないため停止しました。")
        state_file = settings / "state.json"
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        if not isinstance(state, dict):
            raise TypeError("既存のstate.jsonの形式が不明なため停止しました。")
        # Preserve legacy handling for other games; mark only this title as pending.
        applied = state.get("games_applied")
        applied = dict(applied) if isinstance(applied, dict) else (dict(requests) if "tools" in state else {})
        applied.pop(app_id, None)
        state["games_applied"] = applied
        requests[app_id] = {"valve": False, "dir": directory.name}
        backup = settings / "backups" / ("softdenchi-setup-" + str(time.time_ns()))
        backup.mkdir(parents=True)
        for source in [steam / "config/config.vdf", state_file, settings / "games.json"]:
            if source.exists():
                shutil.copy2(source, backup / source.name)
        if not compatibility["write_game_requests"](requests, original, str(settings)):
            # Upstream also returns False when the desired file is already identical.
            current, _ = compatibility["read_game_requests"](str(settings))
            if current != requests:
                raise ValueError("選択情報が途中で変更されたため停止しました。")
        compatibility["write_json"](str(state_file), state)
    return backup


def setup(archive, app_id, mode, home, compatibility, installer, synchronize):
    require_stopped(compatibility)
    steam = home / ".local/share/Steam"
    settings = home / ".local/share/droiddeck-compat"
    if not (steam / "config/config.vdf").is_file():
        raise ValueError("既存のSteam設定がないため停止しました。")
    directory = install_or_reuse(archive, steam / "compatibilitytools.d", mode, installer)
    backup = select_game(steam, settings, directory, app_id, compatibility)
    require_stopped(compatibility)
    synchronize(steam)
    catalog = compatibility["tool_catalog"](str(steam))
    request = {"valve": False, "dir": directory.name}
    wanted = compatibility["requested_tool"](request, catalog)
    mapping = compatibility["read_config_mapping"](str(steam / "config/config.vdf"))
    choices, _ = compatibility["read_game_requests"](str(settings))
    if not wanted or mapping.get(app_id) != wanted or choices.get(app_id) != request:
        raise ValueError("選択と起動設定が一致しません。ゲームを起動せず、表示内容を共有してください。")
    return {"app_id": app_id, "tool": wanted, "directory": directory.name,
            "mode": mode, "selection_verified": True, "backup": str(backup)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--mode", required=True, choices=("off", "observe", "cleanup"))
    args = parser.parse_args()
    if (not args.app_id.isascii() or not args.app_id.isdigit() or args.app_id.startswith("0")
            or not 0 < int(args.app_id) <= 0xFFFFFFFF):
        parser.error("正しいゲームIDを指定してください。")
    script = Path("/usr/local/bin/steam-compatibility")
    if not script.is_file():
        parser.error("DroidDeck内のLinuxターミナルで実行してください。")
    compatibility = runpy.run_path(str(script))
    installer = runpy.run_path(str(Path(__file__).with_name("install-softdenchi.py")))

    def synchronize(steam):
        subprocess.run([str(script), str(steam)], check=True)

    try:
        result = setup(args.archive.resolve(), args.app_id, args.mode, Path("/root"),
                       compatibility, installer, synchronize)
    except (OSError, ValueError, TypeError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"設定未完了: {error}\n")
    Path("softdenchi-setup-result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"完了: ゲーム{args.app_id} → {result['directory']}")
    print("画面でのProton選択・別の同期操作は不要です。このままゲームを起動できます。")


if __name__ == "__main__":
    main()
