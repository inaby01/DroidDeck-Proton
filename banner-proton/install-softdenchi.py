#!/usr/bin/env python3
"""Install a private SoftDenchi build outside DroidDeck's automatic replacement family."""

import argparse
import hashlib
import json
import os
import re
import tarfile
import tempfile
from pathlib import Path

ARCHIVE_NAME = re.compile(r"DroidDeck-Proton-(11-12\.8-softdenchi[1-9][A-Za-z0-9.-]*)-aarch64\.tar\.gz")
TOOLS = Path("/root/.local/share/Steam/compatibilitytools.d")


def verify(archive):
    checksum = archive.with_name(archive.name.removesuffix(".tar.gz") + ".sha512sum")
    rows = checksum.read_text().splitlines()
    expected = []
    for row in rows:
        parts = row.split(maxsplit=1)
        if len(parts) == 2 and parts[1].lstrip("*") == archive.name:
            expected.append(parts[0])
    if len(expected) != 1 or not re.fullmatch(r"[0-9a-fA-F]{128}", expected[0]):
        raise ValueError("対応するSHA-512が一意に見つかりません。")
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha512").hexdigest()
    if digest.lower() != expected[0].lower():
        raise ValueError("SHA-512が一致しません。導入していません。")
    return digest


def render_installation(archive_name, digest, mode, source_version, source_settings=None):
    """Render expected local customizations from archive inputs, without writing."""
    match = ARCHIVE_NAME.fullmatch(archive_name)
    if not match or mode not in ("off", "observe", "cleanup"):
        raise ValueError("配布物名または導入モードが不明です。")
    if not re.fullmatch(r"[0-9a-f]{128}", digest):
        raise ValueError("正しいSHA-512を指定してください。")
    version = match[1]
    if mode == "cleanup" and not version.startswith("11-12.8-softdenchi3-"):
        raise ValueError("自動回収モードはsoftdenchi3系列でのみ指定できます。")
    if mode == "observe" and version == "11-12.8-softdenchi1":
        raise ValueError("この配布物には観測処理がありません。")
    if type(source_version) is not bytes or len(source_version) > 4096:
        raise ValueError("配布物内のversionが不明です。")
    fields = source_version.decode("utf-8").split()
    if len(fields) != 2 or fields[1] != "DroidDeck-Proton-" + version:
        raise ValueError("配布物内のversionがファイル名と一致しません。")
    if source_settings is not None and (type(source_settings) is not bytes or len(source_settings) > 1024*1024):
        raise ValueError("設定ファイルが大きすぎます。")
    folder = "SoftDenchi-Proton " + version
    catalog = ('"compatibilitytools"\n{\n  "compat_tools"\n  {\n'
               f'    "SoftDenchi-Proton-{version}"\n    {{\n'
               '      "install_path" "."\n'
               f'      "display_name" "{folder}"\n'
               '      "from_oslist" "windows"\n'
               '      "to_oslist" "linux"\n    }\n  }\n}\n')
    text = source_settings.decode("utf-8").replace("\r\n","\n").replace("\r","\n") if source_settings is not None else "user_settings = {}\n"
    configuration = {"PROTON_SOFTDENCHI_OBSERVE": "1" if mode in {"observe", "cleanup"} else "0",
                     "PROTON_SOFTDENCHI_CLEANUP": "1" if mode == "cleanup" else "0",
                     "PROTON_LOG": "1" if mode in {"observe", "cleanup"} else "0"}
    text += "\nuser_settings.update(" + repr(configuration) + ")\n"
    compile(text, "user_settings.py", "exec")
    receipt = json.dumps({"source_archive": archive_name, "sha512": digest, "source_build": fields[1],
                          "installed_dir": folder, "mode": mode}, indent=2) + "\n"
    return {"compatibilitytool.vdf": catalog.encode("utf-8"), "user_settings.py": text.encode("utf-8"),
            "softdenchi-install.json": receipt.encode("utf-8")}


def install(archive, tools, mode):
    match = ARCHIVE_NAME.fullmatch(archive.name)
    if not match:
        raise ValueError("11-12.8-softdenchi系列の配布tar.gzを指定してください。")
    if not hasattr(tarfile, "data_filter"):
        raise ValueError("安全な展開フィルターに対応したPythonが必要です。")
    version = match[1]
    if mode == "cleanup" and not version.startswith("11-12.8-softdenchi3-"):
        raise ValueError("自動回収モードはsoftdenchi3系列でのみ指定できます。")
    if mode == "observe" and version == "11-12.8-softdenchi1":
        raise ValueError("softdenchi1には観測処理がありません。offを指定してください。")
    folder = "SoftDenchi-Proton " + version
    destination = tools / folder
    if os.path.lexists(destination):
        raise ValueError(f"{folder}は既に存在します。上書きしていません。")
    digest = verify(archive)
    tools.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".softdenchi-install-", dir=tools) as temporary:
        staging = Path(temporary)
        # Extract away from the final name: DroidDeck cannot adopt a half-installed tool.
        with tarfile.open(archive, "r:gz") as package:
            package.extractall(staging, filter="data")
        roots = list(staging.iterdir())
        if len(roots) != 1 or not roots[0].is_dir() or roots[0].is_symlink():
            raise ValueError("配布物の最上位フォルダーが一意ではありません。")
        source = roots[0]
        expected_build = "DroidDeck-Proton-" + version
        fields = (source / "version").read_text().split()
        if len(fields) != 2 or fields[1] != expected_build:
            raise ValueError("配布物内のversionがファイル名と一致しません。")
        for name in ("proton", "toolmanifest.vdf", "compatibilitytool.vdf"):
            if not (source / name).is_file():
                raise ValueError(f"配布物に{name}がありません。")
        if not os.access(source / "proton", os.X_OK):
            raise ValueError("protonに実行権限がありません。")
        # Change both identifiers. Keep version and all Wine binaries as shipped.
        rendered = render_installation(archive.name, digest, mode, (source / "version").read_bytes(),
                                       (source / "user_settings.py").read_bytes() if (source / "user_settings.py").exists() else None)
        for name, raw in rendered.items():
            (source / name).write_bytes(raw)
        # Do not replace an existing installation, including a concurrent install.
        destination.mkdir()
        try:
            source.rename(destination)
        except OSError:
            destination.rmdir()
            raise
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--mode", required=True, choices=("off", "observe", "cleanup"))
    args = parser.parse_args()
    if not Path("/usr/local/bin/droiddeck-proton-run").is_file():
        parser.error("DroidDeck内のLinuxターミナルで実行してください。")
    try:
        destination = install(args.archive.resolve(), TOOLS, args.mode)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"導入中止: {error}\n")
    print(f"導入しました: {destination.name}（{args.mode}）")
    print("ゲームごとのProton設定でこの版を明示的に選択してください。")
    print("一覧に出ない場合は、セッションを停止してDroidDeckを開き直してください。")
    print("選択後、ゲーム・Steamセッション停止中に次を実行してから起動してください:")
    print("steam-compatibility /root/.local/share/Steam")


if __name__ == "__main__":
    main()
