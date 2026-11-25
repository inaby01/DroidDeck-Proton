#!/usr/bin/env python3
"""Render the files the prefix preparation tool writes into its SoftDenchi Proton slot.

The tool embeds this module and calls ``render_installation``; nothing here writes files.
Only builds named ``<upstream version>-softdenchi-r<N>`` are accepted, and the only mode is
``cleanup``: residual SdProxy cleanup on, Proton's debug log left to the user
(``PROTON_LOG=1`` in DroidDeck's game environment turns it on for one game).
"""

import json
import re

ARCHIVE_NAME = re.compile(r"DroidDeck-Proton-([0-9]{1,4}-[0-9]{1,4}\.[0-9]{1,4}-softdenchi-r[1-9][0-9]{0,3})-aarch64\.tar\.gz")
MODES = ("cleanup",)


def render_installation(archive_name, digest, mode, source_version, source_settings=None):
    """Render expected local customizations from archive inputs, without writing."""
    match = ARCHIVE_NAME.fullmatch(archive_name) if type(archive_name) is str else None
    if not match or mode not in MODES:
        raise ValueError("配布物名または導入モードが不明です。")
    if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{128}", digest):
        raise ValueError("正しいSHA-512を指定してください。")
    version = match[1]
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
    # The observer starts with cleanup; its records go to stderr (DroidDeck's session log).
    configuration = {"PROTON_SOFTDENCHI_CLEANUP": "1"}
    text += "\nuser_settings.update(" + repr(configuration) + ")\n"
    compile(text, "user_settings.py", "exec")
    receipt = json.dumps({"source_archive": archive_name, "sha512": digest, "source_build": fields[1],
                          "installed_dir": folder, "mode": mode}, indent=2) + "\n"
    return {"compatibilitytool.vdf": catalog.encode("utf-8"), "user_settings.py": text.encode("utf-8"),
            "softdenchi-install.json": receipt.encode("utf-8")}
