"""Diagnostic log of the SoftDenchi installer run (design: installer log, 0.31.2).

Only with ``diagnostics.installer_log`` in the bundle. The installer's standard error is a
private append-only file; nothing reads it while the installer runs. Once the installer
has exited and no process of the prefix is visible, the file is fixed up to its current
end as ``final.log`` and the processes still holding it are counted. Results carry only a
summary of allowed forms (no paths, no names outside fixed lists). A copy next to the
shared result is made only after the operator confirms it, for an install that did not
end present-verified.
"""

import errno
import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path

from preparation_common import VERSION, Invalid, fields, require, safe_path

RECORDS = "installer-logs"
LOG_BUDGET = 16 * 1024 * 1024  # Added to the pre-install capacity check of the work directory.
WINEDEBUG = "fixme-all,warn+msi"  # Every err class; warn for msi only.
# Other log switches a slot's user_settings.py could turn on; set so they keep out of the log.
QUIET = {"DXVK_LOG_LEVEL": "none", "DXVK_NVAPI_LOG_LEVEL": "none", "VKD3D_DEBUG": "none",
         "VKD3D_SHADER_DEBUG": "none", "WINE_MONO_TRACE": ""}
LIVE, FINAL = "live.log", "final.log"
HEAD, TAIL = 1024 * 1024, 4 * 1024 * 1024
MAX_ENTRIES, MAX_SUMMARY = 40, 8 * 1024
STATES = ("open", "final", "none")
ID = re.compile(r"depinstall-[0-9a-f]{32}\Z", re.ASCII)

# Fixed lists from the pinned Wine (proton-wine 303894db): functions printing ERR/WARN in
# dlls/msi/action.c, dlls/msi/custom.c, dlls/ntdll/loader.c, dlls/ntdll/exception.c,
# dlls/kernelbase/debug.c, and msi's standard action table.
FUNCTIONS = frozenset((
    "ACTION_InstallFinalize", "ACTION_PerformAction", "ACTION_PerformEndAction", "ACTION_ProcessComponents",
    "ITERATE_Actions", "ITERATE_BindImage", "ITERATE_CostFinalizeConditions", "ITERATE_CreateFolders",
    "ITERATE_CreateShortcuts", "ITERATE_DeleteService", "ITERATE_InstallODBCDataSource", "ITERATE_InstallODBCDriver",
    "ITERATE_InstallODBCTranslator", "ITERATE_InstallService", "ITERATE_PublishIcon", "ITERATE_RegisterTypeLibraries",
    "ITERATE_RemoveEnvironmentString", "ITERATE_RemoveFolders", "ITERATE_RemoveIniValuesOnInstall",
    "ITERATE_RemoveIniValuesOnUninstall", "ITERATE_RemoveODBCDataSource", "ITERATE_RemoveODBCDriver",
    "ITERATE_RemoveODBCTranslator", "ITERATE_RemoveShortcuts", "ITERATE_SelfRegModules", "ITERATE_SelfUnregModules",
    "ITERATE_StartService", "ITERATE_StopService", "ITERATE_UnpublishComponent", "ITERATE_UnregisterTypeLibraries",
    "ITERATE_WriteEnvironmentString", "ITERATE_WriteRegistryValues", "MSI_InstallPackage", "Typelib_EnumResNameProc",
    "admin_create_dest_file", "admin_remove_cabinet_streams", "bind_image", "env_parse_flags", "execute_script",
    "get_ini_file_name", "get_link_file", "get_root_key", "iterate_load_featurecomponents",
    "join_multi_string_values", "load_file", "load_file_disk_id", "load_patch", "load_patch_disk_id",
    "msi_parse_command_line", "open_env_key", "publish_patches", "publish_upgrade_code",
    "remove_product_upgrade_code", "stop_service", "ACTION_CallScript", "ACTION_CustomAction", "HANDLE_CustomType17",
    "HANDLE_CustomType21_22", "__wine_msi_call_dll_function", "action_type_matches_script", "create_temp_binary",
    "custom_client_thread", "custom_get_thread_return", "custom_start_server", "do_msidbCustomActionTypeDll",
    "execute_command", "write_substorage_to_file", "LdrGetProcedureAddress", "LdrProcessRelocationBlock",
    "alloc_module", "alloc_tls_slot", "find_forwarded_export", "fixup_imports_ilonly", "import_dll", "init_wow64",
    "load_arm64ec_module", "load_dll", "load_so_dll", "loader_init", "map_wow64cpu", "perform_relocations",
    "process_attach", "use_lsteamclient", "_assert", "dispatch_exception", "dispatch_user_callback",
    "user_callback_handler", "FatalAppExitA", "FatalAppExitW", "OutputDebugStringA", "OutputDebugStringW",
    "RaiseFailFastException", "start_debugger",
))
ACTIONS = frozenset((
    "AllocateRegistrySpace", "AppSearch", "BindImage", "CCPSearch", "CostFinalize", "CostInitialize", "CreateFolders",
    "CreateShortcuts", "DeleteServices", "DisableRollback", "DuplicateFiles", "ExecuteAction", "FileCost",
    "FindRelatedProducts", "ForceReboot", "InstallAdminPackage", "InstallExecute", "InstallExecuteAgain",
    "InstallFiles", "InstallFinalize", "InstallInitialize", "InstallODBC", "InstallServices", "InstallSFPCatalogFile",
    "InstallValidate", "IsolateComponents", "LaunchConditions", "MigrateFeatureStates", "MoveFiles",
    "MsiPublishAssemblies", "MsiUnpublishAssemblies", "PatchFiles", "ProcessComponents", "PublishComponents",
    "PublishFeatures", "PublishProduct", "RegisterClassInfo", "RegisterComPlus", "RegisterExtensionInfo",
    "RegisterFonts", "RegisterMIMEInfo", "RegisterProduct", "RegisterProgIdInfo", "RegisterTypeLibraries",
    "RegisterUser", "RemoveDuplicateFiles", "RemoveEnvironmentStrings", "RemoveExistingProducts", "RemoveFiles",
    "RemoveFolders", "RemoveIniValues", "RemoveODBC", "RemoveRegistryValues", "RemoveShortcuts", "ResolveSource",
    "RMCCPSearch", "ScheduleReboot", "SelfRegModules", "SelfUnregModules", "SetODBCFolders", "StartServices",
    "StopServices", "UnpublishComponents", "UnpublishFeatures", "UnpublishProduct", "UnregisterClassInfo",
    "UnregisterComPlus", "UnregisterExtensionInfo", "UnregisterFonts", "UnregisterMIMEInfo", "UnregisterProgIdInfo",
    "UnregisterTypeLibraries", "ValidateProductID", "WriteEnvironmentStrings", "WriteIniValues",
    "WriteRegistryValues", "INSTALL", "ADMIN",
))
CHANNELS = ("msi", "module", "seh", "ole", "setupapi", "service")
# Thread and process IDs are at least four hex digits; a timestamp and the IDs may be absent.
LINE = re.compile(r"^\s*(?:[0-9]+\.[0-9]+:)?(?:[0-9a-f]{4,}:){0,2}(err|warn):([a-z0-9_]{1,32}):([A-Za-z_][A-Za-z0-9_]{0,63})\b(.*)$")
WINE_KINDS = (("unimplemented function", "unimplemented-function"), ("Unhandled exception", "unhandled-exception"),
              ("is a dll, not an executable", "dll-not-executable"), ("failed to create main module", "main-module-failed"),
              ("could not load kernel32.dll", "kernel32-not-loaded"))


def enabled(config):
    """Whether the bundle turns the installer log on (a strict boolean, design 3.0)."""
    diagnostics = config.get("diagnostics")
    return type(diagnostics) is dict and diagnostics.get("installer_log") is True


def validate_diagnostics(value):
    fields(value, (), ("installer_log",))
    require(type(value.get("installer_log", False)) is bool, "invalid installer log option")
    return value


def launch_environment(environment):
    """The installer's environment with the diagnostic channels (only together with a log file)."""
    return {**environment, **QUIET, "WINEDEBUG": WINEDEBUG}


def validate_record(record):
    fields(record, ("schema_version", "kind", "tool_version", "install_id", "app_id", "state", "reason", "final", "shared_copy"))
    require(record["schema_version"] == 1 and record["kind"] == "installer-log", "unknown installer log record")
    require(type(record["tool_version"]) is str and 0 < len(record["tool_version"]) <= 64, "invalid installer log writer")
    require(type(record["install_id"]) is str and ID.fullmatch(record["install_id"]), "invalid installation ID")
    require(type(record["app_id"]) is str and record["app_id"].isdigit() and len(record["app_id"]) <= 10, "invalid app ID")
    require(record["state"] in STATES, "unknown installer log state")
    require(record["reason"] is None or type(record["reason"]) is str and len(record["reason"]) <= 200, "invalid reason")
    final = record["final"]
    require((final is None) == (record["state"] != "final"), "final data only for a final log")
    if final is not None:
        fields(final, ("bytes", "sha256", "writers_remaining", "writers_unreadable", "summary"))
        require(type(final["bytes"]) is int and final["bytes"] >= 0 and type(final["sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", final["sha256"]) is not None, "invalid final log")
        require(type(final["writers_remaining"]) is int and type(final["writers_unreadable"]) is int, "invalid writer count")
        require(type(final["summary"]) is dict, "invalid summary")
    shared = record["shared_copy"]
    require(shared is None or type(shared) is dict, "invalid shared copy")
    return record


class LiveLog:
    """The open log of one installer run: the write end for the installer, a read end for the tool."""

    def __init__(self, folder, write_fd, read_fd, identity):
        self.folder, self.write_fd, self.read_fd, self.identity = folder, write_fd, read_fd, identity

    def close_write(self):
        if self.write_fd is not None:
            os.close(self.write_fd)
            self.write_fd = None

    def close(self):
        try:
            self.close_write()
        finally:
            if self.read_fd is not None:
                read_fd, self.read_fd = self.read_fd, None
                os.close(read_fd)


WORK_ROOT = ".local/share/droiddeck-preparation-work"  # The per-game private work folder (as the managed recheck).


def work_parent(home, app_id):
    require(type(app_id) is str and app_id.isdigit() and len(app_id) <= 10, "invalid app ID")
    return safe_path(safe_path(home) / WORK_ROOT / app_id, safe_path(home))


def log_folder(home, app_id, install_id):
    require(type(install_id) is str and ID.fullmatch(install_id), "invalid installation ID")
    return safe_path(work_parent(home, app_id) / "logs" / install_id, safe_path(home))


def _record(install_id, app_id, state, reason=None, final=None):
    return validate_record({"schema_version": 1, "kind": "installer-log", "tool_version": VERSION, "install_id": install_id,
                            "app_id": app_id, "state": state, "reason": reason, "final": final, "shared_copy": None})


def open_log(store, install_id, app_id, home):
    """Create the private log and its ``open`` record before the installer starts.

    Returns (LiveLog or None, record hash or None). Any failure leaves the installer to
    run as before (standard error to /dev/null) with the reason recorded when possible.
    """
    from preparation_trial import _new_private
    live = None
    try:
        folder = log_folder(home, app_id, install_id)
        _new_private(folder, work_parent(home, app_id))
        write_fd = os.open(folder / LIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_APPEND | os.O_CLOEXEC,
                           0o600)
        try:
            read_fd = os.open(folder / LIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except BaseException:
            os.close(write_fd)
            raise
        live = LiveLog(folder, write_fd, read_fd, None)  # Owns both ends from here, so a failure below closes them.
        info = os.fstat(write_fd)
        live.identity = (info.st_dev, info.st_ino)
        require((os.fstat(read_fd).st_dev, os.fstat(read_fd).st_ino) == live.identity and stat.S_ISREG(info.st_mode),
                "installer log replaced")
        digest = store.write_record(RECORDS, install_id + ".json", _record(install_id, app_id, "open"))
        return live, digest
    except (OSError, Invalid, TypeError, ValueError) as error:
        if live is not None:
            live.close()
        reason = "log-unavailable:" + type(error).__name__
        try:
            digest = store.write_record(RECORDS, install_id + ".json", _record(install_id, app_id, "none", reason))
        except (OSError, Invalid, TypeError, ValueError):
            digest = None
        return None, digest


def _writers(identity, proc_root):
    """Processes of this user, other than the tool, holding the log file open (read-only /proc scan)."""
    remaining, unreadable = 0, 0
    own = os.getpid()
    try:
        names = [name for name in os.listdir(proc_root) if name.isdigit()]
    except OSError:
        return 0, 1
    for name in names:
        if int(name) == own:
            continue
        base = Path(proc_root) / name
        try:
            if os.stat(base, follow_symlinks=False).st_uid != os.getuid():
                continue
            descriptors = os.listdir(base / "fd")
        except FileNotFoundError:
            continue
        except OSError:
            unreadable += 1
            continue
        for fd in descriptors:
            try:
                info = os.stat(base / "fd" / fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                remaining += 1
                break
    return remaining, unreadable


def _place(folder_fd, temporary, name):
    """Give a finished temporary file its final name without replacing anything.

    Linux ``renameat2(RENAME_NOREPLACE)`` first (it works on the device, as the slot placement
    shows), then a hard link. ``FileExistsError`` when the name is taken; another OSError when
    neither is available. The temporary name is gone after a rename and stays after a link.
    """
    from preparation_publication import _rename_function, rename_noreplace
    try:
        rename_noreplace(_rename_function(), folder_fd, temporary, folder_fd, name)
        return "rename-noreplace"
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise FileExistsError(errno.EEXIST, "name exists") from None
    except Invalid:
        pass  # No renameat2 (not Linux, or no libc symbol): try a link.
    os.link(temporary, name, src_dir_fd=folder_fd, dst_dir_fd=folder_fd, follow_symlinks=False)
    return "link"


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        require(written > 0, "short write")
        view = view[written:]


def _copy_range(read_fd, folder, size):
    """Write bytes [0, size) of the live log to ``final.log`` (temporary file, then a non-replacing name)."""
    digest = hashlib.sha256()
    folder_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = "final-" + secrets.token_hex(8) + ".tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=folder_fd)
        try:
            offset = 0
            while offset < size:
                chunk = os.pread(read_fd, min(1024 * 1024, size - offset), offset)
                if not chunk:
                    break
                _write_all(fd, chunk)
                digest.update(chunk)
                offset += len(chunk)
            os.fsync(fd)
        finally:
            os.close(fd)
        _place(folder_fd, temporary, FINAL)
        os.fsync(folder_fd)
        return offset, digest.hexdigest()
    finally:
        try:
            os.unlink(temporary, dir_fd=folder_fd)  # Only the tool's own temporary file.
        except FileNotFoundError:
            pass
        os.close(folder_fd)


def finalize(store, live, install_record, stop, proc_root="/proc"):
    """Fix the log once the installer stage is over (design 3.5); returns the log record.

    The installer must have exited and no process of the prefix may be visible now;
    otherwise the record stays ``open``. Nothing here raises into the installer handling.
    """
    install_id = install_record["install_id"]
    try:
        current, digest = store.read_record(RECORDS, install_id + ".json")
        validate_record(current)
    except (OSError, Invalid, TypeError, ValueError, KeyError):
        _close_quietly(live)
        return None
    if current["state"] != "open" or live is None:
        _close_quietly(live)
        return current
    try:
        live.close_write()
        if install_record["installer"]["status"] not in ("exited", "exited-processes-remain"):
            return current
        if not stop.check()["clear_in_view"]:
            return current
        size = os.fstat(live.read_fd).st_size
        written, sha = _copy_range(live.read_fd, live.folder, size)
        remaining, unreadable = _writers(live.identity, proc_root)
        summary = summarize_file(live.folder / FINAL)
        record = {**current, "state": "final",
                  "final": {"bytes": written, "sha256": sha, "writers_remaining": remaining,
                            "writers_unreadable": unreadable, "summary": summary}}
        validate_record(record)
        store.write_record(RECORDS, install_id + ".json", record, digest)
        return record
    except (OSError, Invalid, TypeError, ValueError, KeyError) as error:
        # Stays open; the reason is kept so a result can say why (no path, the class only).
        kept = {**current, "reason": "finalize-failed:" + type(error).__name__}
        try:
            store.write_record(RECORDS, install_id + ".json", validate_record(kept), digest)
            return kept
        except (OSError, Invalid, TypeError, ValueError):
            return current
    finally:
        _close_quietly(live)


def _close_quietly(live):
    if live is not None:
        try:
            live.close()
        except OSError:
            pass


def abandon(store, live, install_id):
    """The installer was never started: close the log and record that there is none (never raises).

    Without this the ``open`` record would stay in menu 9 for a run that wrote nothing.
    """
    _close_quietly(live)
    try:
        current, digest = store.read_record(RECORDS, install_id + ".json")
        validate_record(current)
        if current["state"] != "open":
            return current
        record = validate_record({**current, "state": "none", "reason": "installer-not-started"})
        store.write_record(RECORDS, install_id + ".json", record, digest)
        return record
    except (OSError, Invalid, TypeError, ValueError, KeyError):
        return None


def summarize_file(path):
    """The allowed summary of a fixed log: its first HEAD and last TAIL bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        size = os.fstat(fd).st_size
        if size <= HEAD + TAIL:
            data = os.pread(fd, size, 0)
        else:
            data = os.pread(fd, HEAD, 0) + b"\n" + os.pread(fd, TAIL, size - TAIL)
    finally:
        os.close(fd)
    return summarize(data)


def summarize(data):
    """Counts and fixed forms only: no paths, no names outside the fixed lists (design 3.6)."""
    channels, functions, codes, kinds = {}, {}, {}, {}
    counts = {"execution-halted": 0, "script-halted": 0, "failed-to-load-dll": 0, "failed-to-start-service": 0}
    entries = []
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith("wine: "):
            kind = next((name for text, name in WINE_KINDS if text in line), "other")
            kinds[kind] = kinds.get(kind, 0) + 1
            entries.append({"class": "wine", "kind": kind})
            continue
        match = LINE.match(line)
        if match is None or match.group(2) not in CHANNELS:
            continue
        level, channel, function, rest = match.groups()
        key = level + ":" + channel
        channels[key] = channels.get(key, 0) + 1
        name = function if function in FUNCTIONS else "other"
        functions[key + ":" + name] = functions.get(key + ":" + name, 0) + 1
        entry = {"class": key, "function": name}
        returned = re.search(r"\breturned (\d{1,5})\b", rest)
        if returned and int(returned.group(1)) <= 65535:
            entry["returned"] = int(returned.group(1))
            codes[returned.group(1)] = codes.get(returned.group(1), 0) + 1
        action = re.search(r'action L?"([A-Za-z0-9_.]{1,64})"', rest)
        if action:
            entry["action"] = action.group(1) if action.group(1) in ACTIONS else "custom"
        for text, counter in (("Execution halted", "execution-halted"), ("Execution of script", "script-halted"),
                              ("failed to load dll", "failed-to-load-dll"), ("failed to start service", "failed-to-start-service")):
            if text in rest:
                counts[counter] += 1
        entries.append(entry)
    # msi errors and wine: lines first, then the rest from the end (the deciding lines come last).
    first = [entry for entry in entries if entry["class"] in ("err:msi", "wine")][-MAX_ENTRIES:]
    rest = [entry for entry in entries if entry["class"] not in ("err:msi", "wine")]
    chosen = first + rest[-(MAX_ENTRIES - len(first)):] if len(first) < MAX_ENTRIES else first
    summary = {"lines": len(entries), "channels": dict(sorted(channels.items())[:32]),
               "functions": dict(sorted(functions.items())[:32]), "returned": dict(sorted(codes.items())[:16]),
               "messages": counts, "wine": dict(sorted(kinds.items())), "entries": chosen}
    while len(json.dumps(summary)) > MAX_SUMMARY and summary["entries"]:
        summary["entries"] = summary["entries"][1:]
    return summary


def report_view(record):
    """What a result JSON carries about one installer log (no paths)."""
    if record is None:
        return None
    view = {"install_id": record["install_id"], "app_id": record["app_id"], "state": record["state"], "reason": record["reason"]}
    if record["final"] is not None:
        view.update(bytes=record["final"]["bytes"], writers_remaining=record["final"]["writers_remaining"],
                    summary=record["final"]["summary"])
    return view


def shared_copy_candidates(views, statuses):
    """Final logs of installs that did not end present-verified (design 3.7), by install ID."""
    return [view for view in views if view and view["state"] == "final" and statuses.get(view["install_id"]) != "present-verified"]


def hold_folder(folder):
    """Open the shared folder and keep it open: while held, its inode number cannot be given to a new folder."""
    return os.open(safe_path(folder), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def copy_to_shared(store, install_id, app_id, home, shared_folder, expected=None):
    """Copy ``final.log`` next to the shared result without replacing anything; returns (name or None, reason).

    ``expected``: the (device, inode) of the folder the operator confirmed; another folder at that path is refused.
    """
    name = "installer-" + install_id + ".log"
    try:
        source = log_folder(home, app_id, install_id) / FINAL
        current, digest = store.read_record(RECORDS, install_id + ".json")
        validate_record(current)
        require(current["state"] == "final" and current["shared_copy"] is None, "log not final or already copied")
        folder_fd = os.open(safe_path(shared_folder), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except (OSError, Invalid, TypeError, ValueError, KeyError) as error:
        return None, "not-copied:" + type(error).__name__
    info = os.fstat(folder_fd)
    if expected is not None and (info.st_dev, info.st_ino) != tuple(expected):
        os.close(folder_fd)
        return None, "not-copied:folder-changed"
    temporary = "." + name + "." + secrets.token_hex(8) + ".tmp"
    created, placed, note = False, False, None
    try:
        src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder_fd)
            created = True
            try:
                sha = hashlib.sha256()
                while chunk := os.read(src, 1024 * 1024):
                    _write_all(fd, chunk)
                    sha.update(chunk)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(src)
        require(sha.hexdigest() == current["final"]["sha256"], "installer log changed")
        _place(folder_fd, temporary, name)
        placed = True
        os.fsync(folder_fd)
    except FileExistsError:
        return None, "not-copied:name-exists"
    except (OSError, Invalid, ValueError) as error:
        if placed:
            # The file is there under its name; only making that durable failed.
            note = "copied-sync-failed:" + type(error).__name__
        else:
            return None, "not-copied:" + type(error).__name__
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=folder_fd)  # Only the tool's own temporary file.
            except OSError:
                pass
        os.close(folder_fd)
    try:
        store.write_record(RECORDS, install_id + ".json", {**current, "shared_copy": {"name": name}}, digest)
    except (OSError, Invalid, TypeError, ValueError):
        pass  # The copy exists; the result tells the operator.
    return name, note


COPY_LOCK = hashlib.sha256(b"droiddeck-installer-logs").hexdigest()  # One lock file for every shared copy.


def offer_shared_copies(views, statuses, *, saved, shared_folder, store_root, home, stream, output, text, labels=None):
    """Ask, per eligible log, whether to copy it next to the shared result (design 3.7). Returns the copies made.

    ``saved`` must be the shared path of this result; a result kept privately is never accompanied by a copy.
    """
    candidates = shared_copy_candidates(views, statuses)
    done = []
    if not candidates or saved is None or safe_path(Path(saved).parent) != safe_path(shared_folder):
        return done
    try:
        held = hold_folder(shared_folder)  # The folder shown is the folder written to (Codex medium).
    except OSError:
        return done
    try:
        info = os.fstat(held)
        return _offer(candidates, (info.st_dev, info.st_ino), done, shared_folder, store_root, home, stream, output, text,
                      labels)
    finally:
        os.close(held)  # Held through every copy, so a folder deleted and made again never matches (Fable medium).


def _offer(candidates, confirmed, done, shared_folder, store_root, home, stream, output, text, labels):
    from preparation_store import PrivateStore
    for view in candidates:
        install_id = view["install_id"]
        if labels and labels.get(install_id):
            print("ゲーム: " + text(labels[install_id]), file=output)
        print("導入のログ（導入のときの標準エラー全体、" + str(view.get("bytes", 0)) + "バイト）を、次のフォルダーに " +
              "installer-" + install_id + ".log として写せます: " + text(str(shared_folder)), file=output)
        print("端末のパス・ゲームのフォルダー名を含みます。共有のフォルダーに置いたものは、保存・複製された分を回収できません。",
              file=output)
        print("写す場合は1、写さない場合はq: ", end="", file=output, flush=True)
        if stream.readline(32).strip() != "1":
            done.append({"install_id": install_id, "copied": False, "reason": "declined"})
            continue
        try:
            with PrivateStore(store_root) as store, store.locked(COPY_LOCK):
                name, reason = copy_to_shared(store, install_id, view["app_id"], home, shared_folder, confirmed)
        except (OSError, Invalid, ValueError) as error:
            name, reason = None, "not-copied:" + type(error).__name__
        print(("写しました: " + name) if name else ("写せませんでした（" + str(reason) + "）"), file=output)
        done.append({"install_id": install_id, "copied": name is not None, "name": name, "reason": reason})
    return done


def logs_of(store_root, app_id):
    """The installer log records of one registration (read-only, for the status check)."""
    from preparation_store import PrivateStore
    found = []
    if not os.path.lexists(store_root):
        return found
    try:
        with PrivateStore(store_root) as store:
            try:
                with store.directory((RECORDS,)) as fd:
                    names = sorted(store._names(fd))
            except FileNotFoundError:
                return found
            for name in names:
                if name.startswith("tmp-"):
                    continue
                try:
                    record, _ = store.read_record(RECORDS, name)
                    validate_record(record)
                except (OSError, Invalid, TypeError, ValueError, KeyError):
                    continue
                if record["app_id"] == app_id:
                    found.append(record)
    except (OSError, Invalid, ValueError):
        return found
    return found


def rewrite_result(path, copies):
    """Add the copies made to a saved result, keeping everything it holds (atomic; a failure leaves it as it was)."""
    try:
        path = Path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            saved = json.loads(stream.read(2 * 1024 * 1024))
        require(type(saved) is dict, "saved result is not an object")
        saved["installer_log_copies"] = copies
        # The same form as the saved result (preparation_selection.save_selection_report).
        raw = (json.dumps(saved, ensure_ascii=True, indent=2) + "\n").encode()
        temporary = path.parent / ("." + path.name + "." + secrets.token_hex(8) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)  # Only the tool's own temporary file (gone after a successful replace).
            except FileNotFoundError:
                pass
        return True
    except (OSError, ValueError, TypeError, Invalid):
        return False
