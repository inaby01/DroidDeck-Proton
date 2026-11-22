"""Linux no-replacement publication shared by the writer and capability probe."""

import ctypes
import os
import sys

from preparation_common import require


def _rename_function():
    require(sys.platform == "linux", "non-replacing publication requires Linux renameat2")
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    require(rename is not None, "libc renameat2 unavailable")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    return rename


def _publish(rename, source_fd, destination_fd, name):
    # Linux RENAME_NOREPLACE=1. Never fall back to rename/replace on unsupported
    # kernels/filesystems: those can replace an existing empty directory.
    if rename(source_fd, b"tree", destination_fd, os.fsencode(name), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "non-replacing tool publication refused")


def rename_noreplace(rename, source_fd, source_name, destination_fd, destination_name):
    """One non-replacing rename between two directory FDs (Linux RENAME_NOREPLACE).

    Raises OSError (EEXIST, EXDEV, ...) without any fallback; the caller decides what a
    refused move means.
    """
    if rename(source_fd, os.fsencode(source_name), destination_fd, os.fsencode(destination_name), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "non-replacing rename refused")

