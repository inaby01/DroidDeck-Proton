#!/usr/bin/env python3
"""Asset-folder reads do not compare timestamps (bytes are hashed); every other read stays strict."""

import contextlib
import hashlib
import io
import os
import runpy
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# The trusted entry point inserts the distribution path, as under ``python3 -I`` in the container.
runpy.run_path(str(Path(__file__).with_name("prepare_game.py")))
import preparation_assets as assets
import preparation_common as common
import preparation_payload as payload
from preparation_common import Invalid


def synthetic_pe(machine=0x14C, extra=b''):
    data = bytearray(0x200)
    data[0:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x84, machine)
    struct.pack_into('<H', data, 0x94, 0xE0 if machine == 0x14C else 0xF0)
    struct.pack_into('<H', data, 0x98, 0x10B if machine == 0x14C else 0x20B)
    return bytes(data) + extra


class Touching:
    """A file object whose first read changes the file's timestamps (as shared storage was seen to do)."""

    def __init__(self, stream, path, grow=False):
        self.stream, self.path, self.grow, self.done = stream, path, grow, False

    def _touch(self):
        if not self.done:
            self.done = True
            if self.grow:
                with open(self.path, 'ab') as out:
                    out.write(b'grown')
            else:
                info = os.stat(self.path)
                os.utime(self.path, ns=(info.st_atime_ns + 10**9, info.st_mtime_ns + 10**9))

    def read(self, *args):
        data = self.stream.read(*args)
        self._touch()
        return data

    def readline(self, *args):
        data = self.stream.readline(*args)
        self._touch()
        return data

    def __iter__(self):
        return iter(self.readline, b'')

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()


def touching_open(path_holder, grow=False):
    real = common.regular_open

    def opened(path, limit):
        stream = real(path, limit)
        return Touching(stream, path, grow) if Path(path) == path_holder else stream
    return opened


# Every module that opens inputs through regular_open (each binds its own name).
OPENERS = ('preparation_common', 'preparation_assets', 'preparation_payload', 'preparation_tool_writer', 'preparation_store',
           'preparation_dependency_install', 'preparation_execution', 'preparation_dependency_state')


@contextlib.contextmanager
def touching_asset_folder(root):
    """Change the timestamps of every file of the asset folder on its first read through each open (shared storage)."""
    import preparation_common
    root, real, touched = Path(root).resolve(), preparation_common.regular_open, []

    def opened(path, limit):
        stream = real(path, limit)
        if Path(path).resolve().is_relative_to(root):
            touched.append(Path(path).name)
            return Touching(stream, path)
        return stream
    with contextlib.ExitStack() as stack:
        for name in OPENERS:
            if hasattr(sys.modules.get(name), 'regular_open'):
                stack.enter_context(patch.object(sys.modules[name], 'regular_open', opened))
        yield touched


class UnchangedTests(unittest.TestCase):
    def test_names_of_the_differing_fields_and_the_timestamp_switch(self):
        class Info:
            def __init__(self, **values):
                base = {'st_ino': 1, 'st_dev': 2, 'st_size': 3, 'st_mtime_ns': 4, 'st_ctime_ns': 5}
                base.update(values)
                self.__dict__.update(base)

        common.unchanged(Info(), Info())
        with self.assertRaisesRegex(Invalid, r'input changed during read \(mtime_ns,ctime_ns\)'):
            common.unchanged(Info(), Info(st_mtime_ns=9, st_ctime_ns=9))
        common.unchanged(Info(), Info(st_mtime_ns=9, st_ctime_ns=9), timestamps=False)
        with self.assertRaisesRegex(Invalid, r'\(size\)'):
            common.unchanged(Info(), Info(st_size=9), timestamps=False)


class MeasureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / 'runtime.dll'
        self.data = synthetic_pe(extra=os.urandom(3 * 1024 * 1024))
        self.path.write_bytes(self.data)

    def measure(self, timestamps, grow=False):
        with common.regular_open(self.path, 64 * 1024 * 1024) as stream:
            return assets.measure_stream(Touching(stream, self.path, grow), 64 * 1024 * 1024, 'pe', timestamps=timestamps)

    def test_loose_read_ignores_timestamps_and_hashes_the_bytes(self):
        measured = self.measure(timestamps=False)
        self.assertEqual(measured, {'sha256': hashlib.sha256(self.data).hexdigest(), 'size': len(self.data), 'pe_machine': 'x86'})
        with self.assertRaisesRegex(Invalid, 'input changed during read'):
            self.measure(timestamps=True)

    def test_loose_read_still_stops_on_a_size_change(self):
        with self.assertRaises(Invalid):
            self.measure(timestamps=False, grow=True)

    def test_loose_read_takes_the_pe_machine_from_the_hashed_bytes(self):
        self.path.write_bytes(synthetic_pe(0x8664, b'x' * 100))
        with common.regular_open(self.path, 1024 * 1024) as stream:
            self.assertEqual(assets.measure_stream(stream, 1024 * 1024, 'pe', timestamps=False)['pe_machine'], 'x86_64')
        self.path.write_bytes(b'not a PE')
        with common.regular_open(self.path, 1024 * 1024) as stream, self.assertRaises(Invalid):
            assets.measure_stream(stream, 1024 * 1024, 'pe', timestamps=False)

    def test_folder_entry_of_inspect_assets_is_loose_and_the_default_is_strict(self):
        spec = {'asset_id': 'runtime', 'revision': 1, 'version': '1', 'purpose': 'test', 'filename': 'runtime.dll',
                'format': 'pe', 'pe_machine': 'x86', 'expected_size': len(self.data),
                'expected_sha256': hashlib.sha256(self.data).hexdigest(), 'hash_kind': 'external-reference',
                'hash_reference': 'fixture', 'source_kind': 'official', 'source_reference': 'fixture',
                'acquired_on': '2026-11-21', 'provenance_status': 'operator-reviewed', 'terms_status': 'personal-use-reviewed'}
        document = {'schema_version': 1, 'assets': [spec]}
        with patch.object(assets, 'regular_open', side_effect=touching_open(self.path)):
            (report,) = assets.inspect_assets_from_folder(document, self.root)
        self.assertEqual(report['blockers'], [])
        with patch.object(assets, 'regular_open', side_effect=touching_open(self.path)), \
                self.assertRaisesRegex(Invalid, 'input changed during read'):
            assets.inspect_assets(document, self.root)


class StrictSideTests(unittest.TestCase):
    """Reads outside the asset folder keep comparing timestamps (design: operational entry 5.2)."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_game_exe_settings_and_prefix_registry_reads_stop_on_timestamps(self):
        import preparation_dependency_state as state
        exe = self.root / 'Game.exe'
        exe.write_bytes(synthetic_pe(extra=b'x' * 4096))
        with patch.object(assets, 'regular_open', side_effect=touching_open(exe)), \
                self.assertRaisesRegex(Invalid, r'input changed during read \(mtime_ns'):
            assets.exe_identity(exe)
        with common.regular_open(exe, 1 << 20) as stream, \
                self.assertRaisesRegex(Invalid, r'input changed during read \(mtime_ns'):
            assets.measure_stream(Touching(stream, exe), 1 << 20, 'pe')
        settings = self.root / 'games.json'
        settings.write_text('{"version": 1, "games": {}}')
        with patch.object(common, 'regular_open', side_effect=touching_open(settings)), \
                self.assertRaisesRegex(Invalid, r'input changed during read \(mtime_ns'):
            common.read_bytes(settings)
        registry = self.root / 'system.reg'
        registry.write_bytes(b'WINE REGISTRY Version 2\n;; All keys relative to \\\\Machine\n\n[Software\\\\Fixture] 1\n"Value"="1"\n')
        with patch.object(state, 'regular_open', side_effect=touching_open(registry)), \
                self.assertRaisesRegex(Invalid, r'input changed during read \(mtime_ns'):
            state.read_registry(registry, {'Software\\Fixture': {'Value'}})


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.archive = self.root / 'payload.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as package:
            member = tarfile.TarInfo('Tool')
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            package.addfile(member)
            raw = os.urandom(2 * 1024 * 1024)
            member = tarfile.TarInfo('Tool/proton')
            member.size, member.mode = len(raw), 0o755
            package.addfile(member, io.BytesIO(raw))
        self.sha512 = hashlib.sha512(self.archive.read_bytes()).hexdigest()

    def test_folder_entry_ignores_timestamps_and_the_default_is_strict(self):
        with patch.object(payload, 'regular_open', side_effect=touching_open(self.archive)):
            inventory = payload.inspect_archive_from_folder(self.archive, self.sha512, 'Tool')
        self.assertIn('proton', inventory.entries)
        with patch.object(payload, 'regular_open', side_effect=touching_open(self.archive)), \
                self.assertRaisesRegex(Invalid, 'input changed during read'):
            payload.inspect_archive(self.archive, self.sha512, 'Tool')

    def test_folder_entry_still_checks_the_whole_archive(self):
        with self.assertRaises(Invalid):
            payload.inspect_archive_from_folder(self.archive, '0' * 128, 'Tool')
        with patch.object(payload, 'regular_open', side_effect=touching_open(self.archive, grow=True)), \
                self.assertRaises(Invalid):
            payload.inspect_archive_from_folder(self.archive, self.sha512, 'Tool')


if __name__ == '__main__':
    unittest.main()
