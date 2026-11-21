#!/usr/bin/env python3
"""Handler prefix-dll: declarations, read-only state and the resume table; never Wine or real DLLs."""

import copy
import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path

import preparation_game_prefix as game
import preparation_prefix_dll as dll
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


DATA = synthetic_pe(extra=b'synthetic prefix runtime library')


def asset(data=DATA, **changes):
    spec = {'asset_id': 'mfc42-fixture', 'revision': 1, 'version': '6.00.8665.0', 'purpose': 'synthetic-test',
            'filename': 'mfc42.dll', 'format': 'pe', 'pe_machine': 'x86', 'expected_size': len(data),
            'expected_sha256': hashlib.sha256(data).hexdigest(), 'hash_kind': 'external-reference',
            'hash_reference': 'synthetic fixture', 'source_kind': 'official', 'source_reference': 'synthetic fixture',
            'acquired_on': '2026-11-21', 'provenance_status': 'operator-reviewed', 'terms_status': 'personal-use-reviewed'}
    spec.update(changes)
    return spec


def recipe(data=DATA, status='ready', dependency_id='mfc42-prefix', **changes):
    return {'dependency_id': dependency_id, 'revision': 1, 'handler': 'prefix-dll', 'status': status,
            'reason': 'synthetic recipe', 'asset': asset(data, **changes), 'destination': 'syswow64'}


SOFTDENCHI = {'dependency_id': 'softdenchi-runtime', 'revision': 1, 'handler': 'softdenchi-interactive', 'status': 'ready',
              'reason': 'synthetic recipe'}
PROFILE = {'profile_id': 'common', 'revision': 1, 'title': 'Synthetic common profile', 'edition': 'unconfirmed edition',
           'edition_status': 'unconfirmed', 'dependencies': ['softdenchi-runtime', 'mfc42-prefix'], 'exe_sha256': None}


class Inventory:
    def __init__(self, entries):
        self.entries = entries


class DeclarationTests(unittest.TestCase):
    def test_ready_recipe_requires_a_reviewed_single_x86_dll(self):
        self.assertEqual(dll.validate_prefix_dll_recipe(recipe())['handler'], 'prefix-dll')
        profiles, recipes = game.validate_game_config({'profiles': [PROFILE], 'recipes': [SOFTDENCHI, recipe()]})
        self.assertEqual(recipes['mfc42-prefix']['status'], 'ready')
        self.assertIsNone(profiles['common']['exe_sha256'])
        broken = [recipe(filename=name) for name in ('subdir/mfc42.dll', 'subdir\\mfc42.dll', 'a:b.dll', 'mfc42\n.dll',
                                                      'mfc42.exe', '.mfc42.dll', 'mfc 42.dll', 'x' * 61 + '.dll')]
        broken += [recipe(pe_machine='x86_64'), recipe(format='opaque', pe_machine=None), recipe(terms_status='unconfirmed'),
                   recipe(provenance_status='unconfirmed'), recipe(expected_size=None), recipe(expected_sha256=None),
                   recipe(hash_kind='local-measurement'), {**recipe(), 'destination': 'system32'},
                   {**recipe(), 'handler': 'mfc-local'}, {k: v for k, v in recipe().items() if k != 'asset'},
                   recipe(expected_size=dll.LIMIT + 1)]
        for item in broken:
            with self.subTest(item=item), self.assertRaises(Invalid):
                game.validate_game_config({'profiles': [PROFILE], 'recipes': [SOFTDENCHI, item]})
        # A blocked declaration may still carry an unreviewed asset; it is never placed.
        game.validate_game_config({'profiles': [PROFILE], 'recipes': [SOFTDENCHI, recipe(status='blocked', terms_status='unconfirmed')]})

    def test_profile_refuses_two_dlls_with_the_same_destination_name(self):
        other = recipe(dependency_id='mfc42-other', filename='MFC42.DLL')
        profile = {**PROFILE, 'dependencies': ['softdenchi-runtime', 'mfc42-prefix', 'mfc42-other']}
        with self.assertRaisesRegex(Invalid, 'repeat'):
            game.validate_game_config({'profiles': [profile], 'recipes': [SOFTDENCHI, recipe(), other]})
        self.assertEqual(dll.target_name(other), 'mfc42.dll')


class StateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.dir = self.root / 'syswow64'
        self.dir.mkdir()
        self.fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.spec = asset()

    def state(self):
        return dll.state_of(dll.examine(self.fd, 'mfc42.dll'), self.spec)

    def test_destination_states_are_read_only_and_exact(self):
        self.assertEqual(self.state(), {'state': 'absent'})
        (self.dir / 'MFC42.DLL').write_bytes(DATA)
        before = sorted((p.name, p.stat().st_mtime_ns) for p in self.dir.iterdir())
        self.assertEqual(self.state(), {'state': 'present-verified'})
        self.assertEqual(before, sorted((p.name, p.stat().st_mtime_ns) for p in self.dir.iterdir()))
        (self.dir / 'MFC42.DLL').write_bytes(DATA + b'changed')
        self.assertEqual(self.state()['state'], 'incompatible')
        (self.dir / 'MFC42.DLL').write_bytes(b'not a PE')
        self.assertEqual(self.state()['state'], 'incompatible')
        (self.dir / 'MFC42.DLL').unlink()
        placeholder = bytearray(DATA)
        placeholder[0x40:0x40 + len(b'Wine placeholder DLL')] = b'Wine placeholder DLL'
        (self.dir / 'mfc42.dll').write_bytes(bytes(placeholder))
        self.assertEqual(self.state(), {'state': 'incompatible', 'reason': 'Wine builtin or placeholder file'})
        (self.dir / 'mfc42.dll').write_bytes(DATA)
        os.link(self.dir / 'mfc42.dll', self.root / 'second-name')
        self.assertEqual(self.state(), {'state': 'incompatible', 'reason': 'several links'})
        (self.root / 'second-name').unlink()
        (self.dir / 'mfc42.dll').unlink()
        (self.root / 'elsewhere.dll').write_bytes(DATA)
        (self.dir / 'mfc42.dll').symlink_to(self.root / 'elsewhere.dll')
        self.assertEqual(self.state(), {'state': 'incompatible', 'reason': 'symbolic link'})
        (self.dir / 'mfc42.dll').unlink()
        (self.dir / 'mfc42.dll').mkdir()
        self.assertEqual(self.state(), {'state': 'incompatible', 'reason': 'not a regular file'})
        (self.dir / 'mfc42.dll').rmdir()
        (self.dir / 'mfc42.dll').write_bytes(DATA)
        (self.dir / 'Mfc42.dll').write_bytes(DATA)
        if len(list(self.dir.iterdir())) == 2:  # case-sensitive filesystem
            self.assertEqual(self.state(), {'state': 'incompatible', 'reason': 'several files differ only in case'})

    def test_layout_accepts_only_the_payload_link_or_an_x86_file(self):
        tool = self.root / 'tool'
        member = 'files/lib/wine/i386-windows/kernel32.dll'
        (tool / 'files/lib/wine/i386-windows').mkdir(parents=True)
        (tool / member).write_bytes(synthetic_pe())
        inventory = Inventory({member: {'kind': 'file'}})
        (self.dir / 'kernel32.dll').symlink_to(tool / member)
        self.assertEqual(dll.check_layout(self.fd, self.dir, inventory, tool), 'payload-link')
        # Another spelling of the same tool path (as Proton may write it) is the same file.
        (self.dir / 'kernel32.dll').unlink()
        (self.dir / 'kernel32.dll').symlink_to(os.path.relpath(tool / member, self.dir))
        self.assertEqual(dll.check_layout(self.fd, self.dir, inventory, tool), 'payload-link')
        # A copy with the same content elsewhere is not the payload file.
        (self.dir / 'kernel32.dll').unlink()
        (self.root / 'copy.dll').write_bytes((tool / member).read_bytes())
        (self.dir / 'kernel32.dll').symlink_to(self.root / 'copy.dll')
        with self.assertRaisesRegex(Invalid, 'outside the selected Proton'):
            dll.check_layout(self.fd, self.dir, inventory, tool)
        (self.dir / 'kernel32.dll').unlink()
        (self.dir / 'kernel32.dll').symlink_to(tool / member)
        with self.assertRaisesRegex(Invalid, 'payload lacks'):
            dll.check_layout(self.fd, self.dir, Inventory({}), tool)
        (self.dir / 'kernel32.dll').unlink()
        (self.root / 'other.dll').write_bytes(synthetic_pe())
        (self.dir / 'kernel32.dll').symlink_to(self.root / 'other.dll')
        with self.assertRaisesRegex(Invalid, 'outside the selected Proton'):
            dll.check_layout(self.fd, self.dir, inventory, tool)
        (self.dir / 'kernel32.dll').unlink()
        (tool / member).write_bytes(synthetic_pe(0xAA64))
        (self.dir / 'kernel32.dll').symlink_to(tool / member)
        with self.assertRaisesRegex(Invalid, 'not x86'):
            dll.check_layout(self.fd, self.dir, inventory, tool)
        (self.dir / 'kernel32.dll').unlink()
        (self.dir / 'kernel32.dll').write_bytes(synthetic_pe())
        self.assertEqual(dll.check_layout(self.fd, self.dir, inventory, tool), 'regular-file')
        (self.dir / 'kernel32.dll').write_bytes(synthetic_pe(0x8664))
        with self.assertRaisesRegex(Invalid, 'not x86'):
            dll.check_layout(self.fd, self.dir, inventory, tool)
        (self.dir / 'kernel32.dll').unlink()
        with self.assertRaises(FileNotFoundError):
            dll.check_layout(self.fd, self.dir, inventory, tool)

    def test_builtin_names_cover_wine_libraries_and_prefix_templates(self):
        inventory = Inventory({'files/lib/wine/i386-windows/MSVCRT.dll': {'kind': 'file'},
                               'files/share/default_pfx_arm64/drive_c/windows/syswow64/ole32.dll': {'kind': 'hardlink'},
                               'files/share/fonts/arial.ttf': {'kind': 'file'},
                               'files/share/default_pfx/drive_c/windows/syswow64/OLEAUT32.DLL': {'kind': 'symlink'},
                               'files/lib/wine/i386-windows': {'kind': 'directory'}})
        self.assertEqual(dll.builtin_names(inventory), {'msvcrt.dll', 'ole32.dll', 'oleaut32.dll'})


def facts(kind='none', identity=None, links=1, data=DATA):
    if kind == 'none':
        return {'kind': 'none'}
    measured = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'pe_machine': 'x86'}
    return {'kind': 'file', 'name': 'mfc42.dll', 'identity': identity or {'device': 1, 'inode': 9}, 'links': links,
            'measured': measured, 'wine_marker': False}


def previous(phase, temporary_identity=None):
    return {'record_id': dll.ID_PREFIX + '0' * 32, 'phase': phase, 'directory': {'device': 1, 'inode': 2},
            'temporary': '.prefixdll-' + '0' * 32 + '.tmp', 'temporary_identity': temporary_identity}


DIR = {'device': 1, 'inode': 2}
TEMP = {'device': 1, 'inode': 7}


class ResumeTests(unittest.TestCase):

    def action(self, latest, current, temporary=None, invalid=0, directory=None):
        return dll.resume_action(latest, invalid, directory or DIR, current, asset(), temporary or {'kind': 'none'})

    def test_resume_rows(self):
        own1 = {'kind': 'own', 'identity': TEMP, 'links': 1}
        own2 = {'kind': 'own', 'identity': TEMP, 'links': 2}
        unknown = {'kind': 'unknown', 'identity': {'device': 1, 'inode': 8}, 'links': 1}
        cases = [
            ((None, facts()), 'install'),
            ((None, facts('file')), 'skip'),
            ((previous('present-verified', TEMP), facts('file')), 'skip'),
            ((previous('failed'), facts()), 'install'),
            ((previous('present-verified', TEMP), facts()), 'stop'),
            ((previous('failed'), facts('file')), 'stop'),
            ((previous('planned'), facts()), 'install'),
            ((previous('planned'), facts(), unknown), 'stop'),
            ((previous('temp-created', TEMP), facts(), own1), 'remove-temporary-then-install'),
            ((previous('temp-written', TEMP), facts(), own1), 'remove-temporary-then-install'),
            ((previous('temp-written', TEMP), facts(), unknown), 'stop'),
            ((previous('temp-created', TEMP), facts()), 'install'),
            ((previous('temp-written', TEMP), facts('file', TEMP, 2), own2), 'remove-temporary-then-recheck'),
            ((previous('temp-created', TEMP), facts('file', TEMP, 2), own2), 'stop'),
            ((previous('temp-written', TEMP), facts('file', {'device': 1, 'inode': 5}, 2), own2), 'stop'),
            ((previous('temp-written', TEMP), facts('file', TEMP, 2, DATA + b'x'), own2), 'stop'),
            ((previous('temp-written', TEMP), facts('file')), 'skip'),
            ((previous('linked', TEMP), facts('file')), 'skip'),
            ((previous('linked', TEMP), facts()), 'stop'),
            ((previous('temp-created', TEMP), facts('file')), 'stop'),
            ((None, facts(), unknown), 'stop'),
            ((None, facts('file', links=2)), 'stop'),
            ((previous('temp-written', TEMP), facts('file', TEMP, 1), own1), 'stop'),
            ((previous('linked', TEMP), facts(), own1), 'stop'),
            ((previous('failed', TEMP), facts(), own1), 'remove-temporary-then-install'),
            ((previous('failed', TEMP), facts(), unknown), 'stop'),
            ((previous('failed', TEMP), facts('file'), own1), 'stop'),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(self.action(*args)[0], expected)
        self.assertEqual(self.action(None, facts(), invalid=1), ('stop', 'invalid-prefix-dll-record-present'))
        self.assertEqual(self.action(previous('failed'), facts(), directory={'device': 1, 'inode': 3}),
                         ('stop', 'syswow64-replaced-since-previous-record'))


class TemporaryFactsTests(unittest.TestCase):
    def test_only_the_recorded_identity_is_own(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = '.prefixdll-' + '0' * 32 + '.tmp'
            (root / name).write_bytes(b'x')
            info = (root / name).stat()
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                mine = previous('temp-written', {'device': info.st_dev, 'inode': info.st_ino})
                self.assertEqual(dll._temporary_facts(fd, mine)['kind'], 'own')
                self.assertEqual(dll._temporary_facts(fd, previous('temp-written', {'device': info.st_dev, 'inode': 1}))['kind'],
                                 'unknown')
                self.assertEqual(dll._temporary_facts(fd, previous('planned'))['kind'], 'unknown')
                (root / name).unlink()
                (root / name).symlink_to(root / 'elsewhere')
                self.assertEqual(dll._temporary_facts(fd, mine)['kind'], 'unknown')
                (root / name).unlink()
                self.assertEqual(dll._temporary_facts(fd, mine), {'kind': 'none'})
            finally:
                os.close(fd)


class RecordTests(unittest.TestCase):
    def test_record_shape(self):
        token = 'a' * 32
        record = {'schema_version': 1, 'tool_version': '0.29.0', 'scope': dll.SCOPE, 'record_id': dll.ID_PREFIX + token,
                  'created_ns': 1, 'app_id': '42', 'trial_id': 'gprefix-x', 'dependency_id': 'mfc42-prefix',
                  'recipe_revision': 1, 'recipe_digest': 'b' * 64, 'asset_sha256': 'c' * 64, 'input_digest': 'd' * 64,
                  'destination': 'syswow64', 'name': 'mfc42.dll', 'directory': {'device': 1, 'inode': 2},
                  'temporary': '.prefixdll-' + token + '.tmp', 'temporary_identity': None, 'phase': 'planned',
                  'resumed_from': None, 'error': None, 'preparation_complete': False}
        dll.validate_prefix_dll_record(copy.deepcopy(record))
        for change in ({'phase': 'temp-created'}, {'name': 'MFC42.dll'}, {'temporary': '.other.tmp'},
                       {'preparation_complete': True}, {'destination': 'system32'}, {'phase': 'unknown'},
                       {'temporary_identity': {'device': 1}}):
            with self.subTest(change=change), self.assertRaises((Invalid, TypeError, KeyError)):
                dll.validate_prefix_dll_record({**copy.deepcopy(record), **change})
        dll.validate_prefix_dll_record({**record, 'phase': 'temp-created', 'temporary_identity': {'device': 1, 'inode': 3}})
        dll.validate_prefix_dll_record({**record, 'phase': 'failed'})


if __name__ == '__main__':
    unittest.main()
