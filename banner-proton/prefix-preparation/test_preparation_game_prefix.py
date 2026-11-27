#!/usr/bin/env python3
"""Registered-game new prefix: native surrogate only, never Wine, vendor binaries or real games."""

import copy
import hashlib
import json
import os
import runpy
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
DEP = runpy.run_path(str(HERE / 'test_preparation_dependency_install.py'))
import preparation_dependency_install as dep
import preparation_game_prefix as game
import preparation_prefix_dll as prefix_dll
import preparation_trial as trial
from preparation_common import Invalid
from preparation_processes import ProcessStopCheck
from preparation_store import PrivateStore

PROFILE = {'profile_id': 'example-game', 'revision': 1, 'title': 'Synthetic game profile', 'edition': 'unconfirmed edition',
           'edition_status': 'unconfirmed', 'dependencies': ['softdenchi-runtime', 'mfc42-candidate'], 'exe_sha256': None}
RECIPES = [{'dependency_id': 'softdenchi-runtime', 'revision': 1, 'handler': 'softdenchi-interactive', 'status': 'ready',
            'reason': 'synthetic recipe'},
           {'dependency_id': 'mfc42-candidate', 'revision': 1, 'handler': 'mfc-local', 'status': 'blocked',
            'reason': 'terms and layout unresolved'}]


def synthetic_pe(machine=0x14C, extra=b''):
    """Smallest header the asset reader accepts; never executed."""
    data = bytearray(0x200)
    data[0:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x84, machine)
    struct.pack_into('<H', data, 0x94, 0xE0 if machine == 0x14C else 0xF0)
    struct.pack_into('<H', data, 0x98, 0x10B if machine == 0x14C else 0x20B)
    return bytes(data) + extra


DLL = synthetic_pe(extra=b'synthetic runtime library')
EXE_HASH = 'a' * 64


def folder_recipe(exe_hash=EXE_HASH, data=DLL, status='ready', name='mfc42.dll'):
    return {'dependency_id': 'mfc42-game-folder', 'revision': 1, 'handler': 'game-folder-file', 'status': status,
            'reason': 'synthetic game-folder check',
            'file': {'name': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'pe_machine': 'x86'},
            'required_by': {'exe_sha256': exe_hash, 'import': 'MFC42.DLL'}}


class ConfigTests(unittest.TestCase):
    def test_game_folder_recipe_is_ready_only_with_a_pinned_profile_exe(self):
        profile = {**PROFILE, 'dependencies': ['softdenchi-runtime', 'mfc42-game-folder'], 'exe_sha256': EXE_HASH}
        _profiles, recipes = game.validate_game_config({'profiles': [profile], 'recipes': RECIPES + [folder_recipe()]})
        self.assertEqual(recipes['mfc42-game-folder']['status'], 'ready')
        broken_recipes = (
            {k: v for k, v in folder_recipe().items() if k != 'file'},
            {**folder_recipe(), 'file': {**folder_recipe()['file'], 'name': '../mfc42.dll'}},
            {**folder_recipe(), 'file': {**folder_recipe()['file'], 'name': 'mfc42.exe'}},
            {**folder_recipe(), 'file': {**folder_recipe()['file'], 'pe_machine': 'arm64'}},
            {**folder_recipe(), 'file': {**folder_recipe()['file'], 'sha256': 'x'}},
            {**folder_recipe(), 'required_by': {'exe_sha256': EXE_HASH}},
            {**RECIPES[1], 'file': folder_recipe()['file']},
            {**folder_recipe(), 'required_by': {'exe_sha256': EXE_HASH, 'import': 'OTHER.DLL'}})
        for recipe in broken_recipes:
            with self.subTest(recipe=recipe), self.assertRaises(Invalid):
                game.validate_game_config({'profiles': [profile], 'recipes': RECIPES + [recipe]})
        for entry in ('not-an-object', ['list'], None, 7):
            with self.subTest(entry=entry), self.assertRaises(Invalid):
                game.validate_game_config({'profiles': [profile], 'recipes': RECIPES + [entry]})
        for changed in ({**profile, 'exe_sha256': None}, {**profile, 'exe_sha256': 'b' * 64}):
            with self.subTest(profile=changed), self.assertRaisesRegex(Invalid, 'game-folder dependency requires'):
                game.validate_game_config({'profiles': [changed], 'recipes': RECIPES + [folder_recipe()]})

    def test_game_folder_file_is_only_read_and_matched_exactly(self):
        spec = folder_recipe()['file']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            folder = root / 'Game'
            folder.mkdir()
            exe = folder / 'Game.exe'
            exe.write_bytes(synthetic_pe())
            self.assertEqual(game.inspect_game_folder_file(exe, spec)['state'], 'absent')
            (folder / 'MFC42.DLL').write_bytes(DLL)
            before = sorted((p.name, p.stat().st_mtime_ns) for p in folder.iterdir())
            self.assertEqual(game.inspect_game_folder_file(exe, spec), {'state': 'present-verified'})
            self.assertEqual(before, sorted((p.name, p.stat().st_mtime_ns) for p in folder.iterdir()))
            (folder / 'MFC42.DLL').write_bytes(DLL + b'changed')
            self.assertEqual(game.inspect_game_folder_file(exe, spec)['state'], 'incompatible')
            (folder / 'MFC42.DLL').write_bytes(synthetic_pe(0x8664))
            self.assertEqual(game.inspect_game_folder_file(exe, {**spec, 'size': len(synthetic_pe(0x8664))})['state'],
                             'incompatible')
            # Declared x64 and present as x64, but the game executable is x86.
            x64 = synthetic_pe(0x8664)
            declared = {**spec, 'size': len(x64), 'sha256': hashlib.sha256(x64).hexdigest(), 'pe_machine': 'x86_64'}
            self.assertEqual(game.inspect_game_folder_file(exe, declared),
                             {'state': 'incompatible', 'reason': 'architecture differs from the game executable'})
            # Only ASCII names match: the Kelvin sign is not the letter k.
            (folder / '\u212a.dll').write_bytes(DLL)
            self.assertEqual(game.inspect_game_folder_file(exe, {**spec, 'name': 'k.dll'})['state'], 'absent')
            (folder / '\u212a.dll').unlink()
            (folder / 'MFC42.DLL').unlink()
            (root / 'elsewhere.dll').write_bytes(DLL)
            (folder / 'mfc42.dll').symlink_to(root / 'elsewhere.dll')
            self.assertEqual(game.inspect_game_folder_file(exe, spec)['state'], 'incompatible')
            (folder / 'mfc42.dll').unlink()
            os.link(root / 'elsewhere.dll', folder / 'mfc42.dll')
            self.assertEqual(game.inspect_game_folder_file(exe, spec)['state'], 'incompatible')
            (folder / 'mfc42.dll').unlink()
            (folder / 'mfc42.dll').write_bytes(DLL)
            (folder / 'MFC42.dll').write_bytes(DLL)
            if len({p.name for p in folder.iterdir()}) == 3:  # case-sensitive filesystem
                self.assertEqual(game.inspect_game_folder_file(exe, spec)['state'], 'incompatible')

    def test_non_ascii_executable_paths_are_flagged(self):
        self.assertTrue(game.exe_path_ascii('/root/Games/Example Game/Game.exe'))
        self.assertFalse(game.exe_path_ascii('/root/Games/Example Game - \u30b3\u30d4\u30fc (2)/Game.exe'))


    def test_game_config_rejects_unsafe_declarations(self):
        profiles, _recipes = game.validate_game_config({'profiles': [PROFILE], 'recipes': RECIPES})
        self.assertEqual(list(profiles), ['example-game'])
        for change in ({'recipes': [dict(RECIPES[0]), {**RECIPES[1], 'status': 'ready'}]},
                       {'profiles': [{**PROFILE, 'dependencies': ['unknown-dependency']}]},
                       {'profiles': [{**PROFILE, 'exe_sha256': 'x'}]},
                       {'profiles': [PROFILE, PROFILE]}):
            value = {'profiles': [PROFILE], 'recipes': RECIPES, **change}
            with self.subTest(change=change), self.assertRaises(Invalid):
                game.validate_game_config(value)


    def test_profile_without_dependencies_and_the_default_profile(self):
        bare = {**PROFILE, 'profile_id': 'no-dependencies', 'dependencies': []}
        profiles, _recipes = game.validate_game_config({'profiles': [PROFILE, bare], 'recipes': RECIPES})
        self.assertEqual(profiles['no-dependencies']['dependencies'], [])
        value = {'profiles': [PROFILE, bare], 'recipes': RECIPES}
        # Two profiles without an EXE hash: none is automatic unless the bundle names one.
        self.assertEqual(game.automatic_profiles(value), ['example-game', 'no-dependencies'])
        value['default_profile'] = 'example-game'
        game.validate_game_config(value)
        self.assertEqual(game.automatic_profiles(value), ['example-game'])
        pinned = {**PROFILE, 'profile_id': 'pinned', 'exe_sha256': EXE_HASH}
        for wrong in ('unknown', 'pinned', None, 1):
            with self.subTest(default=wrong), self.assertRaises(Invalid):
                game.validate_game_config({'profiles': [PROFILE, bare, pinned], 'recipes': RECIPES, 'default_profile': wrong})
        with self.assertRaises(Invalid):
            game.validate_game_config({'profiles': [PROFILE], 'recipes': RECIPES, 'other': 1})


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux filesystem/native fixture; not device Wine')
class GamePrefixTests(DEP['InstallTests']):
    def setUp(self):
        super().setUp()
        # The fixture Proton links only cmd.exe into syswow64; use it as the x86 layout reference
        # (SoftDenchi checks the layout before running Wine in a game prefix since 0.31.0).
        reference = patch.object(prefix_dll, 'REFERENCE', 'cmd.exe')
        reference.start()
        self.addCleanup(reference.stop)
        self.config['game_preparation'] = {'profiles': [copy.deepcopy(PROFILE)], 'recipes': copy.deepcopy(RECIPES)}
        self.game_key = '42'
        self.game_compat = self.f.steam / 'steamapps/compatdata/42'

    def game_plan(self, key='42', profile_id='example-game'):
        source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        return game.plan_game_prefix(config=self.config, directory=self.f.fixture.source.root,
            renderer=self.f.fixture.options['renderer'], source=source, games=games, key=key, profile_id=profile_id,
            steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment, runtime_root=self.f.root)

    def initialize(self):
        plan = self.game_plan()
        lock = __import__('hashlib').sha256(str(plan.compatdata).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock), \
                patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            session = game.GamePrefixSession(plan, store, self.game_plan, plan.digest,
                                             ProcessStopCheck(plan.compatdata, self.f.proc)).start()
            result = session.wait(10)
            record, digest = store.read_record(game.RECORDS, result['trial_id'] + '.json')
        return record, digest

    def test_plan_is_read_only_binds_profile_and_refuses_probe_or_existing_prefix(self):
        before = self.protected()
        with patch('subprocess.Popen', side_effect=AssertionError('plan never executes')):
            plan = self.game_plan()
        summary = plan.summary()
        self.assertEqual(summary['scope'], game.SCOPE)
        self.assertEqual(summary['profile_selection'], 'operator-selected-unverified')
        self.assertEqual([item['status'] for item in summary['dependencies']], ['ready', 'blocked'])
        self.assertFalse(summary['binding_written'])
        self.assertEqual(before, self.protected())
        self.assertFalse(self.game_compat.exists())
        with self.assertRaisesRegex(Invalid, 'probe registrations'):
            self.game_plan(key='43')
        self.game_compat.mkdir()
        with self.assertRaisesRegex(Invalid, 'existing prefix is read-only'):
            self.game_plan()
        self.game_compat.rmdir()

    def test_profile_hash_must_match_when_declared(self):
        self.config['game_preparation']['profiles'][0]['exe_sha256'] = '0' * 64
        with self.assertRaisesRegex(Invalid, 'game executable differs'):
            self.game_plan()

    def test_nonempty_fex_appconfig_is_refused_by_the_reuse_plan(self):
        appconfig = next((self.f.steam / 'compatibilitytools.d').glob('*/files/share/fex-emu/AppConfig'))
        (appconfig / 'override.json').write_text('{"DUMMY_SECRET": true}')
        with self.assertRaises(Invalid):
            self.game_plan()
        (appconfig / 'override.json').unlink()
        self.game_plan()

    def test_menu_initializes_the_new_game_prefix_and_lists_it(self):
        with patch('subprocess.Popen', side_effect=AssertionError('cancel never executes')):
            status, report, _ = self.detail_menu('10\nq\n')
        self.assertEqual((status, report), (0, None))
        # An unknown profile name is refused before anything is written.
        with patch('subprocess.Popen', side_effect=AssertionError('refused input never executes')):
            status, report, _ = self.detail_menu('10\n1\nunknown-game\n')
        self.assertEqual(report['reason'], 'invalid profile selection')
        self.assertEqual(report['writes'], [{'scope': 'report-only', 'filename': report['writes'][0]['filename']}])
        with patch('subprocess.Popen', side_effect=AssertionError('cancel never executes')):
            status, report, output = self.detail_menu('10\n1\n1\nq\n')
        self.assertEqual((status, report), (0, None))
        self.assertIn('作品プロファイル: ', output)
        # The profile may be given by its number or, as operators type it from the list, by its name.
        with patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            status, report, output = self.detail_menu('10\n1\nexample-game\n1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual(report['initialization']['status'], 'initialized-unverified')
        self.assertEqual(report['initialization']['scope'], game.SCOPE)
        self.assertTrue(report['initialization']['trial_id'].startswith(game.ID_PREFIX))
        self.assertEqual(report['initialization']['profile']['profile_id'], 'example-game')
        self.assertFalse(report['binding_written'])
        with PrivateStore(self.f.store_root) as store:
            listed = store.inventory()['game_prefixes']
        self.assertEqual([(item['app_id'], item['profile_id']) for item in listed], [('42', 'example-game')])
        # The initialized registration is no longer offered: existing prefixes stay read-only.
        status, report, _ = self.detail_menu('10\n')
        self.assertEqual(report['reason'], 'no registered game without a prefix')

    def test_dependency_installation_accepts_the_initialized_game_prefix(self):
        record, digest = self.initialize()
        self.assertEqual(record['status'], 'initialized-unverified')
        result = self.install_dependency(record, digest)
        self.assertEqual(result['status'], 'present-verified', result)
        self.assertEqual(result['app_id'], '42')
        self.assertFalse(result['preparation_complete'])

    def binding_plan(self, record, digest):
        source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        return game.plan_game_binding(record=record, record_sha256=digest, config=self.config,
            directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source, games=games,
            steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
            runtime_root=self.f.root, stop_check=ProcessStopCheck(self.game_compat, self.f.proc), recipe=self.recipe)

    def test_binding_is_refused_while_a_dependency_is_blocked_or_missing(self):
        record, digest = self.initialize()
        before = self.protected()
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ('dependency-blocked:mfc42-candidate', 'dependency-not-verified:softdenchi-runtime'))
        self.install_dependency(record, digest)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ('dependency-blocked:mfc42-candidate',))
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock), self.assertRaisesRegex(Invalid, 'game binding blocked'):
            game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest,
                                    ProcessStopCheck(self.game_compat, self.f.proc), self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(before, self.protected())

    def test_binding_with_every_dependency_verified_writes_only_this_game(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime']
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ())
        games_before = json.loads(self.games_config.read_text())
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock):
            with self.assertRaises(Invalid):
                game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), '0' * 64,
                                        ProcessStopCheck(self.game_compat, self.f.proc), self.recipe, on_binding_id=lambda run_id: None)
            result = game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest,
                                             ProcessStopCheck(self.game_compat, self.f.proc), self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(result['status'], 'binding-verified')
        games_after = json.loads(self.games_config.read_text())
        self.assertEqual(games_after['games']['42'], {'valve': False, 'dir': plan.base.customization.directory})
        self.assertEqual({k: v for k, v in games_after['games'].items() if k != '42'},
                         {k: v for k, v in games_before['games'].items() if k != '42'})
        self.assertFalse(result['preparation_complete'])

    def test_profile_change_after_initialization_refuses_binding(self):
        record, digest = self.initialize()
        self.config['game_preparation']['profiles'][0]['revision'] = 2
        with self.assertRaisesRegex(Invalid, 'game profile changed'):
            self.binding_plan(record, digest)

    def exe_hash(self):
        return hashlib.sha256(self.f.exe.read_bytes()).hexdigest()

    def use_folder_dependency(self, revision=1):
        profile = self.config['game_preparation']['profiles'][0]
        profile.update(revision=revision, exe_sha256=self.exe_hash(), dependencies=['softdenchi-runtime', 'mfc42-game-folder'])
        self.config['game_preparation']['recipes'].append(folder_recipe(self.exe_hash()))

    def test_game_folder_dependency_gates_binding_and_is_rechecked_before_writing(self):
        self.use_folder_dependency()
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        dll = self.f.exe.parent / 'mfc42.dll'
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ('dependency-not-verified:mfc42-game-folder',))
        self.assertEqual(plan.dependencies[1]['state'], 'absent')
        dll.write_bytes(DLL)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ())
        self.assertIsNone(plan.summary()['profile_revision_change'])
        self.assertIsNone(plan.summary()['tool_runtime_writes'])
        before = self.protected()
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        # Changed after planning: the plan digest no longer matches, nothing is written.
        dll.write_bytes(DLL + b'changed')
        with PrivateStore(self.f.store_root) as store, store.locked(lock), self.assertRaises(Invalid):
            game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest,
                                    ProcessStopCheck(self.game_compat, self.f.proc), self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(before, self.protected())
        dll.write_bytes(DLL)
        with PrivateStore(self.f.store_root) as store, store.locked(lock):
            result = game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest,
                                             ProcessStopCheck(self.game_compat, self.f.proc), self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(result['status'], 'binding-verified')
        self.assertEqual(dll.read_bytes(), DLL)
        dll.unlink()

    def test_recipe_content_is_part_of_the_binding_plan_and_result(self):
        self.use_folder_dependency()
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        dll = self.f.exe.parent / 'mfc42.dll'
        dll.write_bytes(DLL)
        first = self.binding_plan(record, digest)
        state = first.summary()['dependencies'][1]
        self.assertEqual(state['declared_file'], folder_recipe(self.exe_hash())['file'])
        self.assertEqual((state['recipe_revision'], state['state']), (1, 'present-verified'))
        # Same dependency ID and revision, another declared file (and that file in place): still ready,
        # but the plan digest and the recorded declaration change.
        other = synthetic_pe(extra=b'another synthetic runtime library')
        dll.write_bytes(other)
        self.config['game_preparation']['recipes'][-1] = folder_recipe(self.exe_hash(), other)
        second = self.binding_plan(record, digest)
        self.assertEqual(second.blockers, ())
        self.assertNotEqual(first.digest, second.digest)
        self.assertNotEqual(second.summary()['dependencies'][1]['recipe_digest'], state['recipe_digest'])
        self.assertEqual(second.summary()['dependencies'][1]['declared_file']['sha256'], hashlib.sha256(other).hexdigest())
        dll.unlink()

    def test_folder_file_is_rechecked_by_the_readiness_callback_and_needs_a_clear_view(self):
        self.use_folder_dependency()
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        dll = self.f.exe.parent / 'mfc42.dll'
        dll.write_bytes(DLL)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ())
        before = self.protected()
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        dll.write_bytes(DLL + b'changed after the refresh')
        # refresh() still returns the original plan, so only ready() can see the change.
        with PrivateStore(self.f.store_root) as store, store.locked(lock), \
                self.assertRaisesRegex(Invalid, 'dependency postconditions changed'):
            game.apply_game_binding(plan, store, lambda: plan, plan.digest, ProcessStopCheck(self.game_compat, self.f.proc),
                                    self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(before, self.protected())

        class Busy:
            def check(self):
                return {'clear_in_view': False}
        states = game._dependency_states(plan.profile, plan.recipes, self.game_compat, self.recipe, Busy(), self.f.exe)
        self.assertEqual([item['state'] for item in states], ['uninspected', 'uninspected'])
        dll.unlink()

    def tool_pyc(self, body=b'synthetic bytecode, never executed'):
        """A CPython cache for the generated user_settings.py overlay of the preparation slot."""
        tool = next(p for p in (self.f.steam / 'compatibilitytools.d').iterdir() if (p / 'user_settings.py').exists())
        source = tool / 'user_settings.py'
        info = source.stat()
        cache = tool / '__pycache__'
        cache.mkdir(mode=0o755, exist_ok=True)
        import importlib.util
        pyc = cache / ('user_settings.' + sys.implementation.cache_tag + '.pyc')
        pyc.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(info.st_mtime), info.st_size) + body)
        pyc.chmod(0o644)
        return tool, pyc

    def test_tool_runtime_writes_are_planned_reported_and_rechecked(self):
        appconfig = next((self.f.steam / 'compatibilitytools.d').glob('*/files/share/fex-emu'))
        before_digest = self.game_plan().digest
        tool, pyc = self.tool_pyc()
        if not (tool / 'files/share/fex-emu/AppConfig').exists():
            (appconfig / 'AppConfig').mkdir(mode=0o700)
        preview = self.game_plan()
        self.assertNotEqual(preview.digest, before_digest)
        self.assertEqual(sorted(preview.summary()['tool_runtime_writes']['python_caches']['directories']), ['__pycache__'])
        self.use_folder_dependency()
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        (self.f.exe.parent / 'mfc42.dll').write_bytes(DLL)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ())
        self.assertIsNotNone(plan.summary()['tool_runtime_writes']['python_caches'])
        # A cache rewritten with the same header after planning: refused before any write.
        pyc.write_bytes(pyc.read_bytes()[:16] + b'rewritten bytecode')
        before = self.protected()
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock), \
                self.assertRaisesRegex(Invalid, 'tool runtime writes changed'):
            game.apply_game_binding(plan, store, lambda: plan, plan.digest, ProcessStopCheck(self.game_compat, self.f.proc),
                                    self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(before, self.protected())
        self.assertNotEqual(self.binding_plan(record, digest).digest, plan.digest)
        (self.f.exe.parent / 'mfc42.dll').unlink()

    def test_initialization_guard_refuses_runtime_writes_changed_after_planning(self):
        tool, pyc = self.tool_pyc()
        appconfig = tool / 'files/share/fex-emu/AppConfig'
        if not appconfig.exists():
            appconfig.mkdir(mode=0o700)
        plan = self.game_plan()
        lock = __import__('hashlib').sha256(str(plan.compatdata).encode()).hexdigest()
        with PrivateStore(self.f.store_root, create=True) as store, store.locked(lock):
            session = game.GamePrefixSession(plan, store, self.game_plan, plan.digest,
                                             ProcessStopCheck(plan.compatdata, self.f.proc))
            session._guard()
            pyc.write_bytes(pyc.read_bytes()[:16] + b'rewritten after planning')
            with self.assertRaisesRegex(Invalid, 'tool runtime writes changed'):
                session._guard()
        self.assertFalse(self.game_compat.exists())

    def test_later_profile_revision_with_the_initialized_exe_is_accepted(self):
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        (self.f.exe.parent / 'mfc42.dll').write_bytes(DLL)
        self.use_folder_dependency(revision=2)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ())
        change = plan.summary()['profile_revision_change']
        self.assertEqual((change['initialized_revision'], change['current_revision']), (1, 2))
        self.assertEqual(change['initialized_digest'], record['profile']['profile_digest'])
        profile = self.config['game_preparation']['profiles'][0]
        for changed in ({'revision': 1}, {'exe_sha256': 'b' * 64}):
            with self.subTest(changed=changed):
                saved = dict(profile)
                profile.update(changed)
                if 'exe_sha256' in changed:
                    self.config['game_preparation']['recipes'][-1]['required_by']['exe_sha256'] = changed['exe_sha256']
                with self.assertRaisesRegex(Invalid, 'game profile changed'):
                    self.binding_plan(record, digest)
                profile.clear()
                profile.update(saved)
                self.config['game_preparation']['recipes'][-1]['required_by']['exe_sha256'] = self.exe_hash()
        (self.f.exe.parent / 'mfc42.dll').unlink()

    def install_dependency(self, record, digest):
        source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)

        def plan():
            return dep.plan_dependency_install(record=record, record_sha256=digest, config=self.config,
                directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source,
                games=games, steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
                runtime_root=self.f.root, recipe=self.recipe)
        install = plan()
        self.assertEqual(install.blockers, ())
        self.assertEqual(install.recheck.records, game.RECORDS)
        self.assertEqual(install.recheck_id, record['trial_id'])
        lock = __import__('hashlib').sha256(str(install.recheck.compatdata).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock), \
                patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
            session = dep.DependencyInstallSession(install, store, plan, install.digest,
                                                   ProcessStopCheck(install.recheck.compatdata, self.f.proc))
            session.start_gui_check()
            session.wait_gui_check(10)
            session.confirm_display(True)
            session.start_installer()
            result = session.wait_installer(10)
            self.assertEqual(store.read_record(game.RECORDS, record['trial_id'] + '.json')[1], digest)
        return result

    def test_game_executable_change_after_initialization_refuses_dependency_planning(self):
        record, digest = self.initialize()
        self.f.exe.write_bytes(self.f.exe.read_bytes() + b'changed')
        source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        with self.assertRaises(Invalid) as caught:
            dep.plan_dependency_install(record=record, record_sha256=digest, config=self.config,
                directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source,
                games=games, steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
                runtime_root=self.f.root, recipe=self.recipe)
        self.assertIn(caught.exception.preparation_check, ('recheck-registration-pin', 'recheck-game-executable'))

    def plan_install(self, record, digest):
        source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        return dep.plan_dependency_install(record=record, record_sha256=digest, config=self.config,
            directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source,
            games=games, steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
            runtime_root=self.f.root, recipe=self.recipe)

    def test_record_binds_the_created_prefix_directory_and_registration(self):
        record, _ = self.initialize()
        self.assertEqual(record['prefix_identity'], game.prefix_identity(self.game_compat))
        self.assertEqual(record['wineprefix_identity'], game.wineprefix_identity(self.game_compat))
        self.assertEqual({name: record['profile'][name] for name in ('exe_path_sha256', 'title_sha256')},
                         game.registration_identity(self.f.exe, self.registration('42')['title']))
        for broken in ({k: v for k, v in record.items() if k != 'prefix_identity'},
                       {k: v for k, v in record.items() if k != 'wineprefix_identity'},
                       {**record, 'status': 'failed'},
                       {**record, 'prefix_identity': {'device': -1, 'inode': 1}},
                       {**record, 'profile': {k: v for k, v in record['profile'].items() if k != 'title_sha256'}}):
            with self.subTest(broken=sorted(broken)), self.assertRaises(Invalid):
                trial.validate_trial_record(broken, game.SCOPE, game.ID_PREFIX)
        with self.assertRaises(Invalid):
            trial.validate_trial_record({**record, 'scope': trial.SCOPE, 'trial_id': 'trial-' + record['trial_id'][8:]})

    def registration(self, key):
        _source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        return games[key]

    def test_replaced_or_changed_prefix_at_the_same_path_is_refused(self):
        record, digest = self.initialize()
        self.assertEqual(self.plan_install(record, digest).blockers, ())
        moved = self.home / 'moved-prefix'
        shutil.copytree(self.game_compat, moved, symlinks=True)
        self.game_compat.rename(self.home / 'original-prefix')
        moved.rename(self.game_compat)
        with self.assertRaisesRegex(Invalid, 'game prefix replaced') as caught:
            self.plan_install(record, digest)
        self.assertEqual(caught.exception.preparation_check, 'recheck-prefix')
        self.game_compat.rename(moved)
        (self.home / 'original-prefix').rename(self.game_compat)
        self.assertEqual(self.plan_install(record, digest).blockers, ())
        # The prefix root and version stay; only the WINEPREFIX inside is swapped for a copy.
        pfx = self.game_compat / 'pfx'
        shutil.copytree(pfx, self.home / 'pfx-copy', symlinks=True)
        pfx.rename(self.home / 'pfx-original')
        (self.home / 'pfx-copy').rename(pfx)
        with self.assertRaisesRegex(Invalid, 'game Wine prefix replaced') as caught:
            self.plan_install(record, digest)
        self.assertEqual(caught.exception.preparation_check, 'recheck-prefix')
        shutil.rmtree(pfx)
        (self.home / 'pfx-original').rename(pfx)
        self.assertEqual(self.plan_install(record, digest).blockers, ())
        version = self.game_compat / 'version'
        version.write_text(version.read_text() + 'other\n')
        with self.assertRaisesRegex(Invalid, 'game prefix version differs'):
            self.plan_install(record, digest)

    def test_registration_title_or_path_change_after_initialization_is_refused(self):
        record, digest = self.initialize()
        added = Path(self.environment['BL_ADDED_GAMES'])
        original = added.read_text()
        document = json.loads(original)
        entry = next(item for item in document if str(item.get('appid')) == '42')
        entry['name'] = 'Another synthetic title'
        added.write_text(json.dumps(document))
        with self.assertRaisesRegex(Invalid, 'registration path or title changed') as caught:
            self.plan_install(record, digest)
        self.assertEqual(caught.exception.preparation_check, 'recheck-game-registration')
        added.write_text(original)
        # Same EXE content in another folder: the measured hash matches, the registration does not.
        copy_root = self.f.exe.parent.parent / 'same-content-elsewhere'
        shutil.copytree(self.f.exe.parent, copy_root)
        entry = next(item for item in json.loads(original) if str(item.get('appid')) == '42')
        document = [item if str(item.get('appid')) != '42' else {**entry, 'exe': str(copy_root / self.f.exe.name)}
                    for item in json.loads(original)]
        added.write_text(json.dumps(document))
        with self.assertRaisesRegex(Invalid, 'registration path or title changed'):
            self.plan_install(record, digest)
        added.write_text(original)
        self.assertEqual(self.plan_install(record, digest).blockers, ())

    def test_binding_readiness_requires_a_clear_view_after_dependency_inspection(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime']
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ())
        before = self.protected()

        calls = []

        class AppearsDuringInspection(ProcessStopCheck):
            def check(self):
                calls.append(1)
                return {'clear_in_view': len(calls) == 1}
        stop = AppearsDuringInspection(self.game_compat, self.f.proc)
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock), \
                self.assertRaisesRegex(Invalid, 'dependency postconditions changed'):
            game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest, stop, self.recipe, on_binding_id=lambda run_id: None)
        self.assertEqual(len(calls), 2)
        self.assertEqual(before, self.protected())

    def test_binding_observes_the_planned_prefix(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = []
        record, digest = self.initialize()
        plan = self.binding_plan(record, digest)
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        for stop in (ProcessStopCheck(self.game_compat.parent / '43', self.f.proc), object()):
            with self.subTest(stop=stop), PrivateStore(self.f.store_root) as store, store.locked(lock), \
                    self.assertRaisesRegex(Invalid, 'matching process observation required'):
                game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest, stop,
                                        self.recipe, on_binding_id=lambda run_id: None)

    def test_profile_without_dependencies_binds_only_with_the_target_stopped(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = []
        record, digest = self.initialize()
        plan = self.binding_plan(record, digest)
        self.assertEqual((plan.dependencies, plan.blockers), ((), ()))
        with patch.object(ProcessStopCheck, 'check', return_value={'clear_in_view': False}):
            running = self.binding_plan(record, digest)
        self.assertEqual(running.blockers, (game.PROCESS_BLOCKER,))
        before = self.protected()

        calls = []

        class AppearsDuringInspection(ProcessStopCheck):
            def check(self):
                calls.append(1)
                return {'clear_in_view': len(calls) == 1}
        stop = AppearsDuringInspection(self.game_compat, self.f.proc)
        lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
        with PrivateStore(self.f.store_root) as store, store.locked(lock), \
                self.assertRaisesRegex(Invalid, 'target process view not clear'):
            game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest, stop, self.recipe,
                                    on_binding_id=lambda run_id: None)
        self.assertEqual(len(calls), 2)
        self.assertEqual(before, self.protected())
        with PrivateStore(self.f.store_root) as store, store.locked(lock):
            result = game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest,
                                             ProcessStopCheck(self.game_compat, self.f.proc), self.recipe,
                                             on_binding_id=lambda run_id: None)
        self.assertEqual(result['status'], 'binding-verified')

    def test_running_target_is_a_blocker_beside_the_dependencies(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime']
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        with patch.object(ProcessStopCheck, 'check', return_value={'clear_in_view': False}):
            plan = self.binding_plan(record, digest)
        self.assertEqual(plan.blockers, ('dependency-not-verified:softdenchi-runtime', game.PROCESS_BLOCKER))

    def test_dependency_menu_lists_game_prefixes_beside_probe_trials(self):
        self.initialize()
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch('subprocess.Popen', side_effect=AssertionError('listing only')):
            status, report, output = self.detail_menu('9\nq\n')
        self.assertEqual((status, report), (0, None))
        self.assertIn('実ゲーム example-game / ID 42', output)
        self.assertIn('検証用 / ID 43', output)


for _name in dir(DEP['InstallTests']):
    if _name.startswith('test_'):
        setattr(GamePrefixTests, _name, None)


if __name__ == '__main__':
    unittest.main()
