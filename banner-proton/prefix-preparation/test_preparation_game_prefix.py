#!/usr/bin/env python3
"""Registered-game new prefix: native surrogate only, never Wine, vendor binaries or real games."""

import copy
import json
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
DEP = runpy.run_path(str(HERE / 'test_preparation_dependency_install.py'))
import preparation_dependency_install as dep
import preparation_game_prefix as game
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


class ConfigTests(unittest.TestCase):
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


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux filesystem/native fixture; not device Wine')
class GamePrefixTests(DEP['InstallTests']):
    def setUp(self):
        super().setUp()
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
            status, report, _ = self.menu('10\nq\n')
        self.assertEqual((status, report), (0, None))
        with patch.object(trial, 'plan_launch', side_effect=self.launch_fixture):
            status, report, output = self.menu('10\n1\n1\n1\n')
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
        status, report, _ = self.menu('10\n')
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
                                    ProcessStopCheck(self.game_compat, self.f.proc), self.recipe)
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
                                        ProcessStopCheck(self.game_compat, self.f.proc), self.recipe)
            result = game.apply_game_binding(plan, store, lambda: self.binding_plan(record, digest), plan.digest,
                                             ProcessStopCheck(self.game_compat, self.f.proc), self.recipe)
        self.assertEqual(result['status'], 'binding-verified')
        games_after = json.loads(self.games_config.read_text())
        self.assertEqual(games_after['games']['42'], {'valve': False, 'dir': plan.base.customization.directory})
        self.assertEqual({k: v for k, v in games_after['games'].items() if k != '42'},
                         {k: v for k, v in games_before['games'].items() if k != '42'})
        self.assertFalse(result['preparation_complete'])

    def test_binding_menu_reports_blockers_without_writing(self):
        self.initialize()
        before = self.protected()
        with patch('preparation_softdenchi_recipe.softdenchi_recipe', return_value=self.recipe):
            status, report, output = self.menu('11\n1\n')
        self.assertEqual(status, 2, output)
        self.assertFalse(report['binding_written'])
        self.assertIn('dependency-blocked:mfc42-candidate', report['plan']['blockers'])
        self.assertIn('全依存が検証済みになるまで割り当てません', output)
        self.assertEqual(before, self.protected())

    def test_profile_change_after_initialization_refuses_binding(self):
        record, digest = self.initialize()
        self.config['game_preparation']['profiles'][0]['revision'] = 2
        with self.assertRaisesRegex(Invalid, 'game profile changed'):
            self.binding_plan(record, digest)

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

    def test_dependency_menu_lists_game_prefixes_beside_probe_trials(self):
        self.initialize()
        with patch.object(dep, 'softdenchi_recipe', return_value=self.recipe), \
                patch('subprocess.Popen', side_effect=AssertionError('listing only')):
            status, report, output = self.menu('9\nq\n')
        self.assertEqual((status, report), (0, None))
        self.assertIn('実ゲーム example-game / ID 42', output)
        self.assertIn('検証用 / ID 43', output)


for _name in dir(DEP['InstallTests']):
    if _name.startswith('test_'):
        setattr(GamePrefixTests, _name, None)


if __name__ == '__main__':
    unittest.main()
