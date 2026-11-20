#!/usr/bin/env python3
"""Menu 12 one-pass preparation with the native surrogate; never Wine, vendor binaries or real games."""

import hashlib
import json
import runpy
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
GAME = runpy.run_path(str(HERE / 'test_preparation_game_prefix.py'))
DEP = GAME['DEP']
import preparation_dependency_install as dep
import preparation_one_pass as one_pass
import preparation_softdenchi_recipe as recipe_module
import preparation_trial as trial
from preparation_common import Invalid
from preparation_store import PrivateStore


def record(status, phase='post-inspected'):
    return {'install_id': 'depinstall-' + '0' * 32, 'status': status, 'phase': phase}


class ActionTableTests(unittest.TestCase):
    """Design 5.1 step 3 and 5.2: history rows first, then the current state."""

    def test_softdenchi_rows(self):
        cases = [
            ((None, 0, 'absent'), 'install'),
            ((None, 0, 'present-verified'), 'skip'),
            ((None, 0, 'partial'), 'stop'),
            ((None, 1, 'absent'), 'stop'),
            ((record('cancelled-absent'), 0, 'absent'), 'install'),
            ((record('stopped-before-installer', 'gui-check-not-confirmed'), 0, 'absent'), 'install'),
            ((record('present-verified'), 0, 'present-verified'), 'skip'),
            ((record('present-verified'), 0, 'absent'), 'stop'),
            ((record('needs-user', 'installer-exited'), 0, 'present-verified'), 'skip'),
            ((record('needs-user', 'installer-exited'), 0, 'present-unverified'), 'stop'),
            ((record('running', 'stop-observed'), 0, 'uninspected'), 'stop'),
            ((record('failed', 'installer-staged'), 0, 'absent'), 'stop'),
            ((record('failed', 'installer-spawned'), 0, 'present-verified'), 'stop'),
            ((record('partial'), 0, 'partial'), 'stop'),
            ((record('installed-unverified'), 0, 'present-verified'), 'stop'),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(one_pass.softdenchi_action(*args)[0], expected)
        # Moving on from a record whose post-inspection never ran is noted as a separate read-only check.
        self.assertTrue(one_pass.softdenchi_action(record('needs-user', 'installer-exited'), 0, 'present-verified')[2])
        self.assertFalse(one_pass.softdenchi_action(record('present-verified'), 0, 'present-verified')[2])

    def test_binding_rows(self):
        class Plan:
            def __init__(self, same):
                self.before = {'games': b'a', 'config': b'b', 'state': b'c'}
                self.after = {name: value if name in same else value + b'!' for name, value in self.before.items()}
        everything = ('games', 'config', 'state')
        self.assertEqual(one_pass.binding_action(Plan(everything), [])[0], 'already-bound')
        self.assertEqual(one_pass.binding_action(Plan(everything), ['binding-failed'])[0], 'already-bound')
        self.assertEqual(one_pass.binding_action(Plan(('state',)), ['binding-failed']), ('stop', 'previous-binding-incomplete'))
        self.assertEqual(one_pass.binding_action(Plan(()), ['binding-verified']),
                         ('stop', 'binding-changed-after-verified-binding'))
        self.assertEqual(one_pass.binding_action(Plan(()), []), ('apply', None))

    def test_silent_arguments_are_pinned_to_the_recipe_bootstrap(self):
        real = recipe_module.softdenchi_recipe()
        self.assertEqual(recipe_module.silent_arguments(real), ['/s', '/v/qn', '/vREBOOT=ReallySuppress'])
        other = recipe_module.softdenchi_recipe()
        other['bootstrap']['sha256'] = '0' * 64
        with self.assertRaisesRegex(Invalid, 'silent launch not defined'):
            recipe_module.silent_arguments(other)
        for arguments in (['/s', '/v"/qn REBOOT=ReallySuppress"'], [], ['s']):
            with self.subTest(arguments=arguments), self.assertRaises(Invalid):
                recipe_module.silent_arguments(real, {'bootstrap_sha256': real['bootstrap']['sha256'], 'arguments': arguments})


class OnePassTests(GAME['GamePrefixTests']):
    def setUp(self):
        super().setUp()
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime']
        self.pin_silent()

    def pin_silent(self):
        self.silent = {'bootstrap_sha256': self.recipe['bootstrap']['sha256'], 'arguments': ['/s', '/v/qn', '/vREBOOT=ReallySuppress']}

    def run_menu(self, text):
        with patch.object(trial, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch('preparation_softdenchi_recipe.softdenchi_recipe', return_value=self.recipe), \
                patch.object(recipe_module, 'SILENT_LAUNCH', self.silent), \
                patch.object(dep.subprocess, 'Popen', wraps=subprocess.Popen) as spawned:
            status, report, output = self.menu(text)
        return status, report, output, [call.args[0][1:] for call in spawned.call_args_list]

    def installs(self):
        with PrivateStore(self.f.store_root) as store:
            return [store.read_record(dep.RECORDS, item['install_id'] + '.json')[0]
                    for item in store.inventory()['dependency_installs']]

    def test_menu_offers_one_pass_only_with_every_step_configured(self):
        _, _, output = self.menu('q\n')
        self.assertIn('12. 新しいゲームを1回で準備', output)
        del self.config['dependency_installation']
        _, _, output = self.menu('q\n')
        self.assertNotIn('12. ', output)

    def test_cancel_before_confirmation_writes_nothing(self):
        before = self.protected()
        status, report, output, commands = self.run_menu('12\n1\n1\nq\n')
        self.assertEqual((status, report, commands), (0, None, []))
        self.assertIn('画面なし', output)
        self.assertIn('使用許諾', output)
        self.assertIn('SIGTERM', output)
        self.assertFalse(self.game_compat.exists())
        self.assertEqual(before, self.protected())

    def test_new_game_is_initialized_installed_silently_and_bound_in_one_run(self):
        status, report, output, commands = self.run_menu('12\n1\n1\n1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertTrue(report['binding_written'])
        self.assertEqual([step['step'] for step in report['steps']],
                         ['initialize', 'softdenchi-state', 'softdenchi-silent', 'binding-plan', 'binding'])
        # Only the initialization and the silent bootstrap ran; no winver, no interactive installer.
        self.assertEqual(len(commands), 2, commands)
        self.assertNotIn(('runinprefix', 'winver.exe'), commands)
        self.assertEqual(commands[1][0], 'runinprefix')
        self.assertEqual(Path(commands[1][1]).name, 'sdrt-fixture.exe')
        self.assertEqual(list(commands[1][2:]), ['/s', '/v/qn', '/vREBOOT=ReallySuppress'])
        (installed,) = self.installs()
        self.assertEqual(installed['status'], 'present-verified')
        self.assertEqual(installed['installer']['mode'], 'silent')
        self.assertEqual(installed['installer']['arguments'], ['/s', '/v/qn', '/vREBOOT=ReallySuppress'])
        self.assertEqual(installed['gui_check']['status'], 'not-applicable')
        self.assertNotIn('display_confirmed', installed['gui_check'])
        self.assertEqual(installed['license_consent'], 'one-pass-confirmation')
        games = json.loads(self.games_config.read_text())
        self.assertEqual(games['games']['42']['valve'], False)
        self.assertIn('DroidDeckからこのゲームを起動', output)
        self.assertFalse(report['preparation_complete'])

    def test_running_again_after_success_only_reports_the_binding(self):
        self.run_menu('12\n1\n1\n1\n')
        before = self.protected()
        _, report, output, commands = self.run_menu('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(commands, [])
        self.assertIn('[続きから]', output)
        self.assertEqual(report['steps'][0]['action'], 'skip')
        self.assertEqual(report['steps'][-1]['action'], 'already-bound')
        self.assertFalse(report['binding_written'])
        self.assertEqual(before, self.protected())

    def test_initialized_prefix_resumes_with_installation_and_binding(self):
        self.initialize()
        _, report, _, commands = self.run_menu('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual([step['step'] for step in report['steps']],
                         ['softdenchi-state', 'softdenchi-silent', 'binding-plan', 'binding'])
        self.assertEqual(len(commands), 1)

    def test_silent_run_that_installs_nothing_offers_the_interactive_installer(self):
        self.use_installer(DEP['installer'](silent_noop=True))
        self.pin_silent()
        _, report, output, commands = self.run_menu('12\n1\n1\n1\nq\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'installation-declined')
        self.assertFalse(report['binding_written'])
        self.assertEqual([item['status'] for item in self.installs()], ['cancelled-absent'])
        self.assertIn('画面ありで導入する場合は1', output)
        # Running again resumes after the cancelled-absent record; this time the interactive installer is accepted.
        _, report, output, commands = self.run_menu('12\n1\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual([c[0:1] + (Path(c[1]).name,) if len(c) > 1 else c for c in commands],
                         [('runinprefix', 'sdrt-fixture.exe'), ('runinprefix', 'winver.exe'),
                          ('runinprefix', 'sdrt-fixture.exe')])
        statuses = [(item['status'], item['installer'].get('mode', 'interactive')) for item in self.installs()]
        self.assertEqual(sorted(statuses), sorted([('cancelled-absent', 'silent'), ('cancelled-absent', 'silent'),
                                                   ('present-verified', 'interactive')]))
        fallback = [step for step in report['steps'] if step['step'] == 'softdenchi-interactive']
        self.assertEqual(len(fallback), 1)
        self.assertEqual(fallback[0]['record']['gui_check']['display_confirmed'], True)

    def test_changed_fixed_values_stop_before_initialization(self):
        real = one_pass._profile
        calls = []

        def drifting(*args):
            calls.append(1)
            value = real(*args)
            return value if len(calls) == 1 else {**value, 'profile': '0' * 64}

        before = self.protected()
        with patch.object(one_pass, '_profile', side_effect=drifting):
            _, report, _, commands = self.run_menu('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'fixed-values-changed')
        self.assertEqual(commands, [])
        self.assertFalse(self.game_compat.exists())
        self.assertEqual(before, self.protected())

    def test_interactive_fallback_refuses_when_other_fixed_values_changed(self):
        self.use_installer(DEP['installer'](silent_noop=True))
        self.pin_silent()
        real = one_pass._profile
        journal = self.f.store_root / dep.RECORDS

        def drifting(*args):
            value = real(*args)
            # Only after the silent run has recorded that it installed nothing.
            done = journal.exists() and any(b'cancelled-absent' in path.read_bytes() for path in journal.glob('depinstall-*.json'))
            return {**value, 'profile': '0' * 64} if done else value

        with patch.object(one_pass, '_profile', side_effect=drifting):
            _, report, output, commands = self.run_menu('12\n1\n1\n1\n1\n')
        self.assertEqual(report['reason'], 'fixed-values-changed', report)
        self.assertEqual(report['stage'], 'softdenchi-interactive')
        self.assertNotIn('画面ありで導入する場合は1', output)
        self.assertEqual(len(commands), 2)
        self.assertEqual([item['status'] for item in self.installs()], ['cancelled-absent'])

    def test_failed_installation_history_stops_without_reinstalling(self):
        record_, digest = self.initialize()
        self.use_installer(DEP['installer']())
        self.pin_silent()
        with patch.object(dep.DependencyInstallSession, '_spawn', side_effect=OSError('spawn refused')), \
                self.assertRaises(OSError), PrivateStore(self.f.store_root) as store, \
                store.locked(hashlib.sha256(str(self.game_compat).encode()).hexdigest()), \
                patch.object(dep, 'plan_launch', side_effect=self.launch_fixture):
            plan = self.install_plan_for(record_, digest)
            dep.DependencyInstallSession(plan, store, lambda: self.install_plan_for(record_, digest), plan.digest,
                                         GAME['ProcessStopCheck'](self.game_compat, self.f.proc)).start_silent_installer()
        self.assertEqual([(i['status'], i['phase']) for i in self.installs()], [('failed', 'installer-spawned')])
        _, report, _, commands = self.run_menu('12\n1\n1\n')
        self.assertEqual(report['reason'], 'previous-installation-failed-review-required', report)
        self.assertEqual(commands, [])

    def install_plan_for(self, record_, digest, mode='silent'):
        source, _, games = DEP['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        return dep.plan_dependency_install(record=record_, record_sha256=digest, config=self.config,
            directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source, games=games,
            steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
            runtime_root=self.f.root, recipe=self.recipe, installer_mode=mode, silent_launch=self.silent)

    def test_silent_and_interactive_entries_stay_separate(self):
        record_, digest = self.initialize()
        silent = self.install_plan_for(record_, digest)
        interactive = self.install_plan_for(record_, digest, 'interactive')
        self.assertNotEqual(silent.digest, interactive.digest)
        self.assertEqual(silent.summary()['license_decision'], 'one-pass-confirmation')
        self.assertEqual(interactive.summary()['steps'][0]['step'], 'gui-check')
        with self.f.store() as store:
            stop = GAME['ProcessStopCheck'](self.game_compat, self.f.proc)
            with self.assertRaisesRegex(Invalid, 'GUI check belongs to the interactive installer'):
                dep.DependencyInstallSession(silent, store, lambda: silent, silent.digest, stop).start_gui_check()
            with self.assertRaisesRegex(Invalid, 'interactive plan required'):
                dep.DependencyInstallSession(silent, store, lambda: silent, silent.digest, stop).start_installer()
            with self.assertRaisesRegex(Invalid, 'silent plan required'):
                dep.DependencyInstallSession(interactive, store, lambda: interactive, interactive.digest,
                                             stop).start_silent_installer()
            with self.assertRaisesRegex(Invalid, 'exact unused confirmation'):
                dep.DependencyInstallSession(silent, store, lambda: silent, '0' * 64, stop).start_silent_installer()
            session = dep.DependencyInstallSession(silent, store, lambda: silent, silent.digest, stop)
        good = dict(session.record)
        dep.validate_install_record(good)
        for change in ({'gui_check': {'status': 'not-applicable', 'unix_exit_status': None, 'display_confirmed': True}},
                       {'license_consent': None}, {'gui_check': {'status': 'not-started', 'unix_exit_status': None}},
                       {'installer': {**good['installer'], 'arguments': []}}):
            bad = {**good, **change}
            if bad.get('license_consent') is None:
                bad.pop('license_consent')
            with self.subTest(change=change), self.assertRaises(Invalid):
                dep.validate_install_record(bad)


# Only the one-pass tests run here; the inherited fixtures' own tests run in their modules.
for _name in dir(GAME['GamePrefixTests']):
    if _name.startswith('test_') and _name not in OnePassTests.__dict__:
        setattr(OnePassTests, _name, None)


if __name__ == '__main__':
    unittest.main()
