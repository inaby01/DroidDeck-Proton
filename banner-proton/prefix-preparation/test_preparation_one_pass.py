#!/usr/bin/env python3
"""Menu 12 one-pass preparation with the native surrogate; never Wine, vendor binaries or real games."""

import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
GAME = runpy.run_path(str(HERE / 'test_preparation_game_prefix.py'))
DEP = GAME['DEP']
import preparation_dependency_install as dep
import preparation_one_pass as one_pass
import preparation_prefix_dll as prefix_dll
import preparation_softdenchi_recipe as recipe_module
import preparation_trial as trial
from preparation_common import Invalid
from preparation_store import PrivateStore


def game_records_dir():
    import preparation_game_prefix
    return preparation_game_prefix.RECORDS


DLL_DATA = GAME['synthetic_pe'](extra=b'synthetic prefix runtime library')


class Killed(BaseException):
    """Simulates the tool being killed: nothing in the tool catches it."""


def record(status, phase='post-inspected'):
    return {'install_id': 'depinstall-' + '0' * 32, 'status': status, 'phase': phase}


class ActionTableTests(unittest.TestCase):
    """Design 5.1 step 3 and 5.2: history rows first, then the current state."""

    def test_softdenchi_rows(self):
        cases = [
            ((None, 0, 'absent'), 'install'),
            ((record('needs-user', 'installer-exited'), 0, 'absent'), 'install'),
            ((record('running', 'installer-staged'), 0, 'absent'), 'install'),
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
        self.assertTrue(one_pass.softdenchi_action(None, 0, 'present-verified')[2])
        self.assertTrue(one_pass.softdenchi_action(record('cancelled-absent'), 0, 'present-verified')[2])
        self.assertFalse(one_pass.softdenchi_action(record('present-verified'), 0, 'present-verified')[2])

    def test_only_not_verified_blockers_of_pending_dependencies_are_dropped(self):
        pending = {'softdenchi-runtime', 'target-process-view-not-clear'}
        blockers = ('dependency-not-verified:softdenchi-runtime', 'dependency-blocked:softdenchi-runtime',
                    'dependency-not-verified:other', 'process:target-process-view-not-clear',
                    'dependency-not-verified:target-process-view-not-clear', 'no-colon')
        self.assertEqual(one_pass.blockers_left(blockers, pending),
                         ['dependency-blocked:softdenchi-runtime', 'dependency-not-verified:other',
                          'process:target-process-view-not-clear', 'no-colon'])

    def test_binding_rows(self):
        class Plan:
            def __init__(self, same):
                self.before = {'games': b'a', 'config': b'b', 'state': b'c'}
                self.after = {name: value if name in same else value + b'!' for name, value in self.before.items()}
        everything = ('games', 'config', 'state')
        self.assertEqual(one_pass.binding_action(Plan(everything), [])[0], 'already-bound')
        failed_early = {'status': 'binding-failed', 'completed_files': []}
        failed_late = {'status': 'binding-failed', 'completed_files': ['games']}
        verified = {'status': 'binding-verified', 'completed_files': list(everything)}
        self.assertEqual(one_pass.binding_action(Plan(everything), [failed_late])[0], 'already-bound')
        # A partial state stops whatever the history says; it is never completed automatically.
        self.assertEqual(one_pass.binding_action(Plan(('state',)), []), ('stop', 'binding-partially-applied'))
        self.assertEqual(one_pass.binding_action(Plan(('state',)), [failed_late]), ('stop', 'binding-partially-applied'))
        self.assertEqual(one_pass.binding_action(Plan(()), [verified]), ('stop', 'binding-changed-after-verified-binding'))
        self.assertEqual(one_pass.binding_action(Plan(()), [failed_late]), ('stop', 'previous-binding-wrote-files'))
        # A binding that failed before writing anything does not block a new one.
        self.assertEqual(one_pass.binding_action(Plan(()), [failed_early]), ('apply', None))
        self.assertEqual(one_pass.binding_action(Plan(()), []), ('apply', None))

    def test_preapproved_stop_reads_no_input_and_records_how_it_was_confirmed(self):
        class Session:
            def __init__(self, targets, reason=None):
                self.preview = ({'processes': [], 'unreadable_count': 0, 'stop_origins': {'installer-run': 2}}, targets, reason)
                self.calls, self.record = [], {}

            def preview_proxy_stop(self):
                return self.preview

            def stop_lingering_proxies(self, **kwargs):
                self.calls.append(kwargs)
                return {'status': 'present-verified', 'post_state': 'present-verified',
                        'lingering': {'stop': {'result': 'sigterm-sent', 'signals': []}}}

            def _save(self):
                pass

        stream, output = io.StringIO('1\n'), io.StringIO()
        session = Session([(1, 1), (2, 2)])
        dep._offer_session_proxy_stop(session, stream, output, str, preapproved=True, next_step=None)
        self.assertEqual(session.calls, [{'confirmation': 'one-pass-preapproved'}])
        self.assertEqual(stream.tell(), 0)
        self.assertIn('最初の確認に基づき', output.getvalue())
        # Without targets under the unchanged rules nothing is sent, pre-approved or not.
        refused = Session(None, 'unexplained process')
        dep._offer_session_proxy_stop(refused, io.StringIO(), io.StringIO(), str, preapproved=True, next_step=None)
        self.assertEqual(refused.calls, [])
        self.assertEqual(refused.record['lingering']['stop'], {'result': 'refused', 'reason': 'unexplained process'})
        # Menu 8 still asks, and its call carries no pre-approval.
        asked = Session([(1, 1)])
        dep._offer_session_proxy_stop(asked, io.StringIO('1\n'), io.StringIO(), str)
        self.assertEqual(asked.calls, [{}])

    def test_next_step_after_an_unfinished_installation(self):
        operational = {'probe_material': True, 'initialization_trial': True, 'placement_review': {}, 'game_preparation': {},
                       'dependency_installation': {}}
        earlier = {key: value for key, value in operational.items() if key != 'game_preparation'}
        for config, again, menu9 in ((operational, 'もう一度 recovery.sh の1 ', 'recovery.sh の6'), (earlier, 'もう一度 12 ', 'メニュー9')):
            with self.subTest(again=again):
                self.assertIn(again, one_pass.installation_next_step(None, config))
                self.assertEqual(one_pass.installation_next_step({'status': 'failed', 'post_state': None}, config),
                                 one_pass.failed_then_menu9(config))
                self.assertIn(menu9, one_pass.failed_then_menu9(config))
                self.assertEqual(one_pass.installation_next_step({'status': 'needs-user', 'post_state': 'uninspected'}, config),
                                 one_pass.restart_then_one_pass(config))
                self.assertIn(again, one_pass.restart_then_one_pass(config))
                self.assertIn(menu9, one_pass.installation_next_step({'status': 'partial', 'post_state': 'partial'}, config))
        self.assertNotIn('詳細メニュー', one_pass.failed_then_menu9(earlier))

    def test_silent_arguments_are_pinned_to_the_recipe_bootstrap(self):
        real = recipe_module.softdenchi_recipe()
        self.assertEqual(recipe_module.silent_arguments(real), ['/s', '/v/qn', '/vREBOOT=ReallySuppress'])
        other = recipe_module.softdenchi_recipe()
        other['bootstrap']['sha256'] = '0' * 64
        with self.assertRaisesRegex(Invalid, 'silent launch not defined'):
            recipe_module.silent_arguments(other)
        self.assertEqual(recipe_module.silent_arguments(real, {'bootstrap_sha256': real['bootstrap']['sha256'],
                                                               'arguments': ['/' + 'a' * 63]}), ['/' + 'a' * 63])
        for arguments in (['/s', '/v"/qn REBOOT=ReallySuppress"'], [], ['s'], ['/' + 'a' * 64]):
            with self.subTest(arguments=arguments), self.assertRaises(Invalid):
                recipe_module.silent_arguments(real, {'bootstrap_sha256': real['bootstrap']['sha256'], 'arguments': arguments})


class OnePassTests(GAME['GamePrefixTests']):
    def setUp(self):
        super().setUp()
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime']
        self.pin_silent()

    def pin_silent(self):
        self.silent = {'bootstrap_sha256': self.recipe['bootstrap']['sha256'], 'arguments': ['/s', '/v/qn', '/vREBOOT=ReallySuppress']}

    def run_menu(self, text, menu=None):
        menu = self.entry_menu if menu is None else menu
        with patch.object(trial, 'plan_launch', side_effect=self.launch_fixture), \
                patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                patch('preparation_softdenchi_recipe.softdenchi_recipe', return_value=self.recipe), \
                patch.object(recipe_module, 'SILENT_LAUNCH', self.silent), \
                patch.object(dep.subprocess, 'Popen', wraps=subprocess.Popen) as spawned:
            status, report, output = menu(text)
        return status, report, output, [call.args[0][1:] for call in spawned.call_args_list]

    def run_detail(self, text):
        return self.run_menu(text, self.detail_menu)

    def installs(self):
        with PrivateStore(self.f.store_root) as store:
            return [store.read_record(dep.RECORDS, item['install_id'] + '.json')[0]
                    for item in store.inventory()['dependency_installs']]

    def test_menu_offers_one_pass_only_with_every_step_configured(self):
        _, _, output = self.entry_menu('q\n')
        self.assertIn('1. 1本だけ準備する', output)
        self.assertNotIn('12. ', output)
        _, _, output = self.detail_menu('q\n')
        self.assertIn('12. 新しいゲームを1回で準備', output)
        for missing in ('dependency_installation', 'game_preparation'):
            config = dict(self.config)
            del self.config[missing]
            # Without every step the earlier screen stays (validation bundles), with its own numbers.
            _, _, output = self.menu('q\n')
            self.assertTrue(output.startswith('1. 登録済み対象の読み取り検査・計画'), (missing, output))
            self.assertNotIn('12. ', output)
            self.assertNotIn('新しいゲームを準備（', output)
            self.config = config

    def test_cancel_before_confirmation_writes_nothing(self):
        before = self.protected()
        status, report, output, commands = self.run_detail('12\n1\n1\nq\n')
        self.assertEqual((status, report, commands), (0, None, []))
        self.assertIn('画面なし', output)
        self.assertIn('使用許諾', output)
        self.assertIn('SIGTERM', output)
        self.assertFalse(self.game_compat.exists())
        self.assertEqual(before, self.protected())

    def test_new_game_is_initialized_installed_silently_and_bound_in_one_run(self):
        status, report, output, commands = self.run_detail('12\n1\n1\n1\n')
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

    def test_profile_without_dependencies_is_initialized_and_bound(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = []
        status, report, output, commands = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual([step['step'] for step in report['steps']], ['initialize', 'binding-plan', 'binding'])
        self.assertEqual(len(commands), 1, commands)  # Only the initialization ran Wine.
        self.assertEqual(self.installs(), [])
        self.assertIn('依存 なし', output)
        self.assertNotIn('prefix内（', output)
        self.assertNotIn('使用許諾', output)
        self.assertIn('DroidDeckからこのゲームを起動してください。', output)
        self.assertNotIn('ソフト電池の認証', output)

    def test_running_game_without_dependencies_stops_the_resume_before_binding(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = []
        self.initialize()
        before = self.protected()
        with patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
            _, report, output, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['stage'], 'binding')
        self.assertIn('process:target-process-view-not-clear', report['reason'])
        self.assertIn('ゲームまたはWineが動いているため', output)
        self.assertEqual(commands, [])
        self.assertEqual(before, self.protected())
        # Once the game is closed, the same run binds it.
        _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)

    def test_running_game_after_a_new_initialization_stops_before_binding(self):
        self.config['game_preparation']['profiles'][0]['dependencies'] = []
        original = one_pass.plan_game_binding

        def running(**arguments):
            with patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
                return original(**arguments)
        with patch.object(one_pass, 'plan_game_binding', side_effect=running):
            _, report, output, commands = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual((report['status'], report['stage']), ('stopped', 'binding'), report)
        self.assertEqual([step['step'] for step in report['steps']], ['initialize', 'binding-plan'])
        self.assertIn('process:target-process-view-not-clear', report['reason'])
        self.assertEqual(report['next_step'], one_pass.BINDING_RUNNING)
        self.assertIn('初期化は済んでいます', output)
        self.assertEqual(len(commands), 1)
        self.assertFalse(report['binding_written'])
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)

    def test_running_again_after_success_only_reports_the_binding(self):
        self.run_detail('12\n1\n1\n1\n')
        before = self.protected()
        _, report, output, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(commands, [])
        self.assertIn('[続きから]', output)
        self.assertEqual(report['steps'][0]['action'], 'skip')
        self.assertEqual(report['steps'][-1]['action'], 'already-bound')
        self.assertFalse(report['binding_written'])
        self.assertEqual(before, self.protected())

    def test_initialized_prefix_resumes_with_installation_and_binding(self):
        self.initialize()
        _, report, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual([step['step'] for step in report['steps']],
                         ['softdenchi-state', 'softdenchi-silent', 'binding-plan', 'binding'])
        self.assertEqual(len(commands), 1)

    def test_silent_run_that_installs_nothing_offers_the_interactive_installer(self):
        self.use_installer(DEP['installer'](silent_noop=True))
        self.pin_silent()
        _, report, output, commands = self.run_detail('12\n1\n1\n1\nq\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'installation-declined')
        self.assertEqual(report['stage'], 'softdenchi-interactive')
        self.assertFalse(report['binding_written'])
        self.assertEqual([item['status'] for item in self.installs()], ['cancelled-absent'])
        self.assertIn('画面ありで導入する場合は1', output)
        # Running again resumes after the cancelled-absent record; this time the interactive installer is accepted.
        _, report, output, commands = self.run_detail('12\n1\n1\n1\n1\n')
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
        # The separate confirmation is bound to the interactive plan, which is what the session ran.
        self.assertEqual(fallback[0]['confirmed_plan'], fallback[0]['record']['input_digest'])
        self.assertEqual(fallback[0]['plan']['installer_mode'], 'interactive')
        self.assertEqual(report['steps'][1]['plan']['installer_mode'], 'silent')

    def test_changed_fixed_values_stop_before_initialization(self):
        real = one_pass._profile
        calls = []

        def drifting(*args):
            calls.append(1)
            value = real(*args)
            return value if len(calls) == 1 else {**value, 'profile': '0' * 64}

        before = self.protected()
        with patch.object(one_pass, '_profile', side_effect=drifting):
            _, report, _, commands = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'fixed-values-changed:profile')
        self.assertEqual(report['stage'], 'initialize')
        self.assertEqual(sorted(report['confirmed_fixed_values']['items']),
                         ['asset', 'binding', 'dlls', 'installer_log', 'installer_mode', 'paths', 'profile', 'proton', 'registration'])
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
            _, report, output, commands = self.run_detail('12\n1\n1\n1\n1\n')
        self.assertEqual(report['reason'], 'fixed-values-changed:profile', report)
        self.assertEqual(report['stage'], 'softdenchi-interactive')
        self.assertEqual(report['fixed_value_changes'], [{'stage': 'softdenchi-interactive', 'items': ['profile']}])
        self.assertNotIn('画面ありで導入する場合は1', output)
        self.assertEqual(len(commands), 2)
        self.assertEqual([item['status'] for item in self.installs()], ['cancelled-absent'])

    def write_binding_record(self, app, version, status='binding-verified', completed=('games', 'config', 'state')):
        record_ = {'schema_version': 1, 'tool_version': version, 'binding_id': 'binding-' + hashlib.sha256(app.encode()).hexdigest()[:32],
                   'app_id': app, 'input_digest': '0' * 64, 'status': status, 'completed_files': list(completed),
                   'preparation_complete': False}
        directory = self.f.store_root / 'bindings'
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / (record_['binding_id'] + '.json')
        path.write_text(json.dumps(record_))
        path.chmod(0o600)
        return path

    def test_binding_records_of_older_versions_do_not_stop_the_run(self):
        self.write_binding_record('77', '0.27.7')
        _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertTrue(report['binding_written'])

    def test_unreadable_binding_record_stops_before_anything_is_written(self):
        path = self.write_binding_record('77', '0.27.7')
        path.write_text('{"not": "a binding record"}')
        before = self.protected()
        _, report, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual((report['status'], report['stage']), ('stopped', 'binding-history'), report)
        self.assertEqual(commands, [])
        self.assertFalse(self.game_compat.exists())
        self.assertEqual(before, self.protected())

    def test_profile_is_selected_by_the_pinned_exe_hash_and_bound_game_with_a_missing_file_is_not_ready(self):
        self.use_folder_dependency()
        dll = self.f.exe.parent / 'mfc42.dll'
        dll.write_bytes(GAME['DLL'])
        # One pinned match: no profile question (menu, game, confirmation).
        _, report, output, _ = self.run_detail('12\n1\n1\n')
        self.assertIn('EXEハッシュ一致で自動選択', output)
        self.assertEqual(report['status'], 'ready-to-launch', report)
        dll.unlink()
        before = self.protected()
        _, report, output, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'binding-blocked:dependency-not-verified:mfc42-game-folder')
        self.assertNotIn('準備が終わりました', output)
        self.assertEqual(commands, [])
        self.assertEqual(before, self.protected())

    def test_blocked_dependency_or_missing_installer_stops_before_anything_is_written(self):
        before = self.protected()
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime', 'mfc42-candidate']
        _, report, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual((report['stage'], report['reason']), ('one-pass-precheck', 'dependency-blocked:mfc42-candidate'))
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime']
        (self.f.fixture.source.root / 'sdrt-fixture.exe').unlink()
        _, report, output, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['stage'], 'one-pass-precheck', report)
        self.assertIn('asset:', report['reason'])
        self.assertIn('sdrt-fixture.exe', output)
        self.assertEqual(commands, [])
        self.assertFalse(self.game_compat.exists())
        self.assertEqual(before, self.protected())

    def test_unreadable_game_prefix_record_does_not_hide_other_games(self):
        directory = self.f.store_root / game_records_dir()
        directory.mkdir(mode=0o700, exist_ok=True)
        junk = directory / ('gprefix-' + '0' * 32 + '.json')
        junk.write_text('{"not": "a record"}')
        junk.chmod(0o600)
        _, report, output, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertIn('読めない初期化記録が1件', output)
        self.assertEqual(report['unreadable_game_prefix_records'], 1)
        self.assertEqual(report['status'], 'ready-to-launch', report)

    def test_several_matching_profiles_are_asked(self):
        self.use_folder_dependency()
        twin = dict(self.config['game_preparation']['profiles'][0], profile_id='example-twin')
        self.config['game_preparation']['profiles'].append(twin)
        status, report, output, commands = self.run_detail('12\n1\nq\n')
        self.assertEqual((status, report, commands), (0, None, []))
        self.assertIn('作品プロファイルの番号', output)
        self.assertNotIn('自動選択', output)

    def test_settings_changed_between_steps_stop_before_binding(self):
        real = one_pass.plan_game_binding
        games = self.games_config

        def touched(**kwargs):
            # Same content, different bytes: the confirmed settings inputs no longer match.
            games.write_text(json.dumps(json.loads(games.read_text()), indent=2))
            return real(**kwargs)

        with patch.object(one_pass, 'plan_game_binding', side_effect=touched):
            _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['reason'], 'fixed-values-changed:binding', report)
        self.assertEqual(report['stage'], 'binding')
        self.assertFalse(report['binding_written'])
        self.assertNotIn('42', json.loads(self.games_config.read_text())['games'])

    def test_diagnostic_log_of_a_verified_install_is_summarised_and_not_offered(self):
        self.config['diagnostics'] = {'installer_log': True}
        _, report, output, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        step = next(item for item in report['steps'] if item['step'] == 'softdenchi-silent')
        self.assertEqual(step['installer_log']['state'], 'final')
        self.assertEqual(step['installer_log']['writers_remaining'], 0)
        self.assertNotIn('installer_log_copies', report)
        self.assertNotIn('導入のログ（導入のときの標準エラー全体', output)
        self.assertTrue(step['plan']['installer_log'])

    def test_a_failure_after_the_installer_still_fixes_and_reports_the_log(self):
        self.config['diagnostics'] = {'installer_log': True}
        real = dep._wait_loop

        def then_fail(wait, *args, **kwargs):
            outcome = real(wait, *args, **kwargs)
            if args and args[2] == 'installer':
                raise OSError(5, 'stop check failed')
            return outcome
        with patch.object(dep, '_wait_loop', side_effect=then_fail):
            _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        step = next(item for item in report['steps'] if item['step'] == 'softdenchi-silent')
        self.assertEqual(step['installer_log']['state'], 'final', step)

    def inherit_vc(self):
        """Design: inherited VC record. The fake initialization writes DroidDeck's appended keys."""
        import preparation_vc_record as vc
        vc_tests = runpy.run_path(str(Path(__file__).with_name('test_preparation_vc_record.py')))
        (self.f.steam / 'steamapps/compatdata/vc-block.reg').write_text('\n' + vc_tests['block']())
        return vc, vc_tests

    def test_one_pass_releases_the_inherited_vc_record_before_the_silent_installer(self):
        vc, vc_tests = self.inherit_vc()
        with patch.object(vc, 'read_template', return_value=vc_tests['template'](tail_sha256=None)):
            _, report, output, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertIn("ひな形から受け継いだ『VC++ 14.51導入済み』", output)
        self.assertEqual([item['inherited_vc_record']['state'] for item in self.installs()], ['released'])

    def test_a_release_stop_never_waits_for_an_installer_and_a_final_one_stays(self):
        vc, _ = self.inherit_vc()
        with patch.object(vc, 'read_template', side_effect=Invalid('template tail changed')):
            _, report, output, commands = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual((report['status'], report['reason']), ('stopped', 'inherited-vc-record-template-mismatch'), report)
        self.assertIn('もう一度実行しても進みません', output)
        self.assertFalse(any(len(command) > 1 and str(command[1]).endswith('.exe') and str(command[1]).startswith('/')
                             for command in commands))
        self.assertEqual([item['status'] for item in self.installs()], ['stopped-before-installer'])
        # Running again stops before planning an installation (design: inherited VC record, Fable L4).
        _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual((report['stage'], report['reason']), ('softdenchi-state', 'inherited-vc-record-template-mismatch'))
        self.assertEqual(len(self.installs()), 1)

    def test_the_run_itself_stops_on_a_final_release_stop_even_if_the_plan_would_not(self):
        vc, _ = self.inherit_vc()
        with patch.object(vc, 'read_template', side_effect=Invalid('template tail changed')):
            self.run_detail('12\n1\n1\n1\n')
        real = dep.vc_latest

        def only_the_run_sees_it(store_root, trial_id):
            if sys._getframe(1).f_code.co_name == 'evaluate_resume':
                return None, None
            return real(store_root, trial_id)
        # Defence in depth (Fable code review M2): the plan and the evaluation would not stop, the run still does.
        with patch.object(dep, '_vc_final_stop', return_value=None), patch.object(dep, 'vc_latest', only_the_run_sees_it):
            _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual((report['stage'], report['reason']), ('softdenchi-state', 'inherited-vc-record-template-mismatch'))
        self.assertEqual(len(self.installs()), 1)

    def test_the_interactive_fallback_reports_a_release_stop_without_waiting(self):
        self.use_installer(DEP['installer'](silent_noop=True))
        self.pin_silent()
        real = dep.DependencyInstallSession._release_inherited_vc

        def interactive_stops(session):
            if session.plan.installer_mode == 'interactive':
                import preparation_vc_record as vc
                return session._release_stop(vc.failed('wine-start:OSError'))
            return real(session)
        with patch.object(dep.DependencyInstallSession, '_release_inherited_vc', interactive_stops):
            _, report, output, _ = self.run_detail('12\n1\n1\n1\n1\n1\n')
        self.assertEqual((report['status'], report['reason']), ('stopped', 'installation-stopped-before-installer'), report)
        self.assertIn('受け継いだVC++の記録を外す段で止まりました', output)
        self.assertNotIn('インストーラーの画面で操作してください', output)

    def test_ctrl_c_after_the_installer_leaves_the_log_open(self):
        import preparation_installer_log as log
        self.config['diagnostics'] = {'installer_log': True}
        real = dep._wait_loop

        def then_interrupt(wait, *args, **kwargs):
            outcome = real(wait, *args, **kwargs)
            if args and args[2] == 'installer':
                raise KeyboardInterrupt
            return outcome
        with patch.object(dep, '_wait_loop', side_effect=then_interrupt), self.assertRaises(KeyboardInterrupt):
            self.run_detail('12\n1\n1\n1\n')
        records = [json.loads(path.read_text()) for path in (self.f.store_root / log.RECORDS).glob('depinstall-*.json')]
        self.assertEqual([record['state'] for record in records], ['open'])

    def test_ctrl_c_in_the_interactive_fallback_leaves_its_log_open(self):
        import preparation_installer_log as log
        self.config['diagnostics'] = {'installer_log': True}
        self.use_installer(DEP['installer'](silent_noop=True))
        self.pin_silent()
        real, waits = dep._wait_loop, []

        def second_interrupts(wait, *args, **kwargs):
            outcome = real(wait, *args, **kwargs)
            if args and args[2] == 'installer':
                waits.append(1)
                if len(waits) == 2:  # The first wait is the silent run; the second the interactive installer.
                    raise KeyboardInterrupt
            return outcome
        with patch.object(dep, '_wait_loop', side_effect=second_interrupts), self.assertRaises(KeyboardInterrupt):
            self.run_detail('12\n1\n1\n1\n1\n1\n')  # The last 1 answers that the winver window was shown.
        self.assertEqual(len(waits), 2)
        records = [json.loads(path.read_text()) for path in (self.f.store_root / log.RECORDS).glob('depinstall-*.json')]
        self.assertEqual(sorted(record['state'] for record in records), ['final', 'open'])

    def test_a_partial_install_offers_its_log_next_to_the_result(self):
        files = dict(list(DEP['FILES'].items())[:1])
        self.use_installer(DEP['installer'](files=files, exit_code=91,
                                            stderr=['0024:err:msi:ITERATE_Actions Execution halted, action L"InstallServices" returned 1627']))
        self.pin_silent()
        self.config['diagnostics'] = {'installer_log': True}
        _, report, output, _ = self.run_detail('12\n1\n1\n1\n1\n')
        self.assertEqual((report['stage'], report['reason']), ('softdenchi-silent', 'installation-partial'), report)
        step = next(item for item in report['steps'] if item['step'] == 'softdenchi-silent')
        self.assertEqual(step['installer_log']['summary']['returned'], {'1627': 1})
        self.assertIn('回収できません', output)
        copies = report['installer_log_copies']
        self.assertTrue(copies[0]['copied'], copies)
        copied = self.f.fixture.source.root / copies[0]['name']
        self.assertIn(b'returned 1627', copied.read_bytes())

    def test_an_exception_inside_a_step_keeps_that_step_record_in_the_result(self):
        with patch.object(dep.DependencyInstallSession, '_spawn', side_effect=OSError('spawn refused')):
            _, report, _, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual((report['status'], report['stage']), ('stopped', 'softdenchi-silent'), report)
        step = report['steps'][-1]
        self.assertEqual(step['step'], 'softdenchi-silent')
        self.assertTrue(step['interrupted'])
        self.assertEqual((step['record']['status'], step['record']['phase']), ('failed', 'installer-spawned'))
        self.assertEqual(step['plan']['installer_mode'], 'silent')

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
        _, report, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['reason'], 'previous-installation-failed-review-required', report)
        self.assertEqual(commands, [])

    def test_layout_changed_after_planning_stops_before_wine(self):
        """Wine is not started in a game prefix linked outside this Proton, even with a plan made before (0.31.0)."""
        record_, digest = self.initialize()
        self.use_installer(DEP['installer']())
        self.pin_silent()
        plan = self.install_plan_for(record_, digest)
        self.assertEqual(plan.blockers, ())
        link = self.game_compat / 'pfx/drive_c/windows/syswow64/cmd.exe'
        outside = self.home / 'outside-cmd.exe'
        outside.write_bytes(link.read_bytes())
        link.unlink()
        link.symlink_to(outside)
        self.assertIn('prefix-layout-not-this-proton', self.install_plan_for(record_, digest).blockers)
        with patch.object(dep.DependencyInstallSession, '_spawn') as spawn, \
                patch.object(dep, 'plan_launch', side_effect=self.launch_fixture), \
                PrivateStore(self.f.store_root) as store, \
                store.locked(hashlib.sha256(str(self.game_compat).encode()).hexdigest()), \
                self.assertRaisesRegex(Invalid, 'reference builtin links outside the selected Proton'):
            dep.DependencyInstallSession(plan, store, lambda: plan, plan.digest,
                                         GAME['ProcessStopCheck'](self.game_compat, self.f.proc)).start_silent_installer()
        spawn.assert_not_called()

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


class PrefixDllOnePassTests(OnePassTests):
    """Menu 12 with a prefix DLL dependency (design: prefix-preparation-prefix-dll-design)."""

    def setUp(self):
        super().setUp()
        self.use_dll()
        patch.object(prefix_dll, 'REFERENCE', 'cmd.exe').start()
        self.addCleanup(patch.stopall)

    def use_dll(self, data=DLL_DATA, **changes):
        spec = DEP['spec_for'](data, asset_id='mfc42-fixture', filename='mfc42.dll', version='6.00.8665.0')
        spec.update(changes)
        recipes = [item for item in self.config['game_preparation']['recipes'] if item['dependency_id'] != 'mfc42-prefix']
        recipes.append({'dependency_id': 'mfc42-prefix', 'revision': 1, 'handler': 'prefix-dll', 'status': 'ready',
                        'reason': 'synthetic recipe', 'asset': spec, 'destination': 'syswow64'})
        self.config['game_preparation']['recipes'] = recipes
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime', 'mfc42-prefix']
        path = self.f.fixture.source.root / spec['filename']
        if path.exists():
            path.unlink()
        path.write_bytes(data)

    def wow64(self):
        return self.game_compat / 'pfx/drive_c/windows/syswow64'

    def dll_records(self):
        with PrivateStore(self.f.store_root) as store:
            return sorted((store.read_record(prefix_dll.RECORDS, item['record_id'] + '.json')[0]
                           for item in store.inventory()['prefix_dlls']), key=lambda item: item['created_ns'])

    def leftovers(self):
        """Anything in syswow64 besides the fixture builtin and the placed DLL (the copy never leaves other names)."""
        return sorted(p.name for p in self.wow64().iterdir() if p.name not in ('cmd.exe', 'mfc42.dll', 'MFC42.DLL'))

    def test_new_game_gets_the_dll_before_softdenchi_and_is_bound(self):
        _, report, output, commands = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual([step['step'] for step in report['steps']],
                         ['initialize', 'prefix-dll', 'softdenchi-state', 'softdenchi-silent', 'binding-plan', 'binding'])
        self.assertIn('syswow64に mfc42.dll が入っていなければ入れる', output)
        placed = self.wow64() / 'mfc42.dll'
        self.assertEqual(placed.read_bytes(), DLL_DATA)
        self.assertEqual(placed.stat().st_nlink, 1)
        self.assertFalse(placed.is_symlink())
        self.assertEqual(self.leftovers(), [])
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['error'], saved['name']), ('present-verified', None, 'mfc42.dll'))
        self.assertEqual(report['steps'][1]['record']['record_id'], saved['record_id'])
        self.assertFalse(report['steps'][1]['plan']['registry_changed'])
        states = {item['dependency_id']: item['state'] for item in report['steps'][-2]['plan']['dependencies']}
        self.assertEqual(states, {'softdenchi-runtime': 'present-verified', 'mfc42-prefix': 'present-verified'})
        self.assertEqual(len(commands), 2)
        self.assertIn('dlls', report['confirmed_fixed_values']['items'])

    def test_confirmation_lists_any_number_of_dlls(self):
        profile = self.config['game_preparation']['profiles'][0]
        for number in range(8):
            data = GAME['synthetic_pe'](extra=b'synthetic runtime %d' % number)
            name = f'runtime{number}.dll'
            spec = DEP['spec_for'](data, asset_id=f'runtime-fixture-{number}', filename=name)
            self.config['game_preparation']['recipes'].append(
                {'dependency_id': f'runtime-{number}', 'revision': 1, 'handler': 'prefix-dll', 'status': 'ready',
                 'reason': 'synthetic recipe', 'asset': spec, 'destination': 'syswow64'})
            profile['dependencies'].append(f'runtime-{number}')
            (self.f.fixture.source.root / name).write_bytes(data)
        status, report, output, commands = self.run_detail('12\n1\n1\nq\n')
        self.assertEqual((status, report, commands), (0, None, []))
        self.assertIn('  13) 依存がすべて検証済みなら', output)

    def test_running_again_skips_the_placed_dll(self):
        self.run_detail('12\n1\n1\n1\n')
        placed = self.wow64() / 'mfc42.dll'
        before = (placed.stat().st_ino, placed.stat().st_mtime_ns)
        _, report, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(report['steps'][0]['step'], 'prefix-dll')
        self.assertEqual(report['steps'][0]['plan']['action'], 'skip')
        self.assertEqual(len(self.dll_records()), 1)
        self.assertEqual(before, (placed.stat().st_ino, placed.stat().st_mtime_ns))
        self.assertEqual(commands, [])

    def test_existing_different_file_is_never_overwritten(self):
        self.initialize()
        foreign = GAME['synthetic_pe'](extra=b'someone else placed this')
        (self.wow64() / 'MFC42.DLL').write_bytes(foreign)
        _, report, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['stage'], 'prefix-dll')
        self.assertIn('size, hash or architecture differs', report['reason'])
        self.assertEqual((self.wow64() / 'MFC42.DLL').read_bytes(), foreign)
        self.assertEqual((commands, self.dll_records(), self.leftovers()), ([], [], []))
        self.assertFalse(report['binding_written'])

    def test_a_name_the_proton_ships_as_builtin_is_refused(self):
        self.initialize()
        with patch.object(prefix_dll, 'builtin_names', return_value={'mfc42.dll'}):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('builtin', report['reason'])
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())

    def test_unconfirmed_x86_layout_is_refused(self):
        self.initialize()
        (self.wow64() / 'cmd.exe').unlink()
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('x86 system directory not confirmed', report['reason'])
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())

    def test_missing_or_different_asset_stops_before_anything_is_written(self):
        (self.f.fixture.source.root / 'mfc42.dll').write_bytes(DLL_DATA + b'tampered')
        before = self.protected()
        _, report, output, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['stage'], 'one-pass-precheck')
        self.assertIn('dll-asset:mfc42-prefix:hash-mismatch', report['reason'])
        self.assertIn('mfc42.dll', output)
        self.assertEqual(commands, [])
        self.assertFalse(self.game_compat.exists())
        self.assertEqual(before, self.protected())

    def test_dll_asset_changed_after_confirmation_stops_by_name(self):
        real = one_pass._dlls
        calls = []

        def drifting(*args):
            calls.append(1)
            values = real(*args)
            # The confirmed values read it once; every later read is after the confirmation.
            return values if len(calls) <= 1 else [{**values[0], 'measured': None}]

        self.initialize()
        with patch.object(one_pass, '_dlls', side_effect=drifting):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'fixed-values-changed:dlls')
        self.assertIn('prefixに入れるDLL', report['next_step'])
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())

    def exclusive_create(self, effect):
        """Wraps os.open only for the O_EXCL creation of the destination; other opens are untouched."""
        real_open = os.open

        def wrapped(path, flags, *args, **kwargs):
            if path == 'mfc42.dll' and flags & os.O_EXCL:
                return effect(real_open, path, flags, *args, **kwargs)
            return real_open(path, flags, *args, **kwargs)

        return patch.object(prefix_dll.os, 'open', side_effect=wrapped)

    def test_failed_creation_leaves_nothing_and_is_retried(self):
        self.initialize()

        def refused(real_open, *args, **kwargs):
            raise OSError(1, 'Operation not permitted')

        with self.exclusive_create(refused):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['reason'], 'prefix-dll-failed')
        self.assertIn('段階: create', report['next_step'])
        (failed,) = self.dll_records()
        self.assertEqual((failed['phase'], failed['error']['check'], failed['error']['errno'], failed['file_identity']),
                         ('failed', 'create', 1, None))
        self.assertEqual((self.leftovers(), (self.wow64() / 'mfc42.dll').exists()), ([], False))
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual([item['phase'] for item in self.dll_records()], ['failed', 'present-verified'])
        self.assertEqual(self.dll_records()[1]['resumed_from'], failed['record_id'])

    def test_destination_appearing_right_before_creation_is_kept(self):
        self.initialize()
        intruder = GAME['synthetic_pe'](extra=b'appeared concurrently')

        def racing(real_open, *args, **kwargs):
            (self.wow64() / 'mfc42.dll').write_bytes(intruder)
            return real_open(*args, **kwargs)

        with self.exclusive_create(racing):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual((self.wow64() / 'mfc42.dll').read_bytes(), intruder)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual((self.dll_records()[0]['phase'], self.dll_records()[0]['error']['errno']), ('failed', 17))

    def test_case_variant_appearing_right_before_creation_stops(self):
        self.initialize()
        real_directory = prefix_dll.PrefixDllSession._directory
        calls = []

        def directory(session, fd):
            calls.append(1)
            if len(calls) == 2:
                (self.wow64() / 'MFC42.DLL').write_bytes(b'appeared concurrently')
            return real_directory(session, fd)

        with patch.object(prefix_dll.PrefixDllSession, '_directory', directory):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(self.dll_records()[0]['phase'], 'failed')
        self.assertEqual(sorted(p.name for p in self.wow64().iterdir() if p.name.lower() == 'mfc42.dll'), ['MFC42.DLL'])
        self.assertEqual(self.leftovers(), [])

    def test_profile_changed_since_initialization_stops_before_the_dll_is_written(self):
        self.initialize()
        self.config['game_preparation']['profiles'][0]['title'] = 'Edited after initialization'
        before = self.protected()
        _, report, _, commands = self.run_detail('12\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual((report['stage'], report['reason']), ('profile-selection', 'game profile changed since initialization'))
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())
        self.assertEqual((commands, self.dll_records()), ([], []))
        self.assertEqual(before, self.protected())

    def test_unclear_process_view_stops_before_the_dll_is_written(self):
        self.initialize()
        with patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(report['stage'], 'prefix-dll')
        self.assertIn('uninspected:target-process-view-not-clear', report['reason'])
        self.assertEqual((self.dll_records(), (self.wow64() / 'mfc42.dll').exists()), ([], False))

    def test_a_running_game_is_the_reason_shown_even_without_the_asset(self):
        self.initialize()
        (self.f.fixture.source.root / 'mfc42.dll').unlink()
        with patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['stage'], 'prefix-dll', report)
        self.assertIn('uninspected:target-process-view-not-clear', report['reason'])
        self.assertNotIn('dll-asset', report['reason'])

    def test_reason_never_carries_the_os_error_text(self):
        self.initialize()
        with patch.object(prefix_dll, '_pe_of', side_effect=PermissionError(13, 'denied', '/private/secret/path')):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('x86 system directory not confirmed: PermissionError', report['reason'])
        self.assertNotIn('/private/secret/path', json.dumps(report))

    def test_killed_before_creation_leaves_nothing_and_copies_again(self):
        self.initialize()
        with patch.object(prefix_dll, 'load_asset', side_effect=Killed()), self.assertRaises(Killed):
            self.run_detail('12\n1\n1\n')
        (interrupted,) = self.dll_records()
        self.assertEqual(interrupted['phase'], 'planned')
        self.assertEqual((self.leftovers(), (self.wow64() / 'mfc42.dll').exists()), ([], False))
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(report['steps'][0]['plan']['action'], 'install')
        self.assertEqual((self.wow64() / 'mfc42.dll').read_bytes(), DLL_DATA)

    def test_signals_are_blocked_only_between_creation_and_its_record(self):
        import signal
        self.initialize()
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        seen = []

        def observe(real_open, *args, **kwargs):
            seen.append(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
            return real_open(*args, **kwargs)

        with self.exclusive_create(observe):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(len(seen), 1)
        self.assertTrue({signal.SIGINT, signal.SIGTERM} <= seen[0])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), before)

    def saves_failing_at(self, number, effect):
        real_save = prefix_dll.PrefixDllSession._save
        calls = []

        def counted(session):
            calls.append(1)
            if len(calls) == number:
                raise effect
            return real_save(session)

        return patch.object(prefix_dll.PrefixDllSession, '_save', counted)

    def test_killed_between_creation_and_its_record_leaves_an_empty_file_that_stops(self):
        self.initialize()
        with self.saves_failing_at(2, Killed()), self.assertRaises(Killed):
            self.run_detail('12\n1\n1\n')
        placed = self.wow64() / 'mfc42.dll'
        self.assertEqual(placed.read_bytes(), b'')
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['file_identity']), ('planned', None))
        before = placed.stat()
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        after = placed.stat()
        self.assertEqual((placed.read_bytes(), after.st_ino, after.st_mtime_ns), (b'', before.st_ino, before.st_mtime_ns))
        self.assertEqual(len(self.dll_records()), 1)

    def test_identity_failure_right_after_creation_is_not_a_failed_copy(self):
        self.initialize()
        real_fstat = os.fstat
        created = []

        def opened(real_open, *args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            created.append(descriptor)
            return descriptor

        def fstat(fd, *args, **kwargs):
            if created and fd == created[0] and len(created) == 1:
                created.append('failed')
                raise OSError(5, 'Input/output error')
            return real_fstat(fd, *args, **kwargs)

        with self.exclusive_create(opened), patch.object(prefix_dll.os, 'fstat', side_effect=fstat):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('空のファイルが残っている可能性', report['next_step'])
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['file_identity'], saved['error']['check'], saved['error']['errno']),
                         ('planned', None, 'record-created', 5))
        self.assertEqual((self.wow64() / 'mfc42.dll').read_bytes(), b'')
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('after planned', report['reason'])
        self.assertEqual(len(self.dll_records()), 1)
        self.assertEqual((self.wow64() / 'mfc42.dll').read_bytes(), b'')

    def test_failed_record_of_the_creation_keeps_the_file_and_the_created_phase(self):
        self.initialize()
        with self.saves_failing_at(2, OSError(28, 'No space left on device')):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['error']['check'], saved['error']['errno']), ('created', 'record-created', 28))
        placed = self.wow64() / 'mfc42.dll'
        self.assertTrue(placed.exists())
        self.assertEqual(saved['file_identity']['inode'], placed.stat().st_ino)
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('partial-file-of-the-previous-run-operator-recovery', report['reason'])

    def test_killed_after_writing_is_accepted_without_copying_again(self):
        self.initialize()
        with patch.object(prefix_dll.PrefixDllSession, '_post', side_effect=Killed()), self.assertRaises(Killed):
            self.run_detail('12\n1\n1\n')
        placed = self.wow64() / 'mfc42.dll'
        self.assertEqual((placed.read_bytes(), placed.stat().st_nlink), (DLL_DATA, 1))
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['file_identity']['inode']), ('created', placed.stat().st_ino))
        inode = placed.stat().st_ino
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual((report['steps'][0]['plan']['action'], report['steps'][0]['plan']['reason']),
                         ('skip', 'placed-before-the-record-was-completed'))
        self.assertEqual((placed.stat().st_ino, len(self.dll_records())), (inode, 1))

    def test_partial_file_of_an_interrupted_write_is_never_written_again(self):
        self.initialize()
        real_write = prefix_dll._write_all

        def half_then_killed(fd, data):
            real_write(fd, data[:len(data) // 2])
            raise Killed()

        with patch.object(prefix_dll, '_write_all', side_effect=half_then_killed), self.assertRaises(Killed):
            self.run_detail('12\n1\n1\n')
        placed = self.wow64() / 'mfc42.dll'
        partial = placed.read_bytes()
        self.assertEqual(partial, DLL_DATA[:len(DLL_DATA) // 2])
        self.assertEqual(self.dll_records()[0]['phase'], 'created')
        before = placed.stat()
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('partial-file-of-the-previous-run-operator-recovery', report['reason'])
        self.assertIn('回復の手順', report['next_step'])
        after = placed.stat()
        self.assertEqual((placed.read_bytes(), after.st_ino, after.st_mtime_ns), (partial, before.st_ino, before.st_mtime_ns))
        self.assertEqual(len(self.dll_records()), 1)
        # The operator removes the partial file; the next run creates it anew.
        placed.unlink()
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(placed.read_bytes(), DLL_DATA)
        self.assertEqual([item['phase'] for item in self.dll_records()], ['created', 'present-verified'])

    def test_failure_after_creation_keeps_the_file_and_the_created_phase(self):
        self.initialize()
        real_read = prefix_dll._read_all

        def differs(fd, size):
            return b'x' + real_read(fd, size)[1:]

        with patch.object(prefix_dll, '_read_all', side_effect=differs):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['error']['check']), ('created', 'read-back'))
        self.assertIn('段階: read-back', report['next_step'])
        self.assertEqual((self.wow64() / 'mfc42.dll').read_bytes(), DLL_DATA)
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(report['steps'][0]['plan']['action'], 'skip')

    def test_destination_that_is_not_the_recorded_file_stops_the_post_inspection(self):
        self.initialize()
        real_stat = os.stat

        calls = []

        def other_inode(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == 'mfc42.dll' and kwargs.get('dir_fd') is not None:
                calls.append(1)
                # The first lookup is the post-inspection's own read; the second is the identity check of the name.
                if len(calls) == 2:
                    values = list(info)
                    values[1] += 1  # st_ino
                    return os.stat_result(values)
            return info

        with patch.object(prefix_dll.os, 'stat', side_effect=other_inode):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['error']['check']), ('created', 'post-inspection'))

    def test_unsupported_creation_fails_without_another_placement(self):
        self.initialize()

        def unsupported(real_open, *args, **kwargs):
            raise OSError(95, 'Operation not supported')

        with self.exclusive_create(unsupported):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual((self.dll_records()[0]['phase'], self.dll_records()[0]['error']['errno']), ('failed', 95))
        self.assertEqual((self.leftovers(), (self.wow64() / 'mfc42.dll').exists()), ([], False))

    def test_asset_changed_in_the_shared_folder_stops_before_creation(self):
        self.initialize()
        real_load = prefix_dll.load_asset

        def changed(root, spec):
            (self.f.fixture.source.root / 'mfc42.dll').write_bytes(DLL_DATA + b'changed')
            return real_load(root, spec)

        with patch.object(prefix_dll, 'load_asset', side_effect=changed):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual((self.dll_records()[0]['phase'], self.dll_records()[0]['error']['check']), ('failed', 'read-asset'))
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())

    def write_legacy_record(self, record_id, **changes):
        """A record exactly as 0.29.0 wrote it (fixed field set and values), for the initialized game."""
        with PrivateStore(self.f.store_root) as store:
            (item,) = store.inventory()['game_prefixes']
        spec_item = next(r for r in self.config['game_preparation']['recipes'] if r['dependency_id'] == 'mfc42-prefix')
        wow64 = self.wow64().stat()
        legacy = {'schema_version': 1, 'tool_version': '0.29.0', 'scope': 'registered-game-prefix-dll',
                  'record_id': record_id, 'created_ns': 1700000000000000000, 'app_id': item['app_id'],
                  'trial_id': item['trial_id'], 'dependency_id': 'mfc42-prefix', 'recipe_revision': 1,
                  'recipe_digest': one_pass.digest_json(spec_item), 'asset_sha256': spec_item['asset']['expected_sha256'],
                  'input_digest': '0' * 64, 'destination': 'syswow64', 'name': 'mfc42.dll',
                  'directory': {'device': wow64.st_dev, 'inode': wow64.st_ino}, 'file_identity': None, 'phase': 'failed',
                  'resumed_from': None, 'error': {'check': 'copy', 'error_class': 'OSError', 'errno': 95},
                  'preparation_complete': False}
        legacy.update(changes)
        with PrivateStore(self.f.store_root) as store:
            lock = __import__('hashlib').sha256(str(self.game_compat).encode()).hexdigest()
            with store.locked(lock):
                store.write_record(prefix_dll.RECORDS, record_id + '.json', legacy)

    def test_failed_record_of_0_29_0_resumes_with_a_new_creation(self):
        self.initialize()
        self.write_legacy_record('prefixdll-' + '1' * 32)
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(report['steps'][0]['plan']['action'], 'install')
        self.assertEqual(report['steps'][0]['plan']['previous_record']['error']['errno'], 95)
        self.assertEqual((self.wow64() / 'mfc42.dll').read_bytes(), DLL_DATA)

    def test_linked_record_of_0_29_0_is_accepted_or_stops_when_the_file_is_gone(self):
        self.initialize()
        (self.wow64() / 'mfc42.dll').write_bytes(DLL_DATA)
        inode = (self.wow64() / 'mfc42.dll').stat().st_ino
        self.write_legacy_record('prefixdll-' + '2' * 32, phase='linked', error=None,
                                 file_identity={'device': (self.wow64() / 'mfc42.dll').stat().st_dev, 'inode': inode})
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', report)
        self.assertEqual(report['steps'][0]['plan']['action'], 'skip')
        (self.wow64() / 'mfc42.dll').unlink()
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('absent after linked', report['reason'])

    def test_write_failure_after_creation_keeps_the_file_and_stops_next_time(self):
        self.initialize()
        with patch.object(prefix_dll, '_write_all', side_effect=OSError(28, 'No space left on device')):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('書きかけの可能性', report['next_step'])
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['error']['check'], saved['error']['errno']), ('created', 'write', 28))
        _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('operator-recovery:incompatible', report['reason'])
        self.assertEqual(report['steps'][0]['plan']['destination_file']['size'], 0)
        self.assertEqual(report['steps'][0]['plan']['destination_file']['identity'], saved['file_identity'])

    def test_process_view_changing_before_creation_creates_nothing(self):
        self.initialize()
        real_guard = prefix_dll.PrefixDllSession._guard
        calls = []

        def guard(session):
            calls.append(1)
            if len(calls) == 2:
                raise prefix_dll.Invalid("target process view not clear")
            return real_guard(session)

        with patch.object(prefix_dll.PrefixDllSession, '_guard', guard):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertIn('ファイルは作っていません', report['next_step'])
        (saved,) = self.dll_records()
        self.assertEqual((saved['phase'], saved['error']['check']), ('failed', 'create'))
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())

    def test_binding_plan_requires_the_dll_in_the_prefix(self):
        record, digest = self.initialize()
        self.install_dependency(record, digest)
        self.assertEqual(self.binding_plan(record, digest).blockers, ('dependency-not-verified:mfc42-prefix',))
        (self.wow64() / 'mfc42.dll').write_bytes(DLL_DATA)
        self.assertEqual(self.binding_plan(record, digest).blockers, ())

    def test_replaced_syswow64_is_refused_right_before_creation(self):
        self.initialize()
        real_directory = prefix_dll.PrefixDllSession._directory
        calls = []

        def directory(session, fd):
            calls.append(1)
            if len(calls) == 2:
                moved = self.wow64().with_name('syswow64-moved')
                self.wow64().rename(moved)
                self.wow64().mkdir()
            return real_directory(session, fd)

        with patch.object(prefix_dll.PrefixDllSession, '_directory', directory):
            _, report, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(report['status'], 'stopped', report)
        self.assertEqual(self.dll_records()[0]['phase'], 'failed')
        self.assertEqual(list(self.wow64().iterdir()), [])
        self.assertFalse(self.wow64().with_name('syswow64-moved').joinpath('mfc42.dll').exists())

# Only the one-pass tests run here; the inherited fixtures' own tests run in their modules.
for _name in dir(GAME['GamePrefixTests']):
    if _name.startswith('test_') and _name not in OnePassTests.__dict__:
        setattr(OnePassTests, _name, None)
# The DLL tests add their own; the one-pass tests without a DLL keep running in OnePassTests.
for _name in dir(OnePassTests):
    if _name.startswith('test_') and _name not in PrefixDllOnePassTests.__dict__:
        setattr(PrefixDllOnePassTests, _name, None)


if __name__ == '__main__':
    unittest.main()
