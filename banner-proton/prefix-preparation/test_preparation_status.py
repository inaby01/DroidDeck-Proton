#!/usr/bin/env python3
"""Operational entry 2: the read-only game status agrees with what menu 1 (one-pass) then does."""

import dataclasses
import io
import json
import os
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ONE = runpy.run_path(str(HERE / 'test_preparation_one_pass.py'))
FOLDER = runpy.run_path(str(HERE / 'test_preparation_folder_reads.py'))
import preparation_binding as binding
import preparation_dependency_install as dep
import preparation_recheck as recheck
import preparation_status as status
import preparation_store as store_module
from preparation_store import PrivateStore

WRITTEN = {'prefix-dll': 'prefix-dll:mfc42-prefix', 'softdenchi-silent': 'softdenchi-silent', 'binding': 'binding'}


def own_tests_only(cls):
    """The fixture classes' own tests already run in their modules."""
    for base in cls.__mro__[1:]:
        for name in vars(base):
            if name.startswith('test') and name not in vars(cls):
                setattr(cls, name, None)
    return cls


class StatusMixin:
    def status(self, home=None):
        output = io.StringIO()
        code, name = status.interactive_status(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
            output_stream=output, environment=self.environment, steam=self.f.steam, settings=self.f.settings,
            home=home or self.home, runtime_root=self.f.root, recipe=self.recipe, silent_launch=self.silent)
        report = json.loads(Path(name).read_bytes() if Path(name).is_absolute() else
                            (self.f.fixture.source.root / name).read_bytes())
        return code, report, output.getvalue()

    def entry(self, report, key='42'):
        (found,) = [item for item in report['games'] if item['app_id'] == key]
        return found

    def state(self):
        """Every byte, mtime and inode outside the result folder that the status check could touch."""
        result = {}
        roots = [self.home, self.f.steam, self.f.settings, self.f.exe.parent]
        for root in roots:
            for path in [root, *sorted(root.rglob('*'))]:
                info = path.lstat()
                result[str(path)] = (info.st_mode, info.st_size, info.st_mtime_ns, info.st_ino,
                                     path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        return result

    def agrees(self, entry, report):
        """The status check's next step is what menu 1 then did."""
        expected = entry['next']
        if expected['next'] == 'stop':
            self.assertEqual(report['status'], 'stopped', report)
            self.assertEqual((report['stage'], report['reason']), (expected['stage'], expected['reason']))
            return
        self.assertEqual(report['status'], 'ready-to-launch', report)
        done = [WRITTEN[step['step']] for step in report['steps']
                if step['step'] in WRITTEN and not step.get('evaluated') and
                (step['step'] != 'prefix-dll' or 'record' in step)]
        self.assertEqual(done, expected['actions'])
        self.assertEqual(expected['next'] == 'ready', not report['binding_written'])


@own_tests_only
class StatusTests(StatusMixin, ONE['OnePassTests']):
    def test_no_private_store_reports_no_prepared_games(self):
        other = self.f.root / 'empty-home'
        other.mkdir(mode=0o700)
        code, report, output = self.status(home=other)
        self.assertEqual((code, report['status'], report['games']), (2, 'no-prepared-games', []))
        self.assertIn('準備したゲームはありません', output)
        self.assertFalse((other / '.local/state').exists())

    def test_initialized_game_continues_and_menu_1_does_the_same(self):
        self.initialize()
        before = self.state()
        _, report, output = self.status()
        self.assertEqual(before, self.state())
        entry = self.entry(report)
        self.assertEqual(entry['next'], {'next': 'continue', 'actions': ['softdenchi-silent', 'binding']})
        self.assertEqual(entry['assignment']['kind'], 'none')
        self.assertIn('1で続きから進めます（ソフト電池を画面なしで入れる・準備用Protonに割り当てる）', output)
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_prepared_game_is_ready_and_nothing_is_written(self):
        self.run_menu('1\n1\n1\n1\n')
        locks = sorted(os.listdir(self.f.store_root / 'locks')) if (self.f.store_root / 'locks').exists() else []
        before = self.state()
        with patch.object(store_module.PrivateStore, 'locked', side_effect=AssertionError('no store lock')), \
                patch.object(binding, 'droiddeck_lock', side_effect=AssertionError('no settings lock')), \
                patch('subprocess.Popen', side_effect=AssertionError('no process')):
            _, report, output = self.status()
        self.assertEqual(before, self.state())
        self.assertEqual(locks, sorted(os.listdir(self.f.store_root / 'locks')) if (self.f.store_root / 'locks').exists() else [])
        entry = self.entry(report)
        self.assertEqual(entry['assignment']['kind'], 'this-slot')
        self.assertEqual(entry['next'], {'next': 'ready', 'actions': []})
        self.assertIn('起動できます', output)
        self.assertEqual([item['state'] for item in entry['dependencies']], ['present-verified'])
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_bound_game_with_a_missing_file_stops_in_both(self):
        self.use_folder_dependency()
        dll = self.f.exe.parent / 'mfc42.dll'
        dll.write_bytes(ONE['GAME']['DLL'])
        self.run_menu('1\n1\n1\n')
        dll.unlink()
        _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next']['reason'], 'binding-blocked:dependency-not-verified:mfc42-game-folder')
        self.assertIn('1（新しいゲームを準備）はここで止まります', output)
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_missing_installer_or_low_capacity_stops_in_both(self):
        self.initialize()
        (self.f.fixture.source.root / 'sdrt-fixture.exe').unlink()
        _, report, _ = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next']['stage'], 'softdenchi-silent')
        self.assertIn('dependency-plan-blocked:', entry['next']['reason'])
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)
        self.use_installer(self.data)
        self.pin_silent()
        with patch.object(dep, 'RESERVE', 1 << 60):
            _, report, _ = self.status()
            entry = self.entry(report)
            self.assertIn('insufficient', entry['next']['reason'])
            _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_state_json_alone_differing_is_partial_and_menu_1_stops(self):
        self.run_menu('1\n1\n1\n1\n')
        state_path = self.f.settings / 'state.json'
        state = json.loads(state_path.read_text())
        state['picked'] = [app for app in state['picked'] if app != '42']
        state_path.write_text(json.dumps(state))
        _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual((entry['assignment']['kind'], entry['assignment']['differing_files']), ('partial', ['state.json']))
        self.assertIn('一部だけ（このバンドルの準備用Protonと食い違うファイル: state.json）', output)
        self.assertEqual(entry['next']['reason'], 'binding-partially-applied')
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def other_proton(self, games_entry=True):
        config = self.f.steam / 'config/config.vdf'
        config.write_bytes(binding.patch_game_mapping(config.read_bytes(), '42', 'Other-Proton-Tool'))
        other = {'valve': True, 'dir': 'proton_other'}
        games = json.loads((self.f.settings / 'games.json').read_text())
        if games_entry:
            games['games']['42'] = other
        (self.f.settings / 'games.json').write_text(json.dumps(games))
        state_path = self.f.settings / 'state.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        state.setdefault('games_applied', {})['42'] = other
        state_path.write_text(json.dumps(state))

    def test_game_of_another_proton_is_out_of_scope(self):
        self.initialize()
        self.other_proton()
        _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual((entry['assignment']['kind'], entry['assignment']['current_tool']), ('other', 'Other-Proton-Tool'))
        self.assertEqual(entry['next'], {'next': 'out-of-scope'})
        self.assertIn('別のProton（Other-Proton-Tool）', output)
        self.assertIn('このバンドルの対象外', output)
        self.assertNotIn('割り当て直し', output)
        self.assertNotIn('依存:', output)
        _, _, menu_output, _ = self.run_menu('1\nq\n')
        self.assertIn('今の割り当て: Other-Proton-Tool', menu_output)

    def test_disagreeing_files_of_another_proton_are_shown_as_such(self):
        self.initialize()
        self.other_proton(games_entry=False)
        _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['assignment']['kind'], 'other-disagreeing')
        self.assertIn('games.json', entry['assignment']['differing_files'])
        self.assertIn('3つのファイルで食い違っています', output)
        self.assertNotEqual(entry['next']['next'], 'out-of-scope')

    def test_running_game_cannot_be_checked(self):
        self.initialize()
        with patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
            _, report, output = self.status()
        self.assertEqual(self.entry(report)['next'], {'next': 'undetermined', 'reason': 'game-running'})
        self.assertIn('確認できません（動作中または変化中）', output)

    def test_two_softdenchi_dependencies_are_satisfied_by_one_installation(self):
        recipes = self.config['game_preparation']['recipes']
        recipes.append({**next(item for item in recipes if item['dependency_id'] == 'softdenchi-runtime'),
                        'dependency_id': 'softdenchi-runtime-alias'})
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime', 'softdenchi-runtime-alias']
        self.initialize()
        _, report, _ = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next'], {'next': 'continue', 'actions': ['softdenchi-silent', 'binding']})
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_running_game_at_resume_asks_to_end_it(self):
        self.initialize()
        with patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
            _, menu, _, _ = self.run_menu('1\n1\n')
        self.assertEqual(menu['status'], 'stopped')
        self.assertIn('ゲームとWineを終了してから、もう一度 1 を実行', menu['next_step'])

    def test_malformed_state_entry_stops_only_that_game(self):
        self.initialize()
        state_path = self.f.settings / 'state.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        state['games_applied'] = {'42': 'not-an-object'}
        state_path.write_text(json.dumps(state))
        code, report, output = self.status()
        self.assertEqual((code, report['status']), (2, 'reported'))
        self.assertEqual(self.entry(report)['next']['reason'], 'unreadable')
        self.assertIn('照合できません: status-assignment', output)

    def test_store_without_records_says_so(self):
        self.f.store_root.parent.mkdir(parents=True, exist_ok=True)
        with patch.object(status, '_game_records', return_value=([], 0)):
            _, report, output = self.status()
        self.assertEqual((report['status'], report['games']), ('no-prepared-games', []))
        self.assertIn('初期化の記録がありません', output)

    def test_unplaced_slot_or_missing_payload_leaves_dependencies_undetermined(self):
        self.initialize()
        slot = self.f.steam / 'compatibilitytools.d'
        moved = self.f.root / 'moved-tools'
        slot.rename(moved)
        slot.mkdir(mode=0o700)
        try:
            _, report, output = self.status()
        finally:
            slot.rmdir()
            moved.rename(slot)
        self.assertEqual(report['global']['slot'], 'absent')
        self.assertIn('まだ置かれていません（先に3）', output)
        entry = self.entry(report)
        self.assertEqual(entry['next'], {'next': 'undetermined', 'reason': 'slot-absent'})
        self.assertEqual((entry['assignment']['kind'], entry['assignment']['current_tool']), ('undetermined', None))
        archive = self.f.fixture.source.archive
        archive.rename(archive.with_suffix('.moved'))
        try:
            _, report, output = self.status()
        finally:
            archive.with_suffix('.moved').rename(archive)
        self.assertEqual(report['global']['payload'], 'unverified')
        self.assertIn('配布物を照合できません', output)
        self.assertEqual(self.entry(report)['next']['next'], 'undetermined')

    def test_slot_mismatch_keeps_the_verified_payload_and_bound_games_stay_in_scope(self):
        self.run_menu('1\n1\n1\n1\n')
        import preparation_payload as payload
        with patch.object(payload, 'verify_fex_runtime_tree',
                          side_effect=status.require.__globals__['Invalid']('existing installation differs from approved generated trees')):
            _, report, output = self.status()
        self.assertEqual((report['global']['payload'], report['global']['slot']), ('verified', 'unverified'))
        self.assertIsNotNone(report['global']['directory'])
        self.assertIn('このバンドルの準備用Protonを照合できません（existing installation differs', output)
        self.assertNotIn('配布物を照合できません', output)
        entry = self.entry(report)
        self.assertEqual(entry['assignment']['kind'], 'undetermined')
        self.assertTrue(entry['assignment']['current_tool'])
        self.assertEqual(entry['next'], {'next': 'undetermined', 'reason': 'slot-unverified'})
        self.assertNotIn('対象外', output)
        archive = self.f.fixture.source.archive
        archive.rename(archive.with_suffix('.moved'))
        try:
            _, report, output = self.status()
        finally:
            archive.with_suffix('.moved').rename(archive)
        entry = self.entry(report)
        self.assertEqual((entry['assignment']['kind'], entry['next']['next']), ('undetermined', 'undetermined'))
        self.assertIn('判定できません', output)
        self.assertNotIn('対象外', output)

    def test_input_changing_during_the_check_is_shown_as_not_checkable(self):
        self.initialize()
        with patch.object(status, 'evaluate_resume',
                          side_effect=status.require.__globals__['Invalid']('input changed during read (mtime_ns,ctime_ns)')):
            _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next'], {'next': 'undetermined', 'reason': 'changing'})
        self.assertIn('確認できません（動作中または変化中）', output)

    def test_record_problems_are_shown_and_the_next_game_follows(self):
        self.initialize()
        with PrivateStore(self.f.store_root) as store:
            listed = store.inventory()['game_prefixes']
        self.assertEqual(len(listed), 1)
        games = json.loads(self.f.added.read_bytes())
        self.f.added.write_text(json.dumps([game for game in games if game['appid'] != 42]))
        _, report, output = self.status()
        self.assertEqual(self.entry(report)['next'], {'next': 'not-listed', 'reason': 'registration-missing'})
        self.assertIn('（登録が見つかりません）', output)
        self.f.added.write_text(json.dumps(games))
        with patch.object(status, '_game_records', return_value=([{**listed[0], 'status': 'failed'}], 1)):
            _, report, output = self.status()
        self.assertEqual(self.entry(report)['next'], {'next': 'stop', 'stage': 'resume-state', 'reason': 'initialization-failed'})
        self.assertIn('読めない初期化記録が1件', output)
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.assertEqual(menu['status'], 'ready-to-launch')
        several = ([listed[0], listed[0]], 0)
        with patch.object(status, '_game_records', return_value=several):
            _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['record'], 'several')
        self.assertIn('同じIDの記録が複数', output)
        with patch.object(ONE['one_pass'], '_game_records', return_value=several):
            _, menu, _, _ = self.run_menu('1\n1\n')
        self.agrees(entry, menu)
        profiles = self.config['game_preparation']['profiles']
        self.config['game_preparation']['profiles'] = [{**profiles[0], 'profile_id': 'other-profile'}]
        _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next']['stage'], 'profile-selection')
        _, menu, _, _ = self.run_menu('1\n1\n')
        self.agrees(entry, menu)

    def test_archive_is_read_once_and_the_inventory_is_only_for_game_prefixes(self):
        self.initialize()
        with patch.object(recheck, 'inspect_archive_from_folder', wraps=recheck.inspect_archive_from_folder) as loose, \
                patch.object(recheck, 'inspect_archive', wraps=recheck.inspect_archive) as strict:
            _, report, _ = self.status()
        self.assertEqual(self.entry(report)['next']['next'], 'continue')
        self.assertEqual((loose.call_count, strict.call_count), (1, 0))
        with patch.object(recheck, 'inspect_archive_from_folder', wraps=recheck.inspect_archive_from_folder) as loose:
            _, menu, _, _ = self.run_menu('1\n1\nq\n')
        self.assertIsNone(menu)
        self.assertEqual(loose.call_count, 1)
        inventory = recheck.read_payload_inventory(self.config, self.f.fixture.source.root)
        source, _, games = ONE['GAME']['DEP']['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
        common = {'config': self.config, 'directory': self.f.fixture.source.root, 'renderer': self.f.fixture.options['renderer'],
                  'source': source, 'games': games, 'steam': self.f.steam, 'settings': self.f.settings, 'home': self.home,
                  'environment': self.environment, 'runtime_root': self.f.root}
        with self.assertRaisesRegex(status.require.__globals__['Invalid'], 'probe trials read their archive themselves'):
            recheck.plan_recheck(record=self.trial_record, record_sha256=self.trial_digest, inventory=inventory, **common)
        record, digest = self.game_record()
        other = dataclasses.replace(inventory, archive_sha512='0' * 128)
        with self.assertRaisesRegex(status.require.__globals__['Invalid'], 'payload inventory differs'):
            recheck.plan_recheck(record=record, record_sha256=digest, records='game-prefixes', inventory=other, **common)
        self.assertEqual(recheck.plan_recheck(record=record, record_sha256=digest, records='game-prefixes', inventory=inventory,
                                              **common).inventory, inventory)

    def game_record(self):
        with PrivateStore(self.f.store_root) as store:
            (item,) = store.inventory()['game_prefixes']
            return store.read_record('game-prefixes', item['trial_id'] + '.json')

    def test_one_unreadable_game_does_not_stop_the_others(self):
        self.initialize()
        with patch.object(status, 'evaluate_resume', side_effect=status.require.__globals__['Invalid']('fixture failure')):
            code, report, output = self.status()
        self.assertEqual(code, 2)
        self.assertEqual(report['status'], 'reported')
        self.assertEqual(self.entry(report)['error']['reason'], 'fixture failure')
        self.assertIn('照合できません: status-evaluation / fixture failure', output)


@own_tests_only
class EntryTests(StatusMixin, ONE['OnePassTests']):
    """The operational entry screen (design 3 and 7)."""

    def test_other_input_on_either_screen_cancels_without_writing(self):
        self.initialize()
        before = self.state()
        for answer in ('', 'q\n', '12\n', '5\n', 'x\n', '4\n', '4\nq\n', '4\n99\n', '4\nx\n'):
            with self.subTest(answer=answer):
                status_code, report, output = self.menu(answer)
                self.assertEqual((status_code, report), (0, None))
                self.assertTrue(output.startswith('1. 新しいゲームを準備'), output)
                self.assertTrue(output.endswith('取り消しました。\n'), output)
                self.assertEqual('詳細メニュー（番号は従来どおり）' in output, answer.startswith('4'))
        self.assertEqual(before, self.state())

    def test_entry_2_is_the_status_check(self):
        self.initialize()
        before = self.state()
        code, report, _, _ = self.run_menu('2\n')
        self.assertEqual(before, self.state())
        self.assertEqual((code, report['mode']), (2, 'game-status-result'))
        self.assertEqual(self.entry(report)['next']['actions'], ['softdenchi-silent', 'binding'])

    def test_entry_3_uses_an_ordinary_game_and_observes_the_placed_slot(self):
        self.initialize()
        before = self.state()
        code, report, output = self.menu('3\n1\n')
        self.assertEqual(before, self.state())
        self.assertEqual((code, report['mode']), (2, 'static-matching-tool-observed'), output)
        self.assertEqual(report['confirmation_registration']['app_id'], '42')
        self.assertIn('1. Example  [ID 42]', output)
        self.assertNotIn('ID 43', output)

    def test_entry_1_is_the_one_pass_preparation_with_operational_wording(self):
        self.use_installer(ONE['DEP']['installer'](silent_noop=True))
        self.pin_silent()
        _, report, output, _ = self.run_menu('1\n1\n1\n1\nq\n')
        self.assertEqual(report['mode'], 'one-pass-game-preparation-result')
        self.assertEqual(report['reason'], 'installation-declined')
        self.assertIn('もう一度 1 を実行', report['next_step'])
        self.assertIn('詳細メニューの8を使ってください', output)
        self.assertNotIn('メニュー8', output.replace('詳細メニューの8', ''))

    def test_embedded_script_shows_the_entry_screen_and_the_detailed_menu(self):
        import subprocess
        script = self.f.fixture.source.root / 'prepare.sh'
        script.write_text(ONE['GAME']['DEP']['TRIAL']['BASE']['selection'].selection_script(self.config))
        for answer, expected in (('q\n', '1. 新しいゲームを準備'), ('4\nq\n', '12. 新しいゲームを1回で準備')):
            result = subprocess.run(['bash', str(script)], input=answer, text=True, capture_output=True,
                                    env={**os.environ, 'HOME': str(self.home)}, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(expected, result.stdout)
        script.unlink()


@own_tests_only
class DllStatusTests(StatusMixin, ONE['PrefixDllOnePassTests']):
    def test_initialized_game_needs_the_dll_and_menu_1_places_it(self):
        self.initialize()
        _, report, output = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next']['actions'], ['prefix-dll:mfc42-prefix', 'softdenchi-silent', 'binding'])
        self.assertIn('DLL（mfc42.dll）を入れる', output)
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_placed_dll_with_a_missing_asset_stops_before_writing_in_both(self):
        self.run_menu('1\n1\n1\n1\n')
        (self.f.fixture.source.root / 'mfc42.dll').unlink()
        _, report, _ = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next']['stage'], 'one-pass-precheck')
        self.assertTrue(entry['next']['reason'].startswith('dll-asset:mfc42-prefix:'))
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)

    def test_entry_1_new_and_resumed_pass_while_asset_timestamps_change_on_every_read(self):
        with FOLDER['touching_asset_folder'](self.f.fixture.source.root) as touched:
            _, report, output, _ = self.run_menu('1\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', output)
        archive = self.f.fixture.source.archive.name
        self.assertTrue({archive, 'mfc42.dll', 'sdrt-fixture.exe'} <= set(touched), touched)

    def test_resume_passes_while_asset_timestamps_change_and_the_probe_recheck_stays_strict(self):
        self.initialize()
        with FOLDER['touching_asset_folder'](self.f.fixture.source.root) as touched:
            _, report, output, _ = self.run_menu('1\n1\n1\n')
            self.assertEqual(report['status'], 'ready-to-launch', output)
            self.assertIn(self.f.fixture.source.archive.name, touched)
            source, _, games = ONE['GAME']['DEP']['TRIAL']['BASE']['selection'].registration_catalog(self.environment)
            with self.assertRaisesRegex(status.require.__globals__['Invalid'], r'input changed during read \(mtime_ns'):
                recheck.plan_recheck(record=self.trial_record, record_sha256=self.trial_digest, config=self.config,
                    directory=self.f.fixture.source.root, renderer=self.f.fixture.options['renderer'], source=source,
                    games=games, steam=self.f.steam, settings=self.f.settings, home=self.home, environment=self.environment,
                    runtime_root=self.f.root)

    def test_a_binding_that_cannot_follow_stops_before_the_dll_and_softdenchi_are_written(self):
        self.use_folder_dependency()
        self.config['game_preparation']['profiles'][0]['dependencies'] = ['softdenchi-runtime', 'mfc42-prefix', 'mfc42-game-folder']
        self.initialize()
        _, report, _ = self.status()
        entry = self.entry(report)
        self.assertEqual(entry['next']['reason'], 'binding-blocked:dependency-not-verified:mfc42-game-folder')
        self.assertEqual(entry['next']['actions'], ['prefix-dll:mfc42-prefix', 'softdenchi-silent'])
        _, menu, output, commands = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)
        self.assertNotIn('この内容で準備する場合は1', output)
        self.assertEqual((commands, self.dll_records(), self.installs()), ([], [], []))
        self.assertFalse((self.wow64() / 'mfc42.dll').exists())

    def test_space_for_the_installer_counts_the_dll_written_before_it(self):
        self.initialize()
        real = dep._capacity
        wow64 = self.wow64()

        def capacity(needs):
            # A filesystem with room for either step alone but not both: the DLL written first uses space.
            used = sum((wow64 / name).stat().st_size for name in ('mfc42.dll',) if (wow64 / name).exists())
            result = real(needs)
            required = sum(need for _, need in needs)
            limit = 2 * self.config['dependency_installation']['asset']['expected_size'] + dep.RESERVE + 10
            return {**result, "sufficient": required + used <= limit}
        with patch.object(dep, '_capacity', capacity), patch.object(ONE['prefix_dll'], 'RESERVE', 1):
            _, report, _ = self.status()
            entry = self.entry(report)
            self.assertEqual((entry['next']['stage'], entry['next']['reason']),
                             ('softdenchi-silent', 'dependency-plan-blocked:insufficient-capacity'))
            _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)
        self.assertEqual(self.dll_records(), [])

    def test_different_dll_asset_stops_in_both(self):
        self.initialize()
        path = self.f.fixture.source.root / 'mfc42.dll'
        path.write_bytes(path.read_bytes() + b'changed')
        _, report, _ = self.status()
        entry = self.entry(report)
        self.assertTrue(entry['next']['reason'].startswith('dll-asset:mfc42-prefix:'))
        _, menu, _, _ = self.run_menu('1\n1\n1\n')
        self.agrees(entry, menu)
        self.assertEqual(self.dll_records(), [])


if __name__ == '__main__':
    unittest.main()
