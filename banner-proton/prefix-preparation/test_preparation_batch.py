#!/usr/bin/env python3
"""The 0.31.0 first screen: the list of what this bundle would do, run after one confirmation."""

import hashlib
import json
import os
import runpy
import shutil
import sys
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
UPDATE = runpy.run_path(str(HERE / 'test_preparation_proton_update.py'))
ONE = UPDATE['ONE']
import preparation_batch as batch
import preparation_proton_update as update
import preparation_slot_manifest as manifest
from preparation_store import PrivateStore


class BatchFixture:
    def first_screen(self, text):
        """The real first screen (no patched list), with the one-pass fixture's launch patches."""
        status, report, output, _ = self.run_menu(text, self.menu)
        return status, report, output

    def forget_manifest(self):
        """As for a slot placed by 0.30.0 (no saved verification data)."""
        path = self.f.store_root / manifest.DIRECTORY / manifest.record_name(update.bundle_directory(self.config))
        if path.exists():
            path.unlink()

    def manifest_state(self):
        with PrivateStore(self.f.store_root) as store:
            return manifest.state(store, update.bundle_directory(self.config))[0]


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class NewGameBatchTests(BatchFixture, ONE['OnePassTests']):
    """A registered game without a prefix is prepared with the automatic profile."""

    def test_list_shows_the_new_game_consent_and_the_slot_data(self):
        self.forget_manifest()
        before = self.protected()
        status, report, output = self.first_screen('q\n')
        self.assertEqual((status, report), (0, None))
        self.assertEqual(before, self.protected())  # The list writes nothing.
        self.assertIn('すること', output)
        self.assertIn('このProtonの照合情報を保存する', output)
        self.assertIn('[ID 42] を新しく準備する', output)
        self.assertIn('使用許諾に同意したうえで導入します。下の1は、その同意を含みます。', output)
        self.assertIn('1. すべて実行する', output)
        self.assertIn('起動する前に prepare.sh を実行してください', output)
        self.assertFalse(self.game_compat.exists())

    def test_run_saves_the_slot_data_and_prepares_the_game(self):
        self.forget_manifest()
        status, report, output = self.first_screen('1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual(report['mode'], batch.MODE)
        outcomes = {item['kind']: item['outcome'] for item in report['items']}
        self.assertEqual(outcomes, {'save-manifest': 'done', 'new': 'done'}, output)
        self.assertEqual(self.manifest_state(), 'same')
        self.assertIn('起動してよいゲーム: Example', output)
        self.assertIn('ソフト電池の認証', output)
        # Nothing is left to do now.
        _, _, again = self.first_screen('q\n')
        self.assertIn('することはありません', again)
        self.assertNotIn('1. すべて実行する', again)

    def test_changed_game_after_the_list_is_skipped_before_writing(self):
        original = batch.build

        def changed(ctx):
            listing = original(ctx)
            for item in listing['items']:
                if item['kind'] == 'new':
                    item['plan'] = dict(item['plan'], actions=['binding'])  # Confirmed fewer actions than needed.
            return listing
        with unittest.mock.patch.object(batch, 'build', side_effect=changed):
            _, report, output = self.first_screen('1\n')
        outcomes = {item['kind']: item['outcome'] for item in report['items']}
        self.assertEqual(outcomes['new'], 'skipped', output)
        self.assertIn('書き込み前に中止', output)
        self.assertFalse(self.game_compat.exists())

    def test_non_ascii_path_and_unknown_profiles_are_not_prepared_by_the_batch(self):
        self.config['game_preparation']['profiles'][0]['exe_sha256'] = 'a' * 64
        _, _, output = self.first_screen('q\n')
        self.assertIn('自動で選べる作品プロファイルがありません', output)

    def test_not_done_entries_carry_no_settings_into_the_result(self):
        self.game_compat.mkdir(parents=True)  # A prefix without a record of this tool.
        listing = batch.build(self.batch_context())
        entries = listing['skipped'] + [item for group in listing['groups'].values() for item in group]
        self.assertTrue(entries)
        self.assertFalse(any('targets' in item for item in entries))

    def test_a_prefix_without_a_record_is_listed_once_with_its_remedy(self):
        (self.game_compat / 'pfx').mkdir(parents=True)
        _, _, output = self.first_screen('q\n')
        self.assertIn('ツールの記録がなく、prefixがあるゲーム（1本）', output)
        self.assertEqual(output.count('名前を変えて登録し直し'), 1)

    def test_payload_missing_offers_no_run(self):
        archive = next(self.f.fixture.source.root.glob('DroidDeck-Proton-*.tar.gz'))
        archive.rename(archive.with_suffix('.moved'))
        _, _, output = self.first_screen('1\n')
        self.assertIn('配布物を照合できません', output)
        self.assertNotIn('1. すべて実行する', output)
        self.assertIn('取り消しました', output)

    def test_interrupted_run_is_shown(self):
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            store.write_record(batch.RUNS, 'batch-' + '0' * 32 + '.json',
                               {'schema_version': 1, 'kind': 'batch-run', 'tool_version': '0.31.0',
                                'run_id': 'batch-' + '0' * 32, 'created_ns': 1, 'status': 'running',
                                'games': [{'app_id': '42', 'step': 'new', 'started_ns': 1, 'outcome': 'running'}]})
        _, _, output = self.first_screen('q\n')
        self.assertIn('前回のまとめての実行が途中で終わっています', output)
        self.assertIn('ID 42: 書き込み前に中止', output)  # Started, but nothing with its IDs was written.

    def test_a_stop_after_writing_ends_the_run(self):
        self.forget_manifest()
        calls = []
        original = batch.build

        def twice(ctx):
            listing = original(ctx)
            new = next(item for item in listing['items'] if item['kind'] == 'new')
            listing['items'].append(dict(new))  # A following game (the same one) must not start.
            return listing

        def partial(ctx, item, journal):
            calls.append(item['kind'])
            return 'partial', {'report': {'status': 'stopped', 'reason': 'synthetic', 'stage': 'initialize'}}
        with unittest.mock.patch.object(batch, 'build', side_effect=twice), \
                unittest.mock.patch.object(batch, '_run_one_pass', side_effect=partial), \
                unittest.mock.patch.object(batch, '_save_manifest', side_effect=batch._save_manifest) as saved:
            _, report, output = self.first_screen('1\n')
        self.assertEqual(calls, ['new'])
        self.assertTrue(saved.called)
        self.assertEqual([item['outcome'] for item in report['items']], ['done', 'partial', 'not-started'])
        self.assertIn('一部適用・要確認', output)
        self.assertIn('「prefixの初期化」の途中かその後で止まりました', output)
        self.assertIn('再実行では続きから準備します', output)
        self.assertIn('このあとのゲームは実行していません', output)
        self.assertNotIn('backups/', output)

    def test_partial_text_by_stage_names_the_backup_only_when_it_exists(self):
        import types
        ctx = types.SimpleNamespace(management=self.f.store_root)
        binding = 'binding-' + 'a' * 32
        entry = {'outcome': 'partial', 'ids': {'binding': {'binding_id': binding}}}
        lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'move'}, entry))
        self.assertIn('バックアップは作られていません', lines)
        self.assertIn('再実行では飛ばされます', lines)
        (self.f.store_root / 'backups' / binding).mkdir(parents=True)
        lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'new'}, entry))
        self.assertIn('「設定（3つのファイル）の書き換え」', lines)
        self.assertIn(f'backups/{binding}', lines)
        lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'new'}, {'ids': {'binding': {'binding_id': '../x'}}}))
        self.assertNotIn('backups/', lines)

    def test_target_items_changed_after_the_check_stop_under_the_lock(self):
        original = batch.build
        confirmed = {}

        def changed(ctx):
            listing = original(ctx)
            for item in listing['items']:
                if item['kind'] == 'new':
                    item['targets'] = dict(item['targets'], picked=not item['targets']['picked'])
                    confirmed['targets'] = item['targets']
            return listing
        with unittest.mock.patch.object(batch, 'build', side_effect=changed), \
                unittest.mock.patch.object(batch, '_targets_now', side_effect=lambda ctx, key: confirmed['targets']):
            _, report, output = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'new')
        self.assertEqual(entry['outcome'], 'skipped', output)
        self.assertIn('confirmed-target-items-changed', json.dumps(entry['report']))
        self.assertFalse(self.game_compat.exists())

    def write_run(self, ids):
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            name = 'batch-' + os.urandom(16).hex()
            store.write_record(batch.RUNS, name + '.json',
                               {'schema_version': 1, 'kind': 'batch-run', 'tool_version': '0.31.0', 'run_id': name,
                                'created_ns': 1, 'status': 'running',
                                'games': [{'app_id': '42', 'step': 'new', 'started_ns': 1, 'outcome': 'running',
                                           'ids': ids}]})
            return name

    def test_interrupted_runs_are_reconciled_from_their_ids_and_closed_by_the_next_run(self):
        self.first_screen('1\n')
        with PrivateStore(self.f.store_root) as store:
            trial = store.inventory()['game_prefixes'][0]['trial_id']
            items, _ = update.history(store, '42')
        binding = items[-1]['binding_id']
        self.write_run({'initialize': {'trial_id': trial}, 'binding': {'binding_id': binding}})
        self.write_run({'initialize': {'trial_id': trial}, 'softdenchi-silent': {'install_id': 'depinstall-' + 'f' * 32}})
        self.write_run({'softdenchi-silent': {'install_id': 'depinstall-' + 'f' * 32}})
        _, _, output = self.first_screen('q\n')
        self.assertEqual(output.count('前回のまとめての実行が途中で終わっています'), 3)
        self.assertIn('ID 42: 完了', output)
        self.assertIn('ID 42: 一部適用・要確認', output)
        self.assertIn('ID 42: 書き込み前に中止', output)
        self.forget_manifest()
        self.first_screen('1\n')  # A new run marks them reviewed.
        _, _, output = self.first_screen('q\n')
        self.assertNotIn('前回のまとめての実行が途中で終わっています', output)

    def test_artifacts_without_records_count_and_a_note_alone_does_not(self):
        install = 'depinstall-' + 'b' * 32
        binding = 'binding-' + 'c' * 32
        self.write_run({'softdenchi-silent': {'install_id': install}})
        self.write_run({'binding': {'binding_id': binding}})
        _, _, output = self.first_screen('q\n')
        self.assertEqual(output.count('ID 42: 書き込み前に中止'), 2, output)
        for name in list(self.f.store_root.joinpath(batch.RUNS).iterdir()):
            name.unlink()
        (self.home / '.local/share/droiddeck-preparation-work/42/inputs' / install).mkdir(parents=True)
        (self.f.store_root / 'backups' / binding).mkdir(parents=True)
        self.write_run({'softdenchi-silent': {'install_id': install}})
        self.write_run({'binding': {'binding_id': binding}})
        _, _, output = self.first_screen('q\n')
        self.assertEqual(output.count('ID 42: 一部適用・要確認'), 2, output)

    def test_unfinished_binding_with_every_file_written_is_final_check_only(self):
        self.first_screen('1\n')
        with PrivateStore(self.f.store_root) as store:
            items, _ = update.history(store, '42')
        binding = items[-1]['binding_id']
        with PrivateStore(self.f.store_root) as store, store.locked('e' * 64):
            record, digest = store.read_record('bindings', binding + '.json')
            store.write_record('bindings', binding + '.json', dict(record, status='binding-running'), digest)
        self.write_run({'binding': {'binding_id': binding}})
        _, _, output = self.first_screen('q\n')
        self.assertIn('ID 42: 一部適用・要確認（設定はすべて書き換え済みで、最後の確認だけが済んでいません', output)

    def test_final_check_only_holds_when_another_game_changed_the_shared_files(self):
        self.first_screen('1\n')
        with PrivateStore(self.f.store_root) as store:
            items, _ = update.history(store, '42')
        binding = items[-1]['binding_id']
        with PrivateStore(self.f.store_root) as store, store.locked('e' * 64):
            record, digest = store.read_record('bindings', binding + '.json')
            store.write_record('bindings', binding + '.json', dict(record, status='binding-running'), digest)
        games = json.loads(self.games_config.read_text())
        games['games']['99'] = dict(games['games']['42'])  # Another game's entry: the whole-file hash no longer matches.
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        self.write_run({'binding': {'binding_id': binding}})
        _, _, output = self.first_screen('q\n')
        self.assertIn('ID 42: 一部適用・要確認（設定はすべて書き換え済みで、最後の確認だけが済んでいません', output)

    def test_result_keeps_each_game_report_and_ids(self):
        _, report, _ = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'new')
        self.assertEqual(entry['report']['status'], 'ready-to-launch')
        self.assertIn('binding_id', entry['ids']['binding'])
        self.assertIn('groups', report)

    def test_plan_mode_writes_nothing_and_a_run_with_other_fixed_values_stops(self):
        ctx = batch.Context(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
                            input_stream=None, output_stream=None, environment=self.environment, steam=self.f.steam,
                            settings=self.f.settings, home=self.home, runtime_root=self.f.root)
        profile = self.config['game_preparation']['profiles'][0]['profile_id']
        before = self.protected()
        _, plan, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', profile), mode='plan')[1], ''))
        self.assertIn('fixed', plan, plan)
        self.assertEqual(before, self.protected())
        self.assertFalse(self.game_compat.exists())
        expected = dict(plan, fixed={**plan['fixed'], 'dlls': 'changed'})
        _, report, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', profile), mode='run',
                                                                          expected=expected)[1], ''))
        self.assertEqual((report['stage'], report['reason']), ('batch-confirmation', 'confirmed-values-changed:dlls'))
        self.assertFalse(self.game_compat.exists())

    def test_an_initialized_game_is_resumed_by_the_batch(self):
        self.initialize()
        _, _, output = self.first_screen('q\n')
        self.assertIn('[ID 42]', output)
        self.assertNotIn('[ID 42] を新しく準備する', output)
        self.assertIn('の準備を続きから進める（', output)  # What it will do, as in the status check.
        self.assertIn('準備用Protonに割り当てる', output)
        _, report, output = self.first_screen('1\n')
        outcomes = {item['kind']: item['outcome'] for item in report['items']}
        self.assertEqual(outcomes.get('resume'), 'done', output)

    def test_a_run_records_every_listed_game_before_the_first_step(self):
        self.forget_manifest()
        with unittest.mock.patch.object(batch, '_save_manifest', side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.first_screen('1\n')
        with PrivateStore(self.f.store_root) as store:
            records = [store.read_record(batch.RUNS, path.name)[0] for path in (self.f.store_root / batch.RUNS).glob('batch-*.json')]
        games = {(item['app_id'], item['step']): item['outcome'] for item in records[0]['games']}
        self.assertEqual(games, {('-', 'save-manifest'): 'running', ('42', 'new'): 'not-started'})

    def test_a_lock_held_elsewhere_stops_menu_1_before_any_write_and_ends_the_run(self):
        from preparation_store import PrivateStore as Store
        original = Store.locked

        def locked(store, key):
            if key == hashlib.sha256(str(self.game_compat).encode()).hexdigest():
                raise batch.Invalid('preparation already locked')
            return original(store, key)
        with unittest.mock.patch.object(Store, 'locked', locked):
            _, report, output = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'new')
        self.assertEqual(entry['outcome'], 'skipped', output)  # Not "partially applied": nothing was written.
        self.assertTrue(entry['run_stopped'])
        self.assertFalse(self.game_compat.exists())

    def test_an_interrupted_run_lists_the_games_it_never_reached(self):
        journal = batch.Journal(self.batch_context())
        journal.listed([{'kind': 'save-manifest'}, {'kind': 'new', 'app_id': '42'}, {'kind': 'new', 'app_id': '43'}])
        journal.save()
        journal.step('42', 'new', 'running')
        with PrivateStore(self.f.store_root) as store:
            record, _ = store.read_record(batch.RUNS, journal.run_id + '.json')
            outcomes = batch.reconcile(store, record)
        self.assertEqual(outcomes, {'-': 'not-started', '42': 'skipped', '43': 'not-started'})

    def test_each_dll_keeps_its_own_id_in_the_progress_record(self):
        journal = batch.Journal(self.batch_context())
        journal.listed([{'kind': 'resume', 'app_id': '42'}])
        journal.save()
        with PrivateStore(self.f.store_root) as store, store.locked('a' * 64):
            journal.ids(store, '42', 'prefix-dll:first', {'record_id': 'prefixdll-' + '1' * 32})
            journal.ids(store, '42', 'prefix-dll:second', {'record_id': 'prefixdll-' + '2' * 32})
        ids = journal.record['games'][0]['ids']
        self.assertEqual(sorted(value['record_id'] for value in ids.values()),
                         ['prefixdll-' + '1' * 32, 'prefixdll-' + '2' * 32])
        lines = batch._partial_lines(self.batch_context(), {'kind': 'resume'}, {'ids': ids})
        self.assertIn('「prefixのDLLの用意」の途中かその後で止まりました。', lines)

    def test_a_run_stops_when_the_diagnostic_option_changed_after_the_list(self):
        ctx = self.batch_context()
        profile = self.config['game_preparation']['profiles'][0]['profile_id']
        _, plan, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', profile), mode='plan')[1], ''))
        self.config['diagnostics'] = {'installer_log': True}
        _, report, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', profile), mode='run',
                                                                          expected=plan)[1], ''))
        self.assertEqual(plan['fixed']['asset']['mode'], 'silent', plan['fixed']['asset'])
        self.assertEqual((report.get('stage'), report.get('reason')), ('batch-confirmation', 'confirmed-values-changed:installer_log'),
                         report)
        self.assertFalse(self.game_compat.exists())

    def test_a_run_of_another_kind_than_confirmed_stops(self):
        ctx = self.batch_context()
        profile = self.config['game_preparation']['profiles'][0]['profile_id']
        _, plan, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', profile), mode='plan')[1], ''))
        expected = dict(plan, label='続きから')
        _, report, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', profile), mode='run',
                                                                          expected=expected)[1], ''))
        self.assertEqual((report['stage'], report['reason']), ('batch-confirmation', 'confirmed-values-changed:kind'))
        self.assertFalse(self.game_compat.exists())

    def test_a_stop_while_the_details_are_swapped_out_is_still_shown(self):
        import io

        import preparation_one_pass as one_pass
        self.initialize()
        ctx = self.batch_context()
        _, plan, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', None), mode='plan')[1], ''))
        shown = io.StringIO()
        with unittest.mock.patch.object(one_pass, 'action_text', side_effect=ValueError('display failed')):
            _, report, _, _ = self.run_menu('', lambda text: (0, ctx.one_pass(select=('42', None), mode='run',
                                                                              expected=plan, output=shown)[1], ''))
        self.assertEqual(report['status'], 'stopped')
        self.assertIn('検査停止', shown.getvalue())

    def test_a_failed_slot_data_save_is_reported_and_the_run_goes_on(self):
        self.forget_manifest()
        with unittest.mock.patch.object(batch, '_save_manifest_locked', side_effect=OSError(28, 'no space')):
            _, report, output = self.first_screen('1\n')
        entries = {item['kind']: item for item in report['items']}
        self.assertEqual((entries['save-manifest']['outcome'], entries['save-manifest']['reason']),
                         ('skipped', 'manifest-save-failed'))
        self.assertEqual(entries['save-manifest']['error']['error_class'], 'OSError')
        self.assertEqual(entries['new']['outcome'], 'done', output)
        self.assertIn('戻す先には使えません', output)

    def test_slot_data_of_other_contents_is_listed_under_not_done(self):
        path = self.f.store_root / manifest.DIRECTORY / manifest.record_name(update.bundle_directory(self.config))
        path.write_bytes(path.read_bytes().replace(b'"version_value":"', b'"version_value":"changed '))
        _, _, output = self.first_screen('q\n')
        self.assertIn('このProtonの照合情報の保存: ' + batch.MANIFEST_SKIP_TEXT['mismatch'], output)
        self.assertNotIn('このProtonの照合情報を保存する', output)

    def test_the_list_reads_the_payload_once(self):
        import preparation_installation as installation
        import preparation_recheck as recheck
        calls = []

        def counting(real):
            def read(*args, **kwargs):
                calls.append(1)
                return real(*args, **kwargs)
            return read
        with unittest.mock.patch.object(recheck, 'inspect_archive_from_folder',
                                        side_effect=counting(recheck.inspect_archive_from_folder)), \
                unittest.mock.patch.object(installation, 'inspect_archive_from_folder',
                                           side_effect=counting(installation.inspect_archive_from_folder)):
            _, _, output = self.first_screen('q\n')
        self.assertIn('[ID 42] を新しく準備する', output)
        self.assertEqual(len(calls), 1)

    def batch_context(self):
        return batch.Context(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
                             input_stream=None, output_stream=None, environment=self.environment, steam=self.f.steam,
                             settings=self.f.settings, home=self.home, runtime_root=self.f.root)

    def test_the_journal_holds_each_id_before_its_record_is_written(self):
        order = []
        ids = batch.Journal.ids
        write = PrivateStore.write_record

        def noted(journal, store, app_id, step, values):
            order.extend(('journal', value) for value in values.values())
            return ids(journal, store, app_id, step, values)

        def written(store, directory, name, *args, **kwargs):
            if directory in batch.ID_RECORDS.values():
                order.append(('record', name.removesuffix('.json')))
            return write(store, directory, name, *args, **kwargs)
        with unittest.mock.patch.object(batch.Journal, 'ids', autospec=True, side_effect=noted), \
                unittest.mock.patch.object(PrivateStore, 'write_record', autospec=True, side_effect=written):
            _, report, output = self.first_screen('1\n')
        self.assertEqual({item['kind']: item['outcome'] for item in report['items']}.get('new'), 'done', output)
        journaled = [value for kind, value in order if kind == 'journal']
        self.assertGreaterEqual(len(journaled), 3, order)  # initialize, softdenchi-silent, binding
        for value in journaled:
            self.assertLess(order.index(('journal', value)), order.index(('record', value)), order)

    def test_changed_target_items_skip_the_game(self):
        original = batch.build

        def changed(ctx):
            listing = original(ctx)
            for item in listing['items']:
                if item['kind'] == 'new':
                    item['targets'] = dict(item['targets'], picked=not item['targets']['picked'])
            return listing
        with unittest.mock.patch.object(batch, 'build', side_effect=changed):
            _, report, output = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'new')
        self.assertEqual((entry['outcome'], entry['reason']), ('skipped', 'confirmed-target-items-changed'), output)
        self.assertFalse(self.game_compat.exists())

    def test_one_shared_result_is_rewritten_after_each_step(self):
        before = set(self.f.fixture.source.root.glob('plan-*.json'))
        _, report, _ = self.first_screen('1\n')
        after = set(self.f.fixture.source.root.glob('plan-*.json')) - before
        self.assertEqual(len(after), 1, after)
        self.assertEqual(json.loads(next(iter(after)).read_text())['run_id'], report['run_id'])

    def test_a_stop_before_binding_continues_on_the_next_run(self):
        import types
        ctx = types.SimpleNamespace(management=self.f.store_root)
        entry = {'outcome': 'partial', 'ids': {'initialize': {'trial_id': 'gprefix-' + 'a' * 32}},
                 'report': {'stage': 'binding', 'reason': 'binding-blocked:process:target-process-view-not-clear'}}
        lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'new'}, entry))
        self.assertIn('「設定（3つのファイル）の書き換え」の前で止まりました', lines)
        self.assertIn('再実行では続きから準備します', lines)
        self.assertNotIn('再実行では飛ばされます', lines)
        self.assertNotIn('バックアップは作られていません', lines)
        # A move stopped at binding keeps the earlier text.
        lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'move'}, {**entry, 'ids': {}}))
        self.assertIn('再実行では飛ばされます', lines)
        # A plan changed right before the write (the game started in between) is a stop before binding too.
        changed = {**entry, 'report': {'stage': 'binding', 'reason': 'game binding plan changed'}}
        lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'new'}, changed))
        self.assertIn('再実行では続きから準備します', lines)
        self.assertNotIn('再実行では飛ばされます', lines)
        # A binding history that needs a look keeps the earlier text.
        for reason in batch.BINDING_HISTORY_STOPS:
            stopped = {**entry, 'report': {'stage': 'binding', 'reason': reason}}
            lines = '\n'.join(batch._partial_lines(ctx, {'kind': 'new'}, stopped))
            self.assertIn('再実行では飛ばされます', lines)

    def test_the_default_profile_chooses_among_profiles_without_a_hash(self):
        profiles = self.config['game_preparation']['profiles']
        profiles.append(dict(profiles[0], profile_id='no-dependencies', title='Without dependencies', dependencies=[]))
        _, _, output = self.first_screen('q\n')
        self.assertIn('自動で選べる作品プロファイルがありません', output)
        self.config['game_preparation']['default_profile'] = 'no-dependencies'
        _, _, output = self.first_screen('q\n')
        self.assertIn('[ID 42] を新しく準備する（Without dependencies）', output)
        self.assertNotIn('ソフト電池の認証', output)
        self.assertNotIn('使用許諾', output)
        status, report, output = self.first_screen('1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual({item['kind']: item['outcome'] for item in report['items']}.get('new'), 'done', output)
        self.assertNotIn('ソフト電池の認証', output)

    def test_a_batch_stopped_before_binding_resumes_the_game_next_time(self):
        import preparation_one_pass as one_pass
        profiles = self.config['game_preparation']['profiles']
        profiles[0]['dependencies'] = []
        original = one_pass.plan_game_binding

        def running(**arguments):
            with unittest.mock.patch('preparation_processes.ProcessStopCheck.check', return_value={'clear_in_view': False}):
                return original(**arguments)
        with unittest.mock.patch.object(one_pass, 'plan_game_binding', side_effect=running):
            _, report, output = self.first_screen('1\n')
        self.assertEqual({item['kind']: item['outcome'] for item in report['items']}.get('new'), 'partial', output)
        self.assertIn('の前で止まりました（設定は書き換えていません）', output)
        self.assertIn('再実行では続きから準備します', output)
        self.assertNotIn('再実行では飛ばされます', output)
        _, _, output = self.first_screen('q\n')
        self.assertIn('[ID 42] の準備を続きから進める', output)
        _, report, output = self.first_screen('1\n')
        self.assertEqual({item['kind']: item['outcome'] for item in report['items']}.get('resume'), 'done', output)

    def test_a_matching_pinned_profile_is_mentioned(self):
        import hashlib
        exe = next(Path(game['exe']) for key, game in
                   ONE['GAME']['DEP']['TRIAL']['BASE']['selection'].registration_catalog(self.environment)[2].items()
                   if key == '42')
        pinned = dict(self.config['game_preparation']['profiles'][0], profile_id='pinned-game', title='Pinned game',
                      exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
        self.config['game_preparation']['profiles'].append(pinned)
        _, _, output = self.first_screen('q\n')
        self.assertIn('このゲームはPinned gameのプロファイルとも一致します', output)


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class MoveBatchTests(BatchFixture, UPDATE['MoveFixture'], ONE['OnePassTests']):
    """A game on an older slot this bundle replaces is moved by the batch run."""

    def test_move_is_listed_and_run(self):
        _, _, output = self.first_screen('q\n')
        self.assertIn('へ移す（今: ' + self.old, output)
        _, report, output = self.first_screen('1\n')
        outcomes = {item['kind']: item['outcome'] for item in report['items']}
        self.assertEqual(outcomes.get('move'), 'done', output)
        self.assertEqual(self.selection()['kind'], 'bound')
        self.assertIn('最初の起動が長くなることがあります', output)

    def test_slot_not_replaced_by_this_bundle_is_not_moved(self):
        self.config['supersedes'] = []
        _, _, output = self.first_screen('1\n')
        self.assertIn('置き換える版ではありません（個別の操作の5で移せます）', output)
        self.assertEqual(self.selection()['kind'], 'move')

    def test_status_shows_the_move_decision(self):
        _, report, output = self.first_screen('2\n')
        self.assertIn('からこのバンドルの準備用Protonへ移します', output)
        entry = next(item for item in report['games'] if item['app_id'] == '42')
        self.assertEqual(entry['next']['next'], 'move')
        self.config['supersedes'] = []
        _, report, output = self.first_screen('2\n')
        self.assertIn('置き換える版ではありません', output)

    def test_a_move_the_run_would_stop_is_listed_under_not_done_and_in_the_status(self):
        with unittest.mock.patch.object(update, 'proton_prefix_version', return_value='2.0-1'):
            _, _, output = self.first_screen('q\n')
            self.assertIn('移すと途中で止まる状態です（prefix-version-differs）', output)
            self.assertNotIn('へ移す（今: ', output)
            self.assertNotIn('1. すべて実行する', output)
            _, report, output = self.first_screen('2\n')
        entry = next(item for item in report['games'] if item['app_id'] == '42')
        self.assertEqual((entry['next']['next'], entry['next']['blockers']), ('move-blocked', ['prefix-version-differs']))
        self.assertIn('依存: ', output)
        self.assertIn('移すと途中で止まる状態です', output)
        self.assertEqual(self.selection()['kind'], 'move')

    def test_status_shows_the_dependencies_of_a_move(self):
        _, report, output = self.first_screen('2\n')
        entry = next(item for item in report['games'] if item['app_id'] == '42')
        self.assertTrue(entry['dependencies'], output)

    def test_align_is_listed_and_run_keeping_the_screen_choice(self):
        games = json.loads(self.games_config.read_text())
        games['games']['42'] = {'valve': False, 'dir': self.bundle, 'name': update.tool_id_of(self.bundle)}
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        before = self.games_config.read_bytes()
        _, report, output = self.first_screen('1\n')
        outcomes = {item['kind']: item['outcome'] for item in report['items']}
        self.assertEqual(outcomes.get('align'), 'done', output)
        self.assertEqual(before, self.games_config.read_bytes())
        self.assertEqual(self.selection()['kind'], 'bound')

    def test_a_lock_held_elsewhere_ends_the_run(self):
        # A real lock held by another run also blocks the progress record, so the run stops before any game;
        # this is the race where only the game's lock is taken in between.
        original, game = PrivateStore.locked, self.lock()

        def locked(store, key):
            if key == game:
                raise batch.Invalid('preparation already locked')
            return original(store, key)
        with unittest.mock.patch.object(PrivateStore, 'locked', locked):
            _, report, output = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'move')
        self.assertEqual(entry['outcome'], 'skipped', output)
        self.assertTrue(entry['run_stopped'])
        self.assertIn('このゲームによらない理由で止まった', output)
        self.assertEqual(self.selection()['kind'], 'move')

    def test_the_droiddeck_settings_lock_held_elsewhere_ends_the_run(self):
        import preparation_binding as binding

        def locked(settings):
            raise batch.Invalid('DroidDeck settings are locked')
        with unittest.mock.patch.object(binding, 'droiddeck_lock', side_effect=locked):
            _, report, output = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'move')
        self.assertEqual(entry['outcome'], 'skipped', output)
        self.assertTrue(entry['run_stopped'])
        self.assertEqual(self.selection()['kind'], 'move')

    def test_games_on_preparation_slots_are_preferred_for_confirmation(self):
        self.assertIn('42', batch._assigned_to_slots(batch.Context(
            self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config, input_stream=None,
            output_stream=None, environment=self.environment, steam=self.f.steam, settings=self.f.settings,
            home=self.home, runtime_root=self.f.root)))

    def test_individual_operations_5_and_6_are_reachable(self):
        _, _, output = self.first_screen('3\nq\n')
        self.assertIn('5. ゲームを移す', output)
        self.assertIn('6. 前のProtonへ戻す', output)
        _, report, output = self.first_screen('3\n5\n1\n1\n')
        self.assertTrue(report['binding_written'], output)


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class PlacementBatchTests(BatchFixture, ONE['OnePassTests']):
    """Without the bundle slot, only the placement is listed; the rest is listed again after it."""

    def test_place_then_list_again_and_confirm_again(self):
        slot = self.f.steam / 'compatibilitytools.d' / update.bundle_directory(self.config)
        shutil.rmtree(slot)
        _, _, output = self.first_screen('q\n')
        self.assertIn('新しいProtonを準備用slotに置く', output)
        self.assertNotIn('[ID 42] を新しく準備する', output)
        _, report, output = self.first_screen('1\nq\n')
        self.assertTrue(slot.is_dir(), output)
        self.assertEqual(report['placement']['confirmation'], '42')
        self.assertIn('置く確認に使った登録: Example [ID 42]', output)
        self.assertIn('[ID 42] を新しく準備する', output.split('新しいProtonを置きました', 1)[1])
        self.assertIn('取り消しました（新しいProtonは置いたままです）', output)
        self.assertFalse(self.game_compat.exists())

    def context(self):
        return batch.Context(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
                             input_stream=None, output_stream=None, environment=self.environment, steam=self.f.steam,
                             settings=self.f.settings, home=self.home, runtime_root=self.f.root)

    def test_a_candidate_that_cannot_confirm_is_skipped_and_the_next_one_used(self):
        import preparation_selection as selection
        import preparation_static_placement as placement
        slot = self.f.steam / 'compatibilitytools.d' / update.bundle_directory(self.config)
        shutil.rmtree(slot)
        catalog = selection.registration_catalog

        def with_extra(environment):
            source, document, games = catalog(environment)
            return source, document, {**games, '43': dict(games['42'], title='Missing')}
        candidates = placement._confirmation_candidates

        def plus(games, *args):
            selectable, excluded = candidates({key: value for key, value in games.items() if key != '43'}, *args)
            return ['43', *selectable], excluded
        with unittest.mock.patch.object(selection, 'registration_catalog', side_effect=with_extra), \
                unittest.mock.patch.object(placement, '_confirmation_candidates', side_effect=plus):
            # Preferred, but absent from the source.
            _, result, _, _ = self.run_menu('', lambda text: (0, batch.place_automatically(self.context(), ('43',)), ''))
        self.assertEqual(result['confirmation'], '42', result)
        self.assertEqual([item['app_id'] for item in result['skipped_candidates']], ['43'])
        self.assertTrue(slot.is_dir())

    def test_when_no_candidate_can_confirm_the_reasons_and_the_remedy_are_shown(self):
        import preparation_target as target
        slot = self.f.steam / 'compatibilitytools.d' / update.bundle_directory(self.config)
        shutil.rmtree(slot)
        with unittest.mock.patch.object(target, 'pin_registration', side_effect=batch.Invalid('registration EXE missing')):
            _, report, output = self.first_screen('1\n')
        self.assertEqual(report['status'], 'stopped')
        self.assertEqual([(item['app_id'], item['reason']) for item in report['skipped_candidates']],
                         [('42', 'registration EXE missing')])
        self.assertIn('使えなかった登録: ID 42（registration EXE missing）', output)
        self.assertIn('DroidDeckにゲームを1本登録し', output)
        self.assertFalse(slot.exists())

    def test_a_registration_failing_under_the_lock_gives_way_to_the_next_candidate(self):
        import preparation_static_placement as placement
        slot = self.f.steam / 'compatibilitytools.d' / update.bundle_directory(self.config)
        shutil.rmtree(slot)
        original, calls = placement.plan_confirmed_placement, []

        def second_fails(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:  # The plan made again under the lock.
                error = batch.Invalid('registration EXE missing')
                error.preparation_check = 'target-registration-exe'
                raise error
            return original(*args, **kwargs)
        with unittest.mock.patch.object(placement, 'plan_confirmed_placement', side_effect=second_fails), \
                self.assertRaises(batch.Invalid) as stopped:
            self.run_menu('', lambda text: (0, batch.place_automatically(self.context()), ''))
        self.assertEqual(str(stopped.exception), 'no registered game can confirm the placement')
        self.assertEqual(stopped.exception.skipped_candidates, [{'app_id': '42', 'reason': 'registration EXE missing'}])
        self.assertFalse(slot.exists())

    def test_a_check_common_to_every_candidate_stops_once(self):
        import preparation_static_placement as placement
        slot = self.f.steam / 'compatibilitytools.d' / update.bundle_directory(self.config)
        shutil.rmtree(slot)
        calls = []

        def broken(*args, **kwargs):
            calls.append(1)
            raise batch.Invalid('runtime differs')
        with unittest.mock.patch.object(placement, 'plan_confirmed_placement', side_effect=broken), \
                self.assertRaises(batch.Invalid):
            self.run_menu('', lambda text: (0, batch.place_automatically(self.context()), ''))
        self.assertEqual(len(calls), 1)
        self.assertFalse(slot.exists())


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class DllBatchTests(BatchFixture, ONE['PrefixDllOnePassTests']):
    """A new game with a prefix DLL, prepared by the batch run."""

    def test_each_dll_id_is_recorded_under_its_own_key(self):
        _, report, output = self.first_screen('1\n')
        entry = next(item for item in report['items'] if item['kind'] == 'new')
        self.assertEqual(entry['outcome'], 'done', output)
        self.assertIn('prefix-dll:mfc42-prefix', entry['ids'])
        self.assertNotIn('prefix-dll', entry['ids'])

    def test_a_prepared_game_is_not_listed_when_the_asset_files_are_gone(self):
        # As on the device on 2026-11-23: a folder without mfc42.dll listed the ready game under "not done".
        _, report, output = self.first_screen('1\n')
        self.assertEqual(next(item for item in report['items'] if item['kind'] == 'new')['outcome'], 'done', output)
        (self.f.fixture.source.root / 'mfc42.dll').unlink()
        _, _, output = self.first_screen('q\n')
        self.assertNotIn('[ID 42]', output)
        self.assertIn('することはありません', output)


# Only the fixtures of the one-pass tests are reused, not their tests.
for _class in (NewGameBatchTests, MoveBatchTests, PlacementBatchTests, DllBatchTests):
    for _name in dir(ONE['PrefixDllOnePassTests'] if _class is DllBatchTests else ONE['OnePassTests']):
        if _name.startswith('test_') and _name not in _class.__dict__:
            setattr(_class, _name, None)
del _class, _name


class TextTests(unittest.TestCase):
    def test_reasons_are_shown_in_words(self):
        self.assertIn('DroidDeckの画面と同期のコマンドで移せます', batch._skip_text('slot-folder-missing-or-unregistered'))
        self.assertTrue(batch._skip_text('unreadable:OSError').startswith('記録や設定を読めません（OSError）'))
        self.assertIn('もう一度', batch._skip_text('binding-partially-applied', 'もう一度確かめてください'))
        for reason in ('not-a-preparation-slot', 'slot-not-placed-by-this-tool', 'slot-tool-id-differs',
                       'binding-running-record', 'binding-failed-after-writing', 'no-verified-binding',
                       'not-assigned-to-a-placed-slot'):
            self.assertIn(reason, batch.SKIP_TEXT)


class LogCopyTests(unittest.TestCase):
    def test_a_failure_while_offering_copies_does_not_stop_a_finished_run(self):
        import io
        import types
        view = {'install_id': 'depinstall-' + 'a' * 32, 'app_id': '42', 'state': 'final'}
        report = {'items': [{'app_id': '42', 'report': {'steps': [{'installer_log': view, 'record': {'status': 'partial'}}]}}]}
        ctx = types.SimpleNamespace(output=io.StringIO())
        with unittest.mock.patch.object(batch, '_save_shared_now', side_effect=OSError(5, 'refused')):
            batch._offer_log_copies(ctx, [], report, {'items': [{'app_id': '42', 'title': 'Example'}]})
        self.assertEqual(report['installer_log_copies_error'], 'OSError')
        self.assertNotIn('status', report)
        self.assertIn('結果は保存済みです', ctx.output.getvalue())


class NewDeviceTests(unittest.TestCase):
    def test_a_run_creates_the_private_folders(self):
        import io
        import tempfile
        with tempfile.TemporaryDirectory(dir='/tmp') as root:
            root = Path(root)
            for name in ('home', 'steam', 'settings', 'dist'):
                (root / name).mkdir(mode=0o700)
            ctx = batch.Context(root / 'dist', None, {}, input_stream=io.StringIO(), output_stream=io.StringIO(),
                                environment={}, steam=root / 'steam', settings=root / 'settings', home=root / 'home',
                                runtime_root=None)
            listing = {'bundle': 'b', 'items': [], 'skipped': [], 'groups': {}}
            report = batch.run(ctx, listing, [ctx.steam, ctx.settings])
            self.assertTrue((ctx.management / batch.RUNS / (report['run_id'] + '.json')).is_file())
            self.assertTrue((root / 'home/.local/state/droiddeck-prefix-preparation/reports').is_dir())


if __name__ == '__main__':
    unittest.main()
