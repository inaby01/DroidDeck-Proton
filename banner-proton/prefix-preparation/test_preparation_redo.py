#!/usr/bin/env python3
"""recovery.sh 7 (1.0.0): prepare a game again under the same registration, and finishing an
interrupted placement record in prepare.sh."""

import json
import os
import runpy
import stat
import sys
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
BATCH = runpy.run_path(str(HERE / 'test_preparation_batch.py'))
UPDATE = BATCH['UPDATE']
ONE = BATCH['ONE']
import preparation_batch as batch
import preparation_proton_update as update
import preparation_redo as redo
from preparation_slot_manifest import placed_slots
from preparation_store import PrivateStore


def own_tests_only(cls):
    """The fixture classes' own tests already run in their modules."""
    for base in cls.__mro__[1:]:
        for name in vars(base):
            if name.startswith('test') and name not in vars(cls):
                setattr(cls, name, None)
    return cls


@own_tests_only
@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class RedoTests(BATCH['NewGameBatchTests']):
    def redo(self, text):
        return self.script('recovery', '7\n' + text)

    def records(self, directory):
        with PrivateStore(self.f.store_root) as store:
            return redo._records_of(store, directory, '42')[0]

    def test_an_initialized_game_is_prepared_again_under_the_same_registration(self):
        self.initialize()
        self.assertTrue(self.game_compat.is_dir())
        self.assertTrue(self.records('game-prefixes'))
        status, report, output = self.redo('1\ny\n')
        self.assertEqual(status, 2, output)
        self.assertEqual((report['mode'], report['status'], report['prefix']), ('game-redo-result', 'done', 'removed'))
        self.assertEqual(report['retired'], {'game-prefixes': 1})
        work_root = self.home / redo.WORK_ROOT
        self.assertFalse(os.path.lexists(work_root / '42'))
        self.assertTrue((work_root / ('retired-' + report['redo_id'].removeprefix('redo-'))).is_dir())
        self.assertFalse(os.path.lexists(self.game_compat))
        self.assertEqual(self.records('game-prefixes'), [])
        retired = self.f.store_root / 'retired' / report['redo_id'] / 'game-prefixes'
        self.assertEqual(len(list(retired.iterdir())), 1)
        with PrivateStore(self.f.store_root) as store:
            record, _ = store.read_record(redo.REDOS, report['redo_id'] + '.json')
        self.assertEqual((record['status'], record['prefix'], record['app_id']), ('done', 'removed', '42'))
        self.assertIn('prepare.sh を実行すると、このゲームが新しく準備するゲームとして一覧に出ます', output)
        _, _, listed = self.first_screen('q\n')
        self.assertIn('[ID 42] を新しく準備する', listed)
        status, report, output = self.first_screen('1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual({item['kind']: item['outcome'] for item in report['items']}.get('new'), 'done', output)

    def test_a_prefix_made_before_preparation_is_removed_without_following_links(self):
        outside = self.f.root / 'outside.txt'
        outside.write_text('keep')
        (self.game_compat / 'pfx/drive_c/users').mkdir(parents=True)
        (self.game_compat / 'pfx/dosdevices').mkdir()
        (self.game_compat / 'pfx/dosdevices/z:').symlink_to(self.f.root)
        (self.game_compat / 'pfx/link.txt').symlink_to(outside)
        locked = self.game_compat / 'pfx/drive_c/locked'
        locked.mkdir()
        (locked / 'file').write_text('x')
        locked.chmod(0o500)
        _, _, listed = self.first_screen('q\n')
        self.assertIn('recovery.sh の7でprefixを消して', listed)
        status, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['retired']), ('done', {}), output)
        self.assertFalse(os.path.lexists(self.game_compat))
        self.assertEqual(outside.read_text(), 'keep')
        self.assertTrue(self.f.root.is_dir())

    def test_a_prepared_game_is_never_offered(self):
        status, report, output = self.first_screen('1\n')
        self.assertEqual(status, 2, output)
        before = sorted(p.name for p in self.game_compat.iterdir())
        status, report, output = self.redo('q\n')
        self.assertEqual((status, report), (0, None), output)
        self.assertIn('やり直さないゲーム: Example [ID 42]（一度準備を終えています', output)
        self.assertFalse([line for line in output.splitlines() if line[:1].isdigit() and '[ID 42]' in line], output)
        self.assertEqual(before, sorted(p.name for p in self.game_compat.iterdir()))

    def test_a_binding_that_only_started_is_named_as_such_and_never_offered(self):
        self.initialize()
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            store.write_record(redo.BINDINGS, 'binding-' + '1' * 32 + '.json',
                               {'schema_version': 1, 'app_id': '42', 'status': 'binding-running'})
        _, report, output = self.redo('q\n')
        self.assertIn('[ID 42]（設定の書き換えを始めた記録があります', output)
        self.assertNotIn('一度準備を終えています', output)
        self.assertTrue(self.game_compat.is_dir())

    def test_a_signed_form_prefix_is_redone_and_two_forms_are_refused(self):
        self.assertEqual(redo.prefix_names(str(2**32 - 42)), [str(2**32 - 42), '-42'])
        self.assertEqual(redo.prefix_names('42'), ['42'])
        import shutil
        signed = self.game_compat.parent / 'signed-42'
        signed.mkdir(parents=True)
        with unittest.mock.patch.object(redo, 'prefix_names', side_effect=lambda key: [key, 'signed-' + key]):
            _, report, output = self.redo('1\ny\n')
            self.assertEqual((report['status'], report['prefix']), ('done', 'removed'), output)
            self.assertIn(str(signed), output)
            self.assertFalse(os.path.lexists(signed))
            signed.mkdir()
            self.game_compat.mkdir()
            _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（このゲームのprefixが、IDの書き方違いで2つあります', output)
        self.assertTrue(signed.is_dir() and self.game_compat.is_dir())
        shutil.rmtree(signed)

    def test_softdenchi_in_an_initialized_prefix_without_an_install_record_is_refused(self):
        self.initialize()
        (self.game_compat / 'pfx/drive_c/Program Files (x86)/SoftDenchi').mkdir(parents=True)
        _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（ツールが入れた記録のないソフト電池がprefixに入っています', output)

    def test_only_a_run_of_the_tool_installer_explains_softdenchi_in_the_prefix(self):
        self.initialize()
        (self.game_compat / 'pfx/drive_c/Program Files (x86)/SoftDenchi').mkdir(parents=True)
        for installer, offered in (('staged', False), ('exited', True)):
            with self.subTest(installer=installer):
                with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
                    store.write_record('dependency-installs', 'install-' + installer + '.json',
                                       {'schema_version': 1, 'app_id': '42', 'installer': {'status': installer}})
                _, _, output = self.redo('q\n')
                self.assertEqual('1. Example [ID 42]' in output, offered, output)
                if not offered:
                    self.assertIn('[ID 42]（ツールが入れた記録のないソフト電池がprefixに入っています', output)

    def test_an_installer_record_does_not_explain_a_prefix_made_again(self):
        self.initialize()
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            store.write_record('dependency-installs', 'install-ran.json',
                               {'schema_version': 1, 'app_id': '42', 'installer': {'status': 'exited'}})
        import shutil
        shutil.rmtree(self.game_compat)
        (self.game_compat / 'pfx/drive_c/windows/ucharge').mkdir(parents=True)  # Made again, set up by hand.
        _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（ツールが入れた記録のないソフト電池がprefixに入っています', output)

    def test_every_softdenchi_trace_counts_and_links_are_not_followed(self):
        import shutil
        for trace in ('Program Files/SoftDenchi', 'windows/ucharge'):
            with self.subTest(trace=trace):
                (self.game_compat / 'pfx/drive_c' / trace).mkdir(parents=True)
                _, _, output = self.redo('q\n')
                self.assertIn('[ID 42]（ツールが入れた記録のないソフト電池がprefixに入っています', output)
                shutil.rmtree(self.game_compat)
        elsewhere = self.f.root / 'elsewhere'
        (elsewhere / 'drive_c').mkdir(parents=True)
        self.game_compat.mkdir()
        (self.game_compat / 'pfx').symlink_to(elsewhere)
        _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（prefixの中を読めません', output)

    def test_a_game_started_right_before_the_move_is_not_removed_while_it_runs(self):
        self.initialize()
        clear, busy = {'clear_in_view': True}, {'clear_in_view': False}
        with unittest.mock.patch('preparation_processes.ProcessStopCheck.check', side_effect=[clear, busy]):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix'], report['records']), ('partial', 'in-use', 'retired'), output)
        leftover = Path(report['leftover'])
        self.assertTrue(leftover.is_dir())
        self.assertIn('ゲームを終了してから recovery.sh の7を開くと、残りを消します', output)
        with unittest.mock.patch('preparation_processes.ProcessStopCheck.check', return_value=busy):
            _, _, output = self.redo('q\n')
        self.assertIn('前回消しきれなかったprefixが残っています', output)
        self.assertTrue(leftover.is_dir())
        _, _, output = self.redo('q\n')
        self.assertIn('前回消しきれなかったprefixを消しました（1件）', output)
        self.assertFalse(os.path.lexists(leftover))

    def test_a_failed_save_after_moving_the_records_is_reported(self):
        self.initialize()
        import shutil
        shutil.rmtree(self.game_compat)
        original, calls = PrivateStore.write_record, []

        def failing(store, directory, *args, **kwargs):
            if directory == redo.REDOS:
                calls.append(directory)
                if len(calls) >= 2:
                    raise OSError('full')
            return original(store, directory, *args, **kwargs)
        with unittest.mock.patch.object(PrivateStore, 'write_record', failing):
            status, report, output = self.redo('1\ny\n')
        self.assertEqual((status, report['status'], report['records']), (2, 'partial', 'retired'), output)
        self.assertIn('やり直しの記録を保存できませんでした', output)

    def test_a_failed_sync_after_the_move_still_names_the_hidden_folder(self):
        self.initialize()
        with unittest.mock.patch.object(redo, '_fsync_directory', side_effect=OSError('io')):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix'], report['records']), ('partial', 'moved', 'kept'), output)
        leftover = Path(report['leftover'])
        self.assertTrue(leftover.is_dir())
        self.assertNotIn('prefixはそのままです', output)
        self.assertIn('見えない名前に移しましたが、そのあと途中で止まりました', output)
        self.assertIn('（残ったフォルダーを消します）', output)
        _, report, output = self.redo('1\ny\n')
        self.assertIn('前回消しきれなかったprefixを消しました（1件）', output)
        self.assertFalse(os.path.lexists(leftover))
        self.assertEqual(report['status'], 'done', output)

    def test_a_failed_sync_for_a_prefix_without_records_leaves_nothing_to_choose(self):
        (self.game_compat / 'pfx').mkdir(parents=True)  # Made by a launch before any preparation.
        with unittest.mock.patch.object(redo, '_fsync_directory', side_effect=OSError('io')):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix'], report['retired']), ('partial', 'moved', {}), output)
        self.assertNotIn('選び直して', output)
        _, report, output = self.redo('q\n')
        self.assertIn('前回消しきれなかったprefixを消しました（1件）', output)
        self.assertFalse([line for line in output.splitlines() if line[:1].isdigit() and '[ID 42]' in line], output)
        self.assertNotIn('[ID 42]', output)
        self.assertFalse(os.path.lexists(self.game_compat))

    def test_a_prefix_that_cannot_be_inspected_is_refused(self):
        (self.game_compat / 'pfx/drive_c').mkdir(parents=True)
        (self.game_compat / 'pfx/drive_c/Program Files (x86)').write_text('not a folder')
        _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（prefixの中を読めません', output)
        self.assertTrue(self.game_compat.is_dir())

    def test_a_prefix_that_appears_after_the_confirmation_is_not_removed(self):
        self.initialize()
        import shutil
        shutil.rmtree(self.game_compat)
        import preparation_batch as batch_module
        original = batch_module.confirm

        def launched(*args):
            self.game_compat.mkdir()  # The game was started and closed before the answer.
            return original(*args)
        with unittest.mock.patch.object(batch_module, 'confirm', side_effect=launched):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['reason']), ('stopped', 'changed-since-confirmation'), output)
        self.assertTrue(self.game_compat.is_dir())
        self.assertTrue(self.records('game-prefixes'))

    def test_only_a_folder_named_by_a_redo_record_is_removed_as_a_leftover(self):
        backup = self.game_compat.parent / (redo.REMOVING + 'backup')
        backup.mkdir(parents=True)
        stopped = self.game_compat.parent / (redo.REMOVING + '2' * 32)
        stopped.mkdir()
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            store.write_record(redo.REDOS, 'redo-' + '2' * 32 + '.json',
                               {'schema_version': 1, 'redo_id': 'redo-' + '2' * 32, 'app_id': '42',
                                'status': 'stopped', 'prefix': 'present', 'prefix_name': '42'})
        _, _, output = self.redo('q\n')
        self.assertTrue(backup.is_dir())
        self.assertTrue(stopped.is_dir())
        self.assertNotIn('前回消しきれなかった', output)

    def test_an_interruption_after_moving_the_prefix_can_be_redone(self):
        self.initialize()
        with unittest.mock.patch.object(PrivateStore, 'retire_record', side_effect=OSError('power')):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix'], report['records']), ('partial', 'moved', 'kept'), output)
        self.assertIn('見えない名前に移しましたが、そのあと途中で止まりました', output)
        self.assertIn('一覧にこのゲームがまた出たら、選んで続きを行ってください', output)
        self.assertNotIn('prepare.sh で新しく準備できます', output)
        self.assertFalse(os.path.lexists(self.game_compat))
        self.assertTrue(self.records('game-prefixes'))
        _, report, output = self.redo('1\ny\n')
        self.assertIn('前回消しきれなかったprefixを消しました（1件）', output)
        self.assertEqual((report['status'], report['prefix'], report['retired']), ('done', 'absent', {'game-prefixes': 1}))
        self.assertFalse([path for path in self.game_compat.parent.iterdir() if path.name.startswith(redo.REMOVING)])

    def test_cancel_and_a_running_game_change_nothing(self):
        self.initialize()
        before = self.records('game-prefixes')
        for answer in ('q\n', '1\nn\n', '9\n'):
            with self.subTest(answer=answer):
                self.assertEqual(self.redo(answer)[:2], (0, None))
        busy = {'clear_in_view': False}
        with unittest.mock.patch('preparation_processes.ProcessStopCheck.check', return_value=busy):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['reason']), ('stopped', 'game-or-wine-running'))
        self.assertIn('このゲームかWineが動いています', output)
        self.assertTrue(self.game_compat.is_dir())
        self.assertEqual(before, self.records('game-prefixes'))

    def test_an_interrupted_batch_run_does_not_block_a_redo(self):
        self.initialize()
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            store.write_record(batch.RUNS, 'batch-' + '0' * 32 + '.json',
                               {'schema_version': 1, 'kind': 'batch-run', 'tool_version': '1.0.0',
                                'run_id': 'batch-' + '0' * 32, 'created_ns': 1, 'status': 'running', 'games': []})
        _, report, output = self.redo('1\ny\n')
        self.assertEqual(report['status'], 'done', output)

    def test_a_record_without_a_prefix_can_be_redone(self):
        self.initialize()
        import shutil
        shutil.rmtree(self.game_compat)  # As a stop between saving the record and creating the prefix.
        _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix'], report['retired']), ('done', 'absent', {'game-prefixes': 1}))
        _, _, listed = self.first_screen('q\n')
        self.assertIn('[ID 42] を新しく準備する', listed)

    def test_softdenchi_setups_are_never_offered(self):
        (self.game_compat / 'pfx/drive_c/Program Files (x86)/SoftDenchi').mkdir(parents=True)
        _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（ツールが入れた記録のないソフト電池がprefixに入っています', output)
        import preparation_proton_update as update_module
        chosen = {'config': 'SoftDenchi-Proton-11-12.8-softdenchi3-cleanup2', 'games': None, 'applied': None}
        with unittest.mock.patch.object(update_module, 'current_selection', return_value=chosen):
            _, _, output = self.redo('q\n')
        self.assertIn('[ID 42]（ソフト電池用のProtonが選ばれています', output)
        self.assertTrue(self.game_compat.is_dir())

    def test_a_failure_after_the_first_write_names_the_redo_and_a_leftover_goes_next_time(self):
        self.initialize()
        original = redo._remove_tree
        with unittest.mock.patch.object(redo, '_remove_tree', side_effect=OSError('busy')):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix'], report['error_class']), ('partial', 'moved', 'OSError'))
        self.assertTrue(report['redo_id'].startswith('redo-'))
        leftover = Path(report['leftover'])
        self.assertTrue(leftover.is_dir())
        self.assertIn('消しきれませんでした', output)
        locked = leftover / 'pfx' / 'sealed'
        locked.mkdir(parents=True)
        (locked / 'inner').mkdir()
        (locked / 'inner').chmod(0)
        locked.chmod(0o500)
        _, _, output = self.redo('q\n')
        self.assertIn('前回消しきれなかったprefixを消しました（1件）', output)
        self.assertFalse(os.path.lexists(leftover))
        self.assertIs(redo._remove_tree, original)

    def test_an_incomplete_removal_keeps_the_hidden_leftover_and_the_game_is_new(self):
        self.initialize()
        with unittest.mock.patch.object(redo, '_remove_tree', return_value=False):
            _, report, output = self.redo('1\ny\n')
        self.assertEqual((report['status'], report['prefix']), ('partial', 'removal-incomplete'))
        leftover = Path(report['leftover'])
        self.assertTrue(leftover.name.startswith(redo.REMOVING))
        self.assertTrue(leftover.is_dir())
        self.assertFalse(os.path.lexists(self.game_compat))
        self.assertIn('消しきれませんでした', output)
        _, _, listed = self.first_screen('q\n')
        self.assertIn('[ID 42] を新しく準備する', listed)


@own_tests_only
@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class FinishPlacementTests(BATCH['NewGameBatchTests']):
    def bundle(self):
        return update.bundle_directory(self.config)

    def interrupt(self, phase, status='running', staging=None):
        """Leave a placement record of the bundle slot as an interrupted run would."""
        record = UPDATE['installation_record'](self.bundle(), status=status,
                                                published=phase in ('published', 'post-verified'), phase=phase)
        with PrivateStore(self.f.store_root, create=True) as store, store.locked('e' * 64):
            store.write_record('installations', record['installation_id'] + '.json', record)
        if staging is not None:
            path = self.f.steam / 'compatibilitytools.d' / record['staging_name']
            path.mkdir()
            if staging:
                (path / 'tree').mkdir()
        return record

    def record(self, record):
        with PrivateStore(self.f.store_root) as store:
            return store.read_record('installations', record['installation_id'] + '.json')[0]

    def placed(self):
        with PrivateStore(self.f.store_root) as store:
            return placed_slots(store)[0].get(self.bundle())

    def test_a_published_record_is_finished_and_the_slot_counts_as_placed(self):
        record = self.interrupt('published', staging=False)
        self.assertIsNone(self.placed())  # A running record keeps the slot from counting as placed.
        _, _, listed = self.first_screen('q\n')
        self.assertIn('このProtonを置いた記録を仕上げる', listed)
        status, report, output = self.first_screen('1\n')
        self.assertEqual(status, 2, output)
        self.assertEqual(report['items'][0]['kind'], 'finish-placement')
        self.assertEqual(report['items'][0]['outcome'], 'done', output)
        finished = self.record(record)
        self.assertEqual((finished['status'], finished['phase'], finished['published']),
                         ('installed-tree-verified', 'post-verified', True))
        self.assertIsNotNone(self.placed())
        self.assertFalse(os.path.lexists(self.f.steam / 'compatibilitytools.d' / record['staging_name']))
        _, _, listed = self.first_screen('q\n')
        self.assertNotIn('置いた記録を仕上げる', listed)

    def test_publish_intent_and_needs_inspection_are_finished_and_an_earlier_running_record_fails(self):
        intent = self.interrupt('publish-intent', status='needs-inspection')
        early = self.interrupt('tree-verified', staging=True)
        status, report, output = self.first_screen('1\n')
        self.assertEqual(report['items'][0]['outcome'], 'done', output)
        self.assertEqual(self.record(intent)['status'], 'installed-tree-verified')
        self.assertEqual(self.record(early)['status'], 'failed')
        self.assertTrue((self.f.steam / 'compatibilitytools.d' / early['staging_name'] / 'tree').is_dir())

    def test_a_non_empty_staging_folder_of_a_published_record_is_not_finished(self):
        record = self.interrupt('published', staging=True)
        status, report, output = self.first_screen('1\n')
        entry = report['items'][0]
        self.assertEqual((entry['kind'], entry['outcome'], entry['reason']),
                         ('finish-placement', 'skipped', 'placement-record-not-finished'), output)
        self.assertEqual(entry['state'], 'not-finished')
        self.assertIn('置いた記録の仕上げ: 書き込み前に中止', output)
        self.assertEqual(self.record(record)['status'], 'running')

    def test_a_publish_intent_whose_tree_is_still_staged_did_not_publish(self):
        record = self.interrupt('publish-intent', staging=True)
        other = self.interrupt('published', staging=False)
        status, report, output = self.first_screen('1\n')
        self.assertEqual(report['items'][0]['outcome'], 'done', output)
        closed = self.record(record)
        self.assertEqual((closed['status'], closed['phase'], closed['published']), ('failed', 'tree-verified', False))
        self.assertTrue((self.f.steam / 'compatibilitytools.d' / record['staging_name'] / 'tree').is_dir())
        self.assertEqual(self.record(other)['status'], 'installed-tree-verified')

    def test_a_slot_without_a_record_of_this_tool_is_named_and_not_finished(self):
        # The fixture places the slot with a record; without any, the slot looks placed by something else.
        installations = self.f.store_root / 'installations'
        aside = self.f.root / 'installations-aside'
        installations.rename(aside)
        self.assertIsNone(self.placed())
        _, _, listed = self.first_screen('q\n')
        self.assertIn('このProtonを置いた記録の仕上げ: ツールが置いた記録がありません', listed)
        self.assertNotIn('このProtonを置いた記録を仕上げる', listed)
        aside.rename(installations)
        _, _, listed = self.first_screen('q\n')
        self.assertNotIn('ツールが置いた記録がありません', listed)
        self.interrupt('published', staging=False)
        _, _, listed = self.first_screen('q\n')
        self.assertNotIn('ツールが置いた記録がありません', listed)
        self.first_screen('1\n')
        _, _, listed = self.first_screen('q\n')
        self.assertNotIn('ツールが置いた記録がありません', listed)

    def test_a_post_verified_record_left_for_inspection_is_finished(self):
        record = self.interrupt('post-verified', status='needs-inspection')
        status, report, output = self.first_screen('1\n')
        self.assertEqual(report['items'][0]['outcome'], 'done', output)
        self.assertEqual(self.record(record)['status'], 'installed-tree-verified')
        self.assertIsNotNone(self.placed())

    def test_a_partly_finished_placement_is_shown_as_such(self):
        self.interrupt('published', staging=True)
        self.interrupt('published', staging=False)
        status, report, output = self.first_screen('1\n')
        self.assertEqual(report['items'][0]['state'], 'partial', output)
        self.assertIn('置いた記録の仕上げ: 一部だけ仕上げ・要確認', output)

    def test_a_changed_slot_is_never_finished(self):
        record = self.interrupt('published')
        tool = self.f.steam / 'compatibilitytools.d' / self.bundle()
        (tool / 'files' / 'extra.txt').write_text('changed')
        status, report, output = self.first_screen('1\n')
        self.assertEqual(status, 1, output)
        self.assertNotIn('置いた記録を仕上げる', output)
        self.assertEqual(self.record(record)['status'], 'running')

if __name__ == '__main__':
    unittest.main()
