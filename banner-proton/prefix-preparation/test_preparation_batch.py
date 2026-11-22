#!/usr/bin/env python3
"""The 0.31.0 first screen: the list of what this bundle would do, run after one confirmation."""

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

        def partial(ctx, item, journal):
            calls.append(item['kind'])
            return 'partial', {'report': {'status': 'stopped', 'reason': 'synthetic'}}
        with unittest.mock.patch.object(batch, '_run_one_pass', side_effect=partial), \
                unittest.mock.patch.object(batch, '_save_manifest', side_effect=batch._save_manifest) as saved:
            _, _, output = self.first_screen('1\n')
        self.assertEqual(calls, ['new'])
        self.assertTrue(saved.called)
        self.assertIn('一部適用・要確認', output)
        self.assertIn('再実行では飛ばされます', output)

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
        self.assertIn('[ID 42] を新しく準備する', output.split('新しいProtonを置きました', 1)[1])
        self.assertIn('取り消しました（新しいProtonは置いたままです）', output)
        self.assertFalse(self.game_compat.exists())


# Only the fixtures of the one-pass tests are reused, not their tests.
for _class in (NewGameBatchTests, MoveBatchTests, PlacementBatchTests):
    for _name in dir(ONE['OnePassTests']):
        if _name.startswith('test_') and _name not in _class.__dict__:
            setattr(_class, _name, None)
del _class, _name


if __name__ == '__main__':
    unittest.main()
