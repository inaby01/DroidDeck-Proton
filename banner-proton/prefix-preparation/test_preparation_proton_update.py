#!/usr/bin/env python3
"""Moving a prepared game between preparation slots (0.31.0, design: Proton update 4)."""

import hashlib
import io
import json
import os
import runpy
import shutil
import sys
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
ONE = runpy.run_path(str(HERE / 'test_preparation_one_pass.py'))
import preparation_proton_update as update
from preparation_binding import apply_binding, plan_binding
from preparation_common import Invalid
from preparation_store import PrivateStore


def installation_record(directory, status='installed-tree-verified', published=True, phase='post-verified'):
    token = os.urandom(16).hex()
    return {'schema_version': 1, 'tool_version': update.VERSION,
            'installation_id': 'installation-' + token, 'app_id': '42', 'input_digest': 'b' * 64, 'status': status,
            'phase': phase, 'staging_name': '.prefix-preparation-staging-' + token, 'directory': directory,
            'published': published, 'preparation_complete': False, 'created_ns': 1}


class ProtonUpdateUnitTests(unittest.TestCase):
    def test_points_to_and_tool_ids(self):
        slot = 'SoftDenchi-Prep-Proton 11-12.8-softdenchi3-beta2'
        tool = update.tool_id_of(slot)
        self.assertEqual(tool, 'SoftDenchi-Prep-Proton-11-12.8-softdenchi3-beta2')
        self.assertTrue(update.points_to({'valve': False, 'dir': slot}, slot, tool))
        self.assertTrue(update.points_to({'valve': False, 'dir': slot, 'name': tool}, slot, tool))
        self.assertFalse(update.points_to({'valve': False, 'dir': slot, 'name': 'other'}, slot, tool))
        self.assertFalse(update.points_to({'valve': True, 'dir': slot}, slot, tool))
        self.assertFalse(update.points_to(None, slot, tool))

    def test_prefix_version_from_the_real_proton_script(self):
        script = next(path for path in (HERE.parent / 'proton', HERE.parent.parent / 'proton') if path.is_file())
        raw = script.read_bytes()
        self.assertEqual(update.proton_prefix_version(raw), '11.0-100')  # Many lines mention it; one assigns it.
        self.assertTrue(update.prefix_version_matches(raw, b'11.0-100\n'))
        self.assertFalse(update.prefix_version_matches(raw, b'11.0-101\n'))
        self.assertFalse(update.prefix_version_matches(raw + b'\nCURRENT_PREFIX_VERSION="12.0-1"\n', b'11.0-100\n'))
        self.assertFalse(update.prefix_version_matches(b'CURRENT_PREFIX_VERSION="x"\n', b'x\n'))
        self.assertFalse(update.prefix_version_matches(None, b'11.0-100\n'))
        self.assertFalse(update.prefix_version_matches(raw, None))

    def test_history_state_rules(self):
        verified = {'status': 'binding-verified', 'completed_files': ['games']}
        empty_failure = {'status': 'binding-failed', 'completed_files': []}
        self.assertEqual(update.history_state([verified, empty_failure]), (True, None))
        self.assertEqual(update.history_state([verified, {'status': 'binding-failed', 'completed_files': ['games']}])[0], False)
        self.assertEqual(update.history_state([verified, {'status': 'binding-running', 'completed_files': []}])[0], False)
        self.assertEqual(update.history_state([empty_failure]), (False, 'no-verified-binding'))


class MoveFixture:
    """A game prepared on an older slot this tool placed (mixed into a one-pass fixture)."""

    def setUp(self):
        super().setUp()
        _, report, output, _ = self.run_detail('12\n1\n1\n1\n')
        self.assertEqual(report['status'], 'ready-to-launch', output)
        self.forget_first_note()
        self.bundle = update.bundle_directory(self.config)
        self.tools = self.f.steam / 'compatibilitytools.d'
        self.assertTrue((self.tools / self.bundle).is_dir(), list(self.tools.iterdir()))
        self.old = self.bundle + '-old'
        self.make_old_slot(self.old)
        self.config['supersedes'] = [self.old]
        self.assign_old(self.old)

    def forget_first_note(self):
        """Make the first binding look like one of 0.30.0 (no supplementary record), as on the device."""
        for path in (self.f.store_root / 'bindings').glob('binding-*.json'):
            record = json.loads(path.read_text())
            record['tool_version'] = '0.30.0'
            path.write_text(json.dumps(record, sort_keys=True, ensure_ascii=True, indent=2) + '\n')
            (self.f.store_root / update.NOTES / path.name).unlink()

    def make_old_slot(self, name, record=True):
        shutil.copytree(self.tools / self.bundle, self.tools / name, symlinks=True)
        catalog = self.tools / name / 'compatibilitytool.vdf'
        catalog.write_text(catalog.read_text().replace(update.tool_id_of(self.bundle), update.tool_id_of(name)))
        if record:
            with PrivateStore(self.f.store_root) as store, store.locked('c' * 64):
                store.write_record('installations', 'old-' + os.urandom(4).hex() + '.json', installation_record(name))

    def lock(self):
        return hashlib.sha256(str(self.game_compat).encode()).hexdigest()

    def assign_old(self, name, kind='apply'):
        """Assign the game to ``name`` like an earlier bundle did, and link its layout there."""
        with PrivateStore(self.f.store_root) as store, store.locked(self.lock()):
            plan = plan_binding(self.f.steam, self.f.settings, '42', name)

            def ready():
                return {'target': True, 'dependencies': True, 'payload': True, 'stopped': True}

            def on_binding_id(run_id):
                update.write_note(store, update.note(run_id, '42', 'apply', name, None, plan))
            apply_binding(plan, self.f.steam, self.f.settings, store, ready, on_binding_id=on_binding_id)
        link = self.game_compat / 'pfx/drive_c/windows/syswow64/cmd.exe'
        link.unlink()
        link.symlink_to(self.tools / name / 'files/lib/wine/i386-windows/cmd.exe')

    def move_menu(self, text):
        output = io.StringIO()
        with unittest.mock.patch('preparation_softdenchi_recipe.softdenchi_recipe', return_value=self.recipe):
            status, name = self.run_move(text, output)
        report = json.loads(Path(name if os.path.isabs(name) else self.f.fixture.source.root / name).read_bytes()) \
            if name else None
        return status, report, output.getvalue()

    def run_move(self, text, output):
        return update.interactive_move(
            self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config, input_stream=io.StringIO(text),
            output_stream=output, environment=self.environment, steam=self.f.steam, settings=self.f.settings,
            home=self.home, runtime_root=self.f.root)

    def selection(self):
        with PrivateStore(self.f.store_root) as store:
            plan = plan_binding(self.f.steam, self.f.settings, '42', self.bundle)
            items, _ = update.history(store, '42')
            _, placed = update.placed_roots(store, self.f.steam, self.bundle)
            return update.classify(plan.before, '42', self.bundle, placed, self.f.steam,
                                   tuple(self.config.get('supersedes', ())), items)


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class MoveTests(MoveFixture, ONE['OnePassTests']):
    """A game prepared on an older slot this tool placed is moved to the bundle slot."""

    def test_move_writes_the_three_files_and_a_note(self):
        self.assertEqual(self.selection()['kind'], 'move')
        self.assertTrue(self.selection()['batch'])
        status, report, output = self.move_menu('1\n1\n')
        self.assertEqual(status, 2, output)
        self.assertTrue(report['binding_written'], report)
        self.assertIn('最初の起動は、prefixの更新で長くなることがあります', output)
        self.assertIn('同期のコマンドは要りません', output)
        self.assertEqual(self.selection()['kind'], 'bound')
        with PrivateStore(self.f.store_root) as store:
            items, orphans = update.history(store, '42')
        moved = [item for item in items if item['note'] and item['note']['note_kind'] == 'move']
        self.assertEqual(len(moved), 1)
        self.assertEqual((moved[0]['note']['directory'], moved[0]['note']['previous_directory']), (self.bundle, self.old))
        self.assertEqual(orphans, [])

    def test_a_slot_not_in_the_list_is_movable_only_one_by_one(self):
        self.config['supersedes'] = []
        decision = self.selection()
        self.assertEqual((decision['kind'], decision['batch'], decision['reason']),
                         ('move', False, 'not-superseded-by-this-bundle'))
        _, report, output = self.move_menu('1\n1\n')
        self.assertIn('置き換える版ではありません', output)
        self.assertTrue(report['binding_written'], output)

    def test_slots_this_tool_did_not_place_are_not_offered(self):
        other = self.bundle + '-foreign'
        self.make_old_slot(other, record=False)
        self.assign_old(other)
        self.assertEqual(self.selection()['reason'], 'slot-not-placed-by-this-tool')
        _, report, output = self.move_menu('')
        self.assertIn('移せるゲームはありません', output)
        self.assertEqual(report['status'], 'nothing-to-move')

    def test_unregistered_old_slot_is_not_offered(self):
        (self.tools / self.old / 'droiddeck-proton-wrap').unlink()
        self.assertEqual(self.selection()['reason'], 'slot-folder-missing-or-unregistered')

    def test_align_keeps_the_screen_choice_and_games_json(self):
        # The DroidDeck screen chose the bundle slot; config.vdf and games_applied still name the old slot (4.6).
        games = json.loads(self.games_config.read_text())
        games['games']['42'] = {'valve': False, 'dir': self.bundle, 'name': update.tool_id_of(self.bundle)}
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        before = (self.games_config.read_bytes(), self.games_config.stat().st_mtime_ns, self.games_config.stat().st_ino)
        decision = self.selection()
        self.assertEqual((decision['kind'], decision['batch']), ('align', True))
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertEqual(before, (self.games_config.read_bytes(), self.games_config.stat().st_mtime_ns,
                                  self.games_config.stat().st_ino))
        self.assertEqual(self.selection()['kind'], 'bound')

    def test_reverse_screen_choice_is_never_written(self):
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)
        games = json.loads(self.games_config.read_text())
        games['games']['42'] = {'valve': False, 'dir': self.old}
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        self.assertEqual(self.selection()['kind'], 'screen-other')
        _, report, output = self.move_menu('')
        self.assertIn('移せるゲームはありません', output)

    def test_returned_game_is_not_moved_by_the_batch(self):
        self.move_menu('1\n1\n')
        self.assign_old(self.old)  # Back to the old slot (like a revert), with a note naming that slot.
        with PrivateStore(self.f.store_root) as store, store.locked(self.lock()):
            plan = plan_binding(self.f.steam, self.f.settings, '42', self.old)
            items, _ = update.history(store, '42')
        self.assertTrue(update.touched(items, self.bundle))
        decision = self.selection()
        self.assertEqual((decision['kind'], decision['batch'], decision['reason']),
                         ('move', False, 'returned-from-this-slot'))
        self.assertIsNotNone(plan)

    def test_missing_note_of_a_new_record_stops_the_batch(self):
        with PrivateStore(self.f.store_root) as store:
            items, _ = update.history(store, '42')
        newest = [item for item in items if item['note'] and item['note']['directory'] == self.old][-1]
        (self.f.store_root / update.NOTES / (newest['binding_id'] + '.json')).unlink()
        decision = self.selection()
        self.assertEqual((decision['kind'], decision['batch'], decision['reason']), ('move', False, 'binding-note-missing'))

    def test_different_prefix_version_stops_before_writing(self):
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'proton_prefix_version', return_value='2.0-1'):
            _, report, output = self.move_menu('1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('prefix-version-differs', report.get('blockers', []) + [report.get('reason')], report)
        self.assertEqual(before, self.games_config.read_bytes())

    def test_change_after_confirmation_stops_under_the_lock(self):
        original = update.classify
        calls = []

        def changed(*args, **kwargs):
            calls.append(1)
            result = original(*args, **kwargs)
            return dict(result, source='SoftDenchi-Prep-Proton changed') if len(calls) > 1 else result
        with unittest.mock.patch.object(update, 'classify', side_effect=changed):
            _, report, output = self.move_menu('1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('move decision changed', json.dumps(report, ensure_ascii=False))
        self.assertEqual(self.selection()['kind'], 'move')

    def test_writers_cannot_assign_the_wrong_slot(self):
        with PrivateStore(self.f.store_root) as store, store.locked(self.lock()):
            plan = plan_binding(self.f.steam, self.f.settings, '42', self.old)
            ready = lambda: {'target': True, 'dependencies': True, 'payload': True, 'stopped': True}
            with self.assertRaisesRegex(Invalid, 'only assign the bundle slot'):
                apply_binding(plan, self.f.steam, self.f.settings, store, ready, bundle_directory=self.bundle)
            back = plan_binding(self.f.steam, self.f.settings, '42', self.bundle)
            with self.assertRaisesRegex(Invalid, 'cannot assign the bundle slot'):
                apply_binding(back, self.f.steam, self.f.settings, store, lambda: {'target': True, 'stopped': True,
                              'slot_record': True}, kind='revert', bundle_directory=self.bundle)
            with self.assertRaisesRegex(Invalid, 'prerequisites not verified|unknown or missing fields'):
                apply_binding(plan, self.f.steam, self.f.settings, store, ready, kind='revert', bundle_directory=self.bundle)



@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class DllMoveTests(MoveFixture, ONE['PrefixDllOnePassTests']):
    """With MFC42 in the prefix: the x86 layout still links into the old slot until the first launch (4.4)."""

    def test_previous_slot_link_is_accepted_for_the_move_only(self):
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertIn('previous-slot-link', output)
        layouts = [item.get('layout') for item in report['plan']['dependencies']]
        self.assertIn('previous-slot-link', layouts)

    def test_a_link_into_an_unplaced_slot_stops_the_move(self):
        other = self.bundle + '-foreign'
        self.make_old_slot(other, record=False)
        link = self.game_compat / 'pfx/drive_c/windows/syswow64/cmd.exe'
        link.unlink()
        link.symlink_to(self.tools / other / 'files/lib/wine/i386-windows/cmd.exe')
        _, report, output = self.move_menu('1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('x86 system directory not confirmed', output)



@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class RevertTests(MoveFixture, ONE['OnePassTests']):
    """A game moved from an older slot (with saved verification data) is assigned back to it (4.7, 4.8)."""

    def setUp(self):
        super().setUp()
        self.save_manifest(self.old)
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)

    def payload(self):
        import preparation_selection as selection
        from preparation_installation import CAPTURE
        from preparation_payload import inspect_archive_from_folder
        payload = self.config['payload']
        return inspect_archive_from_folder(selection._archive(self.f.fixture.source.root, payload), payload['sha512'],
                                           payload['root'], capture=CAPTURE)

    def save_manifest(self, name):
        import preparation_slot_manifest as manifest
        from preparation_payload import OVERLAY_NAMES
        inventory = self.payload()
        overlays = {}
        for item in sorted(OVERLAY_NAMES):
            path = self.tools / name / item
            if path.is_file():
                raw = path.read_bytes()
                overlays[item] = {'kind': 'file', 'mode': path.stat().st_mode & 0o7777, 'size': len(raw),
                                  'sha256': hashlib.sha256(raw).hexdigest()}
        record = manifest.build(name, update.tool_id_of(name), inventory, overlays,
                                inventory.captured['version'].decode().strip())
        with PrivateStore(self.f.store_root) as store, store.locked('d' * 64):
            self.assertEqual(manifest.save(store, name, record), 'created')

    def add_cache(self, name, body=b'synthetic bytecode, never executed'):
        """A CPython cache beside the slot's generated user_settings.py (as after a normal launch)."""
        import importlib.util
        import struct
        source = self.tools / name / 'user_settings.py'
        info = source.stat()
        cache = source.parent / '__pycache__'
        cache.mkdir(mode=0o755, exist_ok=True)
        pyc = cache / ('user_settings.' + sys.implementation.cache_tag + '.pyc')
        pyc.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(info.st_mtime), info.st_size) + body)
        pyc.chmod(0o644)
        return cache

    def revert_menu(self, text, **extra):
        output = io.StringIO()
        status, name = update.interactive_revert(
            self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config, input_stream=io.StringIO(text),
            output_stream=output, environment=self.environment, steam=self.f.steam, settings=self.f.settings,
            home=self.home, runtime_root=self.f.root, **extra)
        report = json.loads(Path(name if os.path.isabs(name) else self.f.fixture.source.root / name).read_bytes()) \
            if name else None
        return status, report, output.getvalue()

    def test_revert_assigns_the_old_slot_and_moves_its_caches(self):
        cache = self.add_cache(self.old)
        files = sorted(item.name for item in cache.iterdir())
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertIn('このProtonへ移す前のProton', output)
        self.assertIn('実機ではまだ確かめていません', output)
        self.assertIn('Pythonキャッシュ（1か所）', output)
        self.assertFalse(cache.exists())
        with PrivateStore(self.f.store_root) as store:
            items, orphans = update.history(store, '42')
        reverted = [item['note'] for item in items if item['note'] and item['note']['note_kind'] == 'revert']
        self.assertEqual(len(reverted), 1)
        self.assertEqual((reverted[0]['directory'], reverted[0]['previous_directory']), (self.old, self.bundle))
        moved = reverted[0]['cache_move']['moved']
        self.assertEqual([item['name'] for item in moved], ['c0001'])
        kept = self.f.store_root / update.CACHES / reverted[0]['binding_id'] / 'c0001'
        self.assertEqual(sorted(item.name for item in kept.iterdir()), files)
        self.assertEqual(orphans, [])
        current = update.current_selection(update.current_files(self.f.steam, self.f.settings), '42')
        self.assertEqual(current['config'], update.tool_id_of(self.old))
        # Back on the old slot after a revert from this slot: the batch run does not move it again.
        self.assertEqual(self.selection()['reason'], 'returned-from-this-slot')

    def test_slot_without_saved_data_is_not_a_target(self):
        import preparation_slot_manifest as manifest
        (self.f.store_root / manifest.DIRECTORY / manifest.record_name(self.old)).unlink()
        _, report, output = self.revert_menu('1\n')
        self.assertIn('戻す先にできる準備用Protonがありません', output)
        self.assertEqual(report['refused_targets'], {self.old: 'slot-manifest-missing'})

    def test_changed_slot_is_not_a_target(self):
        (self.tools / self.old / 'files' / 'extra.txt').write_text('changed')
        _, report, _ = self.revert_menu('1\n')
        self.assertEqual(report['refused_targets'], {self.old: 'slot-differs-from-saved-data'})

    def test_different_prefix_version_stops(self):
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'proton_prefix_version', return_value='2.0-1'):
            _, report, output = self.revert_menu('1\n1\n')
        self.assertIn('prefix-version-differs', report['blockers'], output)
        self.assertEqual(before, self.games_config.read_bytes())

    def test_a_process_using_the_target_slot_stops(self):
        import subprocess
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)', str(self.tools / self.old / 'proton')])
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        before = self.games_config.read_bytes()
        _, report, output = self.revert_menu('1\n1\n')
        self.assertIn('target-slot-in-use', report['blockers'], output)
        self.assertEqual(before, self.games_config.read_bytes())

    def test_broken_bundle_slot_does_not_prevent_the_revert(self):
        (self.tools / self.bundle / 'droiddeck-proton-wrap').unlink()
        (self.tools / self.bundle / 'compatibilitytool.vdf').write_text('broken')
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)

    def test_refused_rename_keeps_the_settings_and_the_cache(self):
        cache = self.add_cache(self.old)
        import preparation_publication as publication
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(publication, 'rename_noreplace', side_effect=OSError(18, 'refused')):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertEqual(before, self.games_config.read_bytes())
        self.assertTrue(cache.is_dir())
        with PrivateStore(self.f.store_root) as store:
            items, orphans = update.history(store, '42')
        self.assertFalse(any(item['status'] == 'binding-running' for item in items))
        self.assertEqual([record['cache_move']['moved'] for record in orphans], [[]])

    def test_interrupted_move_leaves_no_running_binding_and_can_be_finished(self):
        self.add_cache(self.old)
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'move_caches', side_effect=OSError(18, 'refused')):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertEqual(before, self.games_config.read_bytes())
        with PrivateStore(self.f.store_root) as store:
            items, orphans = update.history(store, '42')
        self.assertFalse(any(item['status'] == 'binding-running' for item in items))
        self.assertEqual(len(orphans), 1)
        self.assertEqual(orphans[0]['note_kind'], 'revert')
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)

    def test_change_of_caches_after_confirmation_stops(self):
        cache = self.add_cache(self.old)
        original = update.list_caches
        calls = []

        def changed(root):
            calls.append(1)
            result = original(root)
            if len(calls) == 2:
                (cache / 'extra.cpython-314.pyc').write_bytes(b'x')
            return result
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'list_caches', side_effect=changed):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertEqual(before, self.games_config.read_bytes())


# Only the fixtures of the one-pass tests are reused, not their tests.
for _class, _base in ((MoveTests, ONE['OnePassTests']), (DllMoveTests, ONE['PrefixDllOnePassTests']),
                      (RevertTests, ONE['OnePassTests'])):
    for _name in dir(_base):
        if _name.startswith('test_') and _name not in _class.__dict__:
            setattr(_class, _name, None)
del _class, _base, _name  # Loop names must not be collected as test classes.


if __name__ == '__main__':
    unittest.main()
