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

    def test_only_the_caches_the_verification_accepted_are_listed(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir='/tmp') as root:
            root = Path(root)
            for name in ('shipped/__pycache__', 'lib/__pycache__'):
                (root / name).mkdir(parents=True)
                (root / name / 'module.cpython-314.pyc').write_bytes(b'x')
            self.assertEqual(update.list_caches(root, {'python_caches': None}), [])
            found = update.list_caches(root, {'python_caches': {'directories': {'lib/__pycache__': {}}}})
            self.assertEqual([item['relative'] for item in found], ['lib/__pycache__'])
            self.assertEqual(list(found[0]['files']), ['module.cpython-314.pyc'])
            with self.assertRaises(Invalid):
                update.list_caches(root, {'python_caches': {'directories': {'lib/../shipped/__pycache__': {}}}})

    def test_supplementary_records_are_checked_to_the_cache_move(self):
        import types
        slot, previous = 'SoftDenchi-Prep-Proton b', 'SoftDenchi-Prep-Proton a'
        plan = types.SimpleNamespace(before={name: b'old' for name in update.FILES},
                                     after={name: b'new' for name in update.FILES})
        binding_id = 'binding-' + '0' * 32
        planned = [{'relative': '__pycache__', 'device': 1, 'inode': 2, 'files': {'a.pyc': '0' * 64}}]
        good = update.note(binding_id, '42', 'revert', slot, previous, plan,
                           cache_move={'planned': planned, 'moved': [{'relative': '__pycache__', 'name': 'c0001'}],
                                       'destination': update.CACHES + '/' + binding_id})
        update.validate_note(good)
        bad = [
            lambda r: r['cache_move'].update(destination='slot-caches/other'),
            lambda r: r['cache_move'].update(moved=[{'relative': 'other/__pycache__', 'name': 'c0001'}]),
            lambda r: r['cache_move'].update(moved=[{'relative': '__pycache__', 'name': 'c0002'}]),
            lambda r: r['cache_move']['planned'][0].update(relative='../__pycache__'),
            lambda r: r['cache_move']['planned'][0].update(files={'a.pyc': 7}),
            lambda r: r['cache_move'].pop('planned'),
            lambda r: r['files']['games'].update(after_sha256=None),
            lambda r: r['files']['games'].update(present_before=False),
            lambda r: r.update(note_kind='move'),
        ]
        for change in bad:
            record = json.loads(json.dumps(good))
            change(record)
            with self.subTest(record=record), self.assertRaises((Invalid, KeyError, TypeError, ValueError)):
                update.validate_note(record)

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

    def test_slot_users_by_executable_working_directory_or_path_argument(self):
        import tempfile

        from preparation_processes import observe_slot_users
        with tempfile.TemporaryDirectory(dir='/tmp') as folder:
            base = Path(folder)
            slot = base / 'tools' / 'SoftDenchi-Prep-Proton x-beta1'
            other = base / 'tools' / 'SoftDenchi-Prep-Proton x-beta10'
            for path in (slot, other):
                path.mkdir(parents=True)
                (path / 'proton').write_text('#')
            (base / 'link').symlink_to(slot)
            proc = base / 'proc'
            (proc / str(os.getpid())).mkdir(parents=True)

            def process(pid, argv, cwd=base, exe='/usr/bin/python3', cmdline=True):
                entry = proc / str(pid)
                entry.mkdir()
                (entry / 'stat').write_text(f'{pid} (python3) S ' + ' '.join(['1'] * 25))
                if cmdline:
                    (entry / 'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in argv) + b'\0')
                (entry / 'exe').symlink_to(exe)
                (entry / 'cwd').symlink_to(cwd)

            process(100, ['python3', str(other / 'proton'), 'run'])  # beta10 is not beta1.
            self.assertEqual(observe_slot_users(slot, proc)['users'], 0)
            process(101, ['python3', 'SoftDenchi-Prep-Proton x-beta1/proton'], cwd=base / 'tools')  # Relative.
            process(102, ['python3', str(base / 'link' / 'proton')])  # Through a symbolic link.
            process(103, ['python3'], cwd=slot)  # Working directory.
            process(104, ['wine'], exe=str(slot / 'proton'))  # Executable.
            found = observe_slot_users(slot, proc)
            self.assertEqual((found['users'], found['unknown'], found['clear']), (4, 0, False))
            process(105, [], cmdline=False)  # Unreadable process of the same owner.
            self.assertEqual(observe_slot_users(other, proc)['unknown'], 1)
            self.assertFalse(observe_slot_users(other, proc)['clear'])

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
            apply_binding(plan, self.f.steam, self.f.settings, store, ready, bundle_directory=name,
                          on_binding_id=on_binding_id)
        link = self.game_compat / 'pfx/drive_c/windows/syswow64/cmd.exe'
        link.unlink()
        link.symlink_to(self.tools / name / 'files/lib/wine/i386-windows/cmd.exe')

    def status_report(self):
        from preparation_status import interactive_status
        output = io.StringIO()
        with unittest.mock.patch('preparation_softdenchi_recipe.softdenchi_recipe', return_value=self.recipe):
            _, name = interactive_status(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
                                         output_stream=output, environment=self.environment, steam=self.f.steam,
                                         settings=self.f.settings, home=self.home, runtime_root=self.f.root)
        report = json.loads(Path(name if os.path.isabs(name) else self.f.fixture.source.root / name).read_bytes())
        return next(item for item in report['games'] if item['app_id'] == '42'), output.getvalue()

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
        with PrivateStore(self.f.store_root) as store:
            self.assertIn(self.tools / self.old, update.placed_roots(store, self.f.steam, self.bundle)[0])
        (self.tools / self.old / 'droiddeck-proton-wrap').unlink()
        self.assertEqual(self.selection()['reason'], 'slot-folder-missing-or-unregistered')
        with PrivateStore(self.f.store_root) as store:  # Nor accepted by the layout check (4.4, same conditions).
            self.assertNotIn(self.tools / self.old, update.placed_roots(store, self.f.steam, self.bundle)[0])

    def test_unreadable_binding_record_is_listed_with_its_reason(self):
        path = self.f.store_root / 'bindings' / ('binding-' + 'f' * 32 + '.json')
        path.write_bytes(b'{')
        path.chmod(0o600)
        _, report, output = self.move_menu('')
        self.assertIn('移せるゲームはありません', output)
        self.assertIn(update.UNREADABLE_TEXT + 'ID 42', output)
        self.assertEqual([item['app_id'] for item in report['unreadable_games']], ['42'])

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

    def test_aligned_choice_with_the_tool_id_counts_as_bound(self):
        games = json.loads(self.games_config.read_text())
        games['games']['42'] = {'valve': False, 'dir': self.bundle, 'name': update.tool_id_of(self.bundle)}
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)
        entry, text = self.status_report()
        self.assertEqual(entry['assignment']['kind'], 'this-slot', text)
        _, again, _, _ = self.run_detail('12\n1\n1\n')
        self.assertEqual(again['status'], 'ready-to-launch', again)

    def test_alignment_of_a_slot_not_replaced_is_one_by_one(self):
        self.config['supersedes'] = []
        games = json.loads(self.games_config.read_text())
        games['games']['42'] = {'valve': False, 'dir': self.bundle}
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        decision = self.selection()
        self.assertEqual((decision['kind'], decision['batch'], decision['reason']),
                         ('align', False, 'not-superseded-by-this-bundle'))

    def test_a_failed_binding_after_writing_is_never_aligned(self):
        games = json.loads(self.games_config.read_text())
        games['games']['42'] = {'valve': False, 'dir': self.bundle}
        self.games_config.write_text(json.dumps(games, indent=2) + '\n')
        with PrivateStore(self.f.store_root) as store, store.locked(self.lock()):
            store.write_record('bindings', 'binding-' + 'a' * 32 + '.json',
                               {'schema_version': 1, 'tool_version': update.VERSION, 'binding_id': 'binding-' + 'a' * 32,
                                'app_id': '42', 'input_digest': 'c' * 64, 'status': 'binding-failed',
                                'completed_files': ['games'], 'preparation_complete': False})
        self.assertEqual((self.selection()['kind'], self.selection()['reason']), ('other', 'binding-failed-after-writing'))

    def test_binding_records_keep_the_shape_earlier_tools_read(self):
        self.move_menu('1\n1\n')
        for path in (self.f.store_root / 'bindings').glob('binding-*.json'):
            self.assertEqual(set(json.loads(path.read_text())), {
                'schema_version', 'tool_version', 'binding_id', 'app_id', 'input_digest', 'status', 'completed_files',
                'preparation_complete'})
        with PrivateStore(self.f.store_root) as store:
            self.assertEqual(set(store.inventory()), {
                'assets', 'bindings', 'installations', 'dependency_installs',
                'game_prefixes', 'prefix_dlls', 'backups', 'temporary_records'})

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

    def test_a_game_no_longer_for_the_batch_is_not_moved_by_its_confirmed_decision(self):
        decision = self.selection()
        self.assertTrue(decision['batch'])
        changed = dict(decision, batch=False, reason='returned-from-this-slot')  # As after a move and a revert elsewhere.
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'classify', return_value=changed), PrivateStore(self.f.store_root) as store:
            check = update.move_check(store, self.f.steam, self.config, '42', decision)
            with self.assertRaisesRegex(Invalid, 'move decision changed'):
                check(plan_binding(self.f.steam, self.f.settings, '42', self.bundle))
        self.assertEqual(before, self.games_config.read_bytes())

    def test_the_whole_config_entry_is_a_confirmed_item(self):
        files = update.current_files(self.f.steam, self.f.settings)
        before = update.target_items(files, '42')
        self.assertEqual(before['config_entry']['name'], update.tool_id_of(self.old))
        config = self.f.steam / 'config/config.vdf'
        raw = config.read_bytes()
        text = raw.decode()
        marker = '"name"'
        index = text.index(marker, text.index('"42"'))
        config.write_bytes((text[:index] + '"extra_setting" "250"\n' + text[index:]).encode())
        after = update.target_items(update.current_files(self.f.steam, self.f.settings), '42')
        self.assertNotEqual(before, after)
        self.assertEqual(after['config_entry']['extra_setting'], '250')
        config.write_bytes(raw)

    def test_writers_cannot_assign_the_wrong_slot(self):
        with PrivateStore(self.f.store_root) as store, store.locked(self.lock()):
            plan = plan_binding(self.f.steam, self.f.settings, '42', self.old)
            ready = lambda: {'target': True, 'dependencies': True, 'payload': True, 'stopped': True}
            with self.assertRaisesRegex(Invalid, 'only assign the bundle slot'):
                apply_binding(plan, self.f.steam, self.f.settings, store, ready, bundle_directory=self.bundle,
                              on_binding_id=lambda run_id: None)
            back = plan_binding(self.f.steam, self.f.settings, '42', self.bundle)
            with self.assertRaisesRegex(Invalid, 'cannot assign the bundle slot'):
                apply_binding(back, self.f.steam, self.f.settings, store, lambda: {'target': True, 'stopped': True,
                              'slot_record': True}, kind='revert', bundle_directory=self.bundle,
                              on_binding_id=lambda run_id: None)
            with self.assertRaisesRegex(Invalid, 'prerequisites not verified|unknown or missing fields'):
                apply_binding(plan, self.f.steam, self.f.settings, store, ready, kind='revert', bundle_directory=self.bundle,
                              on_binding_id=lambda run_id: None)
            # Neither the bundle slot nor the supplementary record can be left out (a record without its note).
            for missing in ({'bundle_directory': None, 'on_binding_id': lambda run_id: None},
                            {'bundle_directory': self.old, 'on_binding_id': None}):
                with self.assertRaisesRegex(Invalid, 'bundle slot and supplementary record required'):
                    apply_binding(plan, self.f.steam, self.f.settings, store, ready, **missing)



@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class DllMoveTests(MoveFixture, ONE['PrefixDllOnePassTests']):
    """With MFC42 in the prefix: the x86 layout still links into the old slot until the first launch (4.4)."""

    def test_previous_slot_link_is_accepted_for_the_move_only(self):
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertIn('previous-slot-link', output)
        layouts = [item.get('layout') for item in report['plan']['dependencies']]
        self.assertIn('previous-slot-link', layouts)

    def test_moved_game_is_ready_before_its_first_launch(self):
        _, report, output = self.move_menu('1\n1\n')
        self.assertTrue(report['binding_written'], output)
        entry, text = self.status_report()
        self.assertEqual(entry['next']['next'], 'ready', text)
        layouts = [item.get('layout') for step in entry.get('evaluated_steps', []) if step['step'] == 'prefix-dll'
                   for item in [step['plan']['state']]]
        self.assertIn('previous-slot-link', layouts, text)
        _, again, _, commands = self.run_detail('12\n1\n1\n')
        self.assertEqual(again['status'], 'ready-to-launch', again)
        self.assertEqual(commands, [])

    def test_an_old_slot_builtin_that_is_not_x86_stops_the_move(self):
        member = self.tools / self.old / 'files/lib/wine/i386-windows/cmd.exe'
        member.chmod(0o644)
        member.write_bytes(ONE['DEP']['X64'])
        _, report, output = self.move_menu('1\n')
        self.assertFalse(report.get('binding_written'), output)

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

    def status_output(self):
        from preparation_status import interactive_status
        output = io.StringIO()
        with unittest.mock.patch('preparation_softdenchi_recipe.softdenchi_recipe', return_value=self.recipe):
            interactive_status(self.f.fixture.source.root, self.f.fixture.options['renderer'], self.config,
                               output_stream=output, environment=self.environment, steam=self.f.steam,
                               settings=self.f.settings, home=self.home, runtime_root=self.f.root)
        return output.getvalue()

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

    def test_refused_slots_are_shown_with_the_manual_route_beside_the_targets(self):
        third = self.bundle + '-third'
        self.make_old_slot(third)  # Placed by this tool, but without saved verification data.
        _, _, output = self.revert_menu('1\nq\n')
        self.assertIn('1. ' + self.old, output)
        self.assertIn('戻す先にできないProton:', output)
        self.assertIn(third + ': ' + update.REFUSED_TEXT['slot-manifest-missing'] + '。' + update.REFUSED_GUIDE, output)
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertEqual(report['refused_targets'], {third: 'slot-manifest-missing'})

    def test_dependencies_are_shown_but_not_required(self):
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertTrue(report['dependencies'], report)
        self.assertIsNone(report['dependencies_unreadable'])
        self.assertIn('  依存: ' + report['dependencies'][0]['dependency_id'], output)
        self.assertIn('戻す条件にしません', output)

    def test_changed_placement_record_after_the_list_stops(self):
        original = update.list_caches

        def blocking(root, verified):
            with PrivateStore(self.f.store_root) as store, store.locked('e' * 64):
                store.write_record('installations', 'old-running.json',
                                   installation_record(self.old, status='running', published=False, phase='staging'))
            return original(root, verified)
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'list_caches', side_effect=blocking):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('revert target placement record changed', json.dumps(report, ensure_ascii=False))
        self.assertEqual(before, self.games_config.read_bytes())

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
        status = self.status_output()
        self.assertIn('戻すときのキャッシュの退避が途中で止まりました', status)
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)
        self.assertNotIn('戻すときのキャッシュの退避が途中で止まりました', self.status_output())

    def test_caches_moved_before_the_note_was_updated_are_counted(self):
        self.add_cache(self.old)
        with unittest.mock.patch.object(update, 'move_caches', side_effect=OSError(18, 'refused')):
            self.revert_menu('1\n1\n1\n')
        with PrivateStore(self.f.store_root) as store:
            _, orphans = update.history(store, '42')
        # As if the rename had finished and the note update had not.
        folder = self.f.store_root / update.CACHES / orphans[0]['binding_id']
        folder.mkdir(mode=0o700, parents=True)
        (self.f.store_root / update.CACHES).chmod(0o700)
        (folder / 'c0001').mkdir(mode=0o755)
        self.assertIn('戻すときのキャッシュの退避が途中で止まりました（1か所を移しました', self.status_output())

    def test_a_catalog_naming_another_exe_than_the_registration_stops(self):
        import preparation_selection as selection
        from preparation_recheck import check_game_identity
        source, _, games = selection.registration_catalog(self.environment)
        other = Path(games['42']['exe']).with_name('other.exe')
        shutil.copyfile(games['42']['exe'], other)
        with PrivateStore(self.f.store_root) as store:
            item = next(entry for entry in store.inventory()['game_prefixes'] if entry['app_id'] == '42')
            record, digest = store.read_record('game-prefixes', item['trial_id'] + '.json')
        with self.assertRaisesRegex(Invalid, 'game registration EXE changed'):
            check_game_identity(record=record, record_sha256=digest, source=source,
                                games={**games, '42': dict(games['42'], exe=str(other))}, steam=self.f.steam, home=self.home)

    def test_cache_directory_replaced_after_the_note_is_not_moved(self):
        cache = self.add_cache(self.old)
        original = update.write_note

        def swap_after_note(store, record):
            result = original(store, record)
            if record['note_kind'] == 'revert':
                kept = cache.with_name('__pycache__.kept')
                cache.rename(kept)
                shutil.copytree(kept, cache)  # Same files, another directory.
            return result
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'write_note', side_effect=swap_after_note):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('cache directory changed', json.dumps(report, ensure_ascii=False))
        self.assertEqual(before, self.games_config.read_bytes())
        self.assertTrue(cache.is_dir())

    def test_change_of_caches_after_confirmation_stops(self):
        self.add_cache(self.old)
        original = update.list_caches
        calls = []

        def changed(root, verified):
            calls.append(1)
            if len(calls) == 2:  # The comparison under the lock sees a cache rewritten after the confirmation.
                self.add_cache(self.old, body=b'other synthetic bytecode')
            return original(root, verified)
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'list_caches', side_effect=changed):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('revert target caches changed', json.dumps(report, ensure_ascii=False))
        self.assertEqual(before, self.games_config.read_bytes())

    def test_failed_write_after_the_cache_move_reports_it(self):
        self.add_cache(self.old)
        import preparation_binding as binding
        with unittest.mock.patch.object(binding, '_atomic', side_effect=OSError(5, 'write refused')):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertEqual(report['cache_move']['moved'], 1, report)
        self.assertIn('Pythonキャッシュを1か所移しました', output)
        self.assertIn('戻すときのキャッシュの退避が途中で止まりました（1か所', self.status_output())

    def test_changed_saved_data_after_the_list_stops(self):
        import preparation_slot_manifest as manifest
        path = self.f.store_root / manifest.DIRECTORY / manifest.record_name(self.old)
        original = update.list_caches

        def tamper(root, verified):
            path.write_bytes(path.read_bytes().replace(b'"version_value":"', b'"version_value":"changed '))
            return original(root, verified)
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'list_caches', side_effect=tamper):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('slot data changed', json.dumps(report, ensure_ascii=False))
        self.assertEqual(before, self.games_config.read_bytes())

    def test_a_process_appearing_after_the_confirmation_stops(self):
        import preparation_processes as processes
        original = processes.observe_slot_users
        calls = []

        def appears(root, proc_root=Path('/proc')):
            calls.append(1)
            found = original(root, proc_root)
            return found if len(calls) == 1 else dict(found, users=1, clear=False)
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(processes, 'observe_slot_users', side_effect=appears):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('revert target slot in use', json.dumps(report, ensure_ascii=False))
        self.assertEqual(before, self.games_config.read_bytes())

    def test_registration_changed_to_another_exe_after_the_list_stops(self):
        source = Path(self.environment['BL_ADDED_GAMES'])
        original = update.list_caches

        def switch(root, verified):
            document = json.loads(source.read_text())
            entry = next(item for item in document if str(item['appid']) == '42')
            other = Path(entry['exe']).with_name('other.exe')
            shutil.copyfile(entry['exe'], other)  # The initialized EXE stays in place.
            entry['exe'] = str(other)
            source.write_text(json.dumps(document))
            return original(root, verified)
        before = self.games_config.read_bytes()
        with unittest.mock.patch.object(update, 'list_caches', side_effect=switch):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        self.assertIn('registration changed', json.dumps(report, ensure_ascii=False))
        self.assertEqual(before, self.games_config.read_bytes())

    def test_a_revert_stopped_after_a_replacement_is_not_shown_as_unchanged(self):
        self.add_cache(self.old)
        import preparation_binding as binding
        original, calls = binding._atomic, []

        def second_fails(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise OSError(5, 'write refused')
            return original(*args, **kwargs)
        with unittest.mock.patch.object(binding, '_atomic', side_effect=second_fails):
            _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertFalse(report.get('binding_written'), output)
        status = self.status_output()
        self.assertIn('設定（3つのファイル）の書き換えが途中で止まりました', status)
        self.assertIn('backups/', status)
        self.assertNotIn('設定は変わっていません', status)

    def test_changed_game_executable_stops(self):
        import preparation_selection as selection
        exe = Path(selection.registration_catalog(self.environment)[2]['42']['exe'])
        with exe.open('ab') as stream:
            stream.write(b'changed')
        _, report, output = self.revert_menu('1\n1\n')
        self.assertIn('game executable changed', json.dumps(report, ensure_ascii=False), output)


# Only the fixtures of the one-pass tests are reused, not their tests.
for _class, _base in ((MoveTests, ONE['OnePassTests']), (DllMoveTests, ONE['PrefixDllOnePassTests']),
                      (RevertTests, ONE['OnePassTests'])):
    for _name in dir(_base):
        if _name.startswith('test_') and _name not in _class.__dict__:
            setattr(_class, _name, None)
del _class, _base, _name  # Loop names must not be collected as test classes.


def _only(cls, keep):
    """Run only ``keep`` of the inherited tests: the rest assume a profile with dependencies."""
    for name in [name for name in dir(cls) if name.startswith('test_') and name not in keep]:
        setattr(cls, name, None)
    return cls


class _WithoutDependencies:
    def pin_silent(self):
        super().pin_silent()
        self.config['game_preparation']['profiles'][0]['dependencies'] = []


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class NoDependencyMoveTests(_WithoutDependencies, MoveTests):
    """A game prepared with a profile without dependencies is shown and moved (design: no-SoftDenchi 8.1)."""

    def test_game_without_dependencies_is_shown_and_moved(self):
        self.assertEqual(self.selection()['kind'], 'move')
        entry, output = self.status_report()
        self.assertEqual(entry['dependencies'], [], output)
        self.assertIn('依存: なし', output)
        status, report, output = self.move_menu('1\n1\n')
        self.assertEqual(status, 2, output)
        self.assertTrue(report['binding_written'], report)
        self.assertEqual(self.selection()['kind'], 'bound')


_only(NoDependencyMoveTests, {'test_game_without_dependencies_is_shown_and_moved'})


@unittest.skipUnless(sys.platform == 'linux', 'native writer tests require Linux')
class NoDependencyRevertTests(_WithoutDependencies, RevertTests):
    """A moved game without dependencies is assigned back to the older slot."""

    def test_game_without_dependencies_is_reverted(self):
        _, report, output = self.revert_menu('1\n1\n1\n')
        self.assertTrue(report['binding_written'], output)
        current = update.current_selection(update.current_files(self.f.steam, self.f.settings), '42')
        self.assertEqual(current['config'], update.tool_id_of(self.old))


_only(NoDependencyRevertTests, {'test_game_without_dependencies_is_reverted'})


if __name__ == '__main__':
    unittest.main()
