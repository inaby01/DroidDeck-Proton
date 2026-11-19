#!/usr/bin/env python3
"""Dependency plans and observation contracts using generated PE files only."""

import copy
import hashlib
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / 'test_preparation_store.py'))
import preparation_dependencies as dependencies
from preparation_assets import inspect_assets
from preparation_common import Invalid


class DependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.data = FIX['FIXTURES']['pe']()
        self.spec = FIX['spec_for'](self.data)
        self.path = self.root / self.spec['filename']
        self.path.write_bytes(self.data)

    def plan(self, handler='softdenchi-interactive', state='uninspected'):
        report = inspect_assets({'schema_version': 1, 'assets': [self.spec]}, self.root)[0]
        return dependencies.dependency_plan(handler, self.spec, report, state)

    def test_original_interactive_bootstrap_has_no_inferred_silent_or_msi_bypass(self):
        before = self.path.read_bytes()
        with patch('subprocess.Popen', side_effect=AssertionError('plan never executes')):
            result = self.plan()
        operation = result['planned_operation']
        self.assertEqual(operation['arguments'], [])
        self.assertFalse(operation['silent_arguments_inferred'])
        self.assertFalse(operation['msi_only_bypass'])
        self.assertEqual(operation['inner_product_architecture'], 'x86_64')
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(result['writes'], [])
        self.assertFalse(result['execution_authorized'])

    def test_terms_origin_and_independent_hash_blockers_are_preserved(self):
        self.spec.update(terms_status='unconfirmed', provenance_status='unconfirmed', hash_kind='local-measurement')
        result = self.plan()
        for code in ('terms-unconfirmed', 'provenance-unconfirmed', 'independent-hash-reference-unavailable'):
            self.assertIn(code, result['blockers'])
        self.assertFalse(result['binding_authorized'])

    def test_inspection_identity_cannot_be_rebound_to_another_spec(self):
        inspection = inspect_assets({'schema_version': 1, 'assets': [self.spec]}, self.root)[0]
        self.spec['revision'] = 2
        with self.assertRaises(Invalid):
            dependencies.dependency_plan('softdenchi-interactive', self.spec, inspection)

    def test_hash_mismatch_is_recomputed_instead_of_trusting_supplied_blockers(self):
        inspection = inspect_assets({'schema_version': 1, 'assets': [self.spec]}, self.root)[0]
        inspection['measured']['sha256'] = '0' * 64
        inspection['blockers'] = []
        result = dependencies.dependency_plan('softdenchi-interactive', self.spec, inspection)
        self.assertIn('hash-mismatch', result['blockers'])
        self.assertNotEqual(result['input_digest'], self.plan()['input_digest'])

    def test_mfc_is_single_file_without_architecture_guess_or_broad_overrides(self):
        result = self.plan('mfc-local')
        operation = result['planned_operation']
        self.assertFalse(operation['broad-vcrun6-install'])
        self.assertFalse(operation['msvcrt-or-oleaut32-overrides'])
        self.assertFalse(operation['mfc140-substitute'])
        self.assertIn('prefix-dll-architecture-map-unverified', result['blockers'])
        self.assertIn('unresolved', operation['destination'])

    def test_partial_unknown_and_persisted_verified_state_never_authorize_repair_or_skip(self):
        for state in ('partial', 'incompatible', 'present-unverified', 'present-verified'):
            result = self.plan(state=state)
            self.assertFalse(result['automatic_repair'])
            self.assertFalse(result['automatic_upgrade'])
            self.assertFalse(result['skip_installation_authorized'])
            self.assertTrue(any('reinspection' in code or 'preserve' in code for code in result['blockers']))

    def test_fixed_postcondition_set_is_complete_and_does_not_grant_authority(self):
        values = {key: 'passed' for key in dependencies.SOFTDENCHI_CHECKS}
        result = dependencies.summarize_postcondition_observations('softdenchi-interactive', values)
        self.assertEqual(result['result'], 'all-reported-checks-passed')
        self.assertFalse(result['live_evidence_verified'])
        self.assertFalse(result['execution_authorized'])
        values['x64-com-registration'] = 'uninspected'
        self.assertEqual(dependencies.summarize_postcondition_observations('softdenchi-interactive', values)['result'], 'incomplete-observations')
        del values['x64-com-registration']
        with self.assertRaises(Invalid):
            dependencies.summarize_postcondition_observations('softdenchi-interactive', values)

    def test_cli_is_separate_read_only_mode_and_hides_declaration_text(self):
        spec = copy.deepcopy(self.spec)
        spec['source_reference'] = 'DUMMY_PRIVATE_SOURCE'
        manifest = self.root / 'assets.json'
        manifest.write_text(json.dumps({'schema_version': 1, 'assets': [spec]}))
        script = HERE / 'prepare_game.py'
        args = [sys.executable, '-I', '-B', str(script), '--plan-dependency', '--assets', str(manifest), '--asset-root', str(self.root),
                '--dependency-handler', 'softdenchi-interactive', '--dependency-asset', spec['asset_id']]
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['mode'], 'dependency-installation-plan')
        self.assertNotIn('DUMMY_PRIVATE_SOURCE', result.stdout)
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())
        mixed = subprocess.run(args + ['--app-id', '42'], capture_output=True, text=True, check=False)
        self.assertEqual(mixed.returncode, 1)


if __name__ == '__main__':
    unittest.main()
