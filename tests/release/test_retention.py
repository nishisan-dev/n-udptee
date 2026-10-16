import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / '.github/scripts/prune_releases.py'
SPEC = importlib.util.spec_from_file_location('retention', SCRIPT)
retention = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retention)


def release(i, **changes):
    value = {'id': i, 'tag_name': f'v1.0.{i}', 'draft': False,
             'prerelease': False, 'published_at': f'2026-10-{i:02d}T12:00:00Z'}
    value.update(changes)
    return value


class RetentionTest(unittest.TestCase):
    def test_exact_stable_tag(self):
        for tag in ['v0.1.0', 'v1.2.3', 'v100.20.300']:
            self.assertTrue(retention.valid_tag(tag))
        for tag in ['1.2.3', 'v1.2', 'v01.2.3', 'v1.02.3', 'v1.2.03',
                    'v1.2.3-rc1', 'v1.2.3+build', 'v1.2.3\n', 'v١.2.3', None]:
            self.assertFalse(retention.valid_tag(tag))

    def test_keep_five_by_publication_not_version_or_input_order(self):
        releases = [release(i) for i in [3, 1, 7, 2, 6, 5, 4]]
        releases[1]['tag_name'] = 'v999.0.0'
        expired = retention.select_releases_to_delete(releases)
        self.assertEqual([r['id'] for r in expired], [2, 1])

    def test_do_not_delete_when_under_limit(self):
        for count in range(6):
            self.assertEqual(retention.select_releases_to_delete(
                [release(i) for i in range(1, count + 1)]), [])

    def test_preserve_drafts_prereleases_and_other_tags(self):
        releases = [release(i) for i in range(1, 6)]
        releases += [release(6, draft=True, published_at=None),
                     release(7, prerelease=True), release(8, tag_name='nightly')]
        self.assertEqual(retention.select_releases_to_delete(releases), [])

    def test_deterministic_ties_and_invalid_metadata(self):
        releases = [release(i, published_at='2026-10-01T00:00:00Z') for i in range(1, 7)]
        self.assertEqual(retention.select_releases_to_delete(releases)[0]['id'], 1)
        with self.assertRaises((TypeError, ValueError)):
            retention.select_releases_to_delete([release(1, published_at=None)])
        with self.assertRaises(ValueError):
            retention.select_releases_to_delete([], keep=0)

    @patch.object(retention.subprocess, 'run')
    def test_pagination_and_delete_only_release_not_tag(self, run):
        pages = [[release(i) for i in range(1, 5)], [release(i) for i in range(5, 8)]]
        run.side_effect = [subprocess.CompletedProcess([], 0, json.dumps(pages), ''),
                           subprocess.CompletedProcess([], 0, '', ''),
                           subprocess.CompletedProcess([], 0, '', '')]
        retention.prune('owner/repo')
        self.assertIn('--paginate', run.call_args_list[0].args[0])
        deletes = [call.args[0] for call in run.call_args_list[1:]]
        self.assertEqual(deletes, [
            ['gh', 'api', '--method', 'DELETE', 'repos/owner/repo/releases/2'],
            ['gh', 'api', '--method', 'DELETE', 'repos/owner/repo/releases/1']])

    @patch.object(retention.subprocess, 'run')
    def test_api_failure_stops_cleanup(self, run):
        run.side_effect = subprocess.CalledProcessError(1, 'gh')
        with self.assertRaises(subprocess.CalledProcessError):
            retention.prune('owner/repo')
        self.assertEqual(run.call_count, 1)

    @patch.object(retention.subprocess, 'run')
    def test_concurrent_404_is_safe_but_403_fails(self, run):
        data = json.dumps([[release(i) for i in range(1, 7)]])
        for status, fails in [('404', False), ('403', True)]:
            run.side_effect = [subprocess.CompletedProcess([], 0, data, ''),
                               subprocess.CompletedProcess([], 1, '', f'gh: error (HTTP {status})')]
            if fails:
                with self.assertRaises(RuntimeError):
                    retention.prune('owner/repo')
            else:
                retention.prune('owner/repo')
