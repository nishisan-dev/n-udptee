"""Exercise the actual workflow shell with a fake gh; never contact GitHub."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/release.yaml').read_text()
PUBLISH = textwrap.dedent(WORKFLOW.split(
    '      - name: Publish complete release\n        run: |\n', 1)[1].split(
    '      - name: Keep the five latest published stable releases', 1)[0])


class PublishTest(unittest.TestCase):
    def run_publish(self, view=None, upload_fails=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'dist').mkdir()
            files = ['n-udptee_v1.2.3_linux_amd64.tar.gz',
                     'n-udptee_v1.2.3_linux_arm64.tar.gz', 'SHA256SUMS']
            for name in files:
                (root / 'dist' / name).write_text('test asset')
            stub = root / 'gh'
            stub.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['STUB_CALLS'], 'a') as out:
    out.write(json.dumps(args) + '\\n')
if args[:2] == ['release', 'view']:
    value = os.environ['STUB_VIEW']
    if value == 'missing':
        sys.exit(1)
    print(value)
if args[:2] == ['release', 'upload'] and os.environ['STUB_UPLOAD_FAILS'] == '1':
    sys.exit(1)
''')
            stub.chmod(0o755)
            calls = root / 'calls.jsonl'
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
                       RELEASE_TAG='v1.2.3', STUB_CALLS=str(calls),
                       STUB_VIEW='missing' if view is None else json.dumps(view),
                       STUB_UPLOAD_FAILS=str(int(upload_fails)))
            result = subprocess.run(['bash', '-c', PUBLISH], cwd=root, env=env,
                                    capture_output=True, text=True)
            return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_new_release_publishes_only_after_upload(self):
        result, calls = self.run_publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[1] for call in calls], ['view', 'create', 'upload', 'edit'])
        self.assertIn('--draft', calls[1])
        self.assertIn('--verify-tag', calls[1])
        self.assertIn('--draft=false', calls[-1])
        self.assertIn('--prerelease=false', calls[-1])
        self.assertIn('dist/SHA256SUMS', calls[2])

    def test_existing_draft_resumes_upload(self):
        result, calls = self.run_publish({'isDraft': True, 'assets': []})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[1] for call in calls], ['view', 'upload', 'edit'])

    def test_published_release_is_not_overwritten(self):
        names = ['n-udptee_v1.2.3_linux_amd64.tar.gz',
                 'n-udptee_v1.2.3_linux_arm64.tar.gz', 'SHA256SUMS']
        result, calls = self.run_publish({'isDraft': False,
                                         'assets': [{'name': name} for name in names]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)

    def test_incomplete_published_release_fails_without_mutating(self):
        result, calls = self.run_publish({'isDraft': False, 'assets': []})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_failed_upload_does_not_publish(self):
        result, calls = self.run_publish(upload_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[1] for call in calls], ['view', 'create', 'upload'])
