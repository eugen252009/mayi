"""DOC-PATH: remove local locations, preserve every other historical byte.
Run: python3 -m unittest discover -s docs/development -p 'test_*.py'
"""
from pathlib import Path
import unittest
from unittest.mock import patch
from historical_paths import archive_view, NOTICE
from check_documentation import audit


class HistoricalPathTests(unittest.TestCase):
    def test_no_local_paths_is_byte_identical(self):
        for body in [b'', b'FAIL 44/45\nSHA256 abc123\n',
                     b'/tmp/pwned /usr/bin/mayi ../../executor/src/broker.rs\n']:
            self.assertEqual(archive_view(body), body)

    def test_only_location_is_removed(self):
        for location in ['/home/eugen/projekte/mayi/', '~/projekte/releases/mayi/1/',
                         '/tmp/mayi-release-1/src', '/tmp/mayi-qemu-qualification/logs/',
                         '/tmp/tpahub/staging/artifacts/']:
            body = f'FAIL `{location}`; SHA256 abc123\n'.encode()
            expected = (NOTICE + 'FAIL `[local-only path omitted]`; SHA256 abc123\n').encode()
            self.assertEqual(archive_view(body), expected)

    def test_transformation_is_idempotent(self):
        body = b'Evidence: /home/eugen/projekte/example/\n'
        self.assertEqual(archive_view(archive_view(body)), archive_view(body))

    def test_actual_archive_views_match_originals(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(audit(root)['errors'], [])

    def test_checker_rejects_non_path_mutation(self):
        root = Path(__file__).resolve().parents[2]
        target = root / 'docs/historical/baseline-3b6/CLI_TEST_RESULTS.md'
        read_bytes = Path.read_bytes
        def altered(path):
            body = read_bytes(path)
            return body.replace(b'PASS', b'FAIL', 1) if path == target else body
        self.assertIn(b'PASS', read_bytes(target))
        with patch.object(Path, 'read_bytes', altered):
            result = audit(root)
        self.assertTrue(any(e.get('file') == str(target.relative_to(root))
                            and 'historical view differs' in e.get('error', '')
                            for e in result['errors']))


if __name__ == '__main__':
    unittest.main()
