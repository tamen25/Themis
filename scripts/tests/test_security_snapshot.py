import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('security_snapshot', SCRIPTS / 'security-snapshot.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class Response(io.BytesIO):
    def __init__(self, url, data):
        super().__init__(data)
        self.url = url
        self.headers = {}

    def geturl(self):
        return self.url


class SnapshotTests(unittest.TestCase):
    def capture(self, kind):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / 'snapshot'
            calls = []

            def fetch(url, timeout):
                calls.append(url)
                self.assertEqual(timeout, 30)
                if kind == 'network':
                    raise OSError('synthetic unavailable database')
                name = url.removeprefix('https://vuln.go.dev/')
                if name == 'index/db.json':
                    data = b'{"modified":"2026-10-21T00:00:00Z"}'
                    if kind == 'drift' and len(calls) > 1:
                        data = b'{"modified":"2026-10-21T00:00:01Z"}'
                elif name == 'index/modules.json':
                    data = b'[{"path":"stdlib","vulns":[{"id":"GO-2099-0001"}]}]'
                else:
                    data = b'{"id":"GO-2099-0001"}'
                    if kind == 'malformed':
                        data = b'{"id":'
                    elif kind == 'identity':
                        data = b'{"id":"GO-2099-0002"}'
                return Response(url, data)

            argv = ['security-snapshot.py', '--output', str(target)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(snapshot.urllib.request, 'urlopen', side_effect=fetch), mock.patch.object(snapshot.subprocess, 'check_output', side_effect=[b'{"Path":"example.invalid/main","Main":true}', b'go1.26.10']):
                if kind == 'clean':
                    snapshot.main()
                    result = json.loads((target / 'snapshot.json').read_text())
                    self.assertEqual(result['goVersion'], 'go1.26.10')
                    self.assertEqual(len(result['fetches']), 4)
                else:
                    with self.assertRaises((OSError, ValueError)):
                        snapshot.main()
                    self.assertFalse((target / 'snapshot.json').exists())

    def test_complete_snapshot(self):
        self.capture('clean')

    def test_failures_never_publish_completed_snapshot(self):
        for kind in ('network', 'drift', 'malformed', 'identity'):
            with self.subTest(kind=kind):
                self.capture(kind)


if __name__ == '__main__':
    unittest.main()
