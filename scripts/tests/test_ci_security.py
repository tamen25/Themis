"""Security gate orchestration and the real command recorder's exit contract."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ci_security', SCRIPTS / 'ci-security.py')
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)
VALID = '{"config":{"protocol_version":"v1.0.0"}}\n{"SBOM":{}}\n'


class SecurityGateTests(unittest.TestCase):
    def gate(self, text=VALID, exits=(0, 0)):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            evidence = root / 'vulnerabilities-json.stdout.txt'
            evidence.write_text(text, encoding='utf-8')
            argv = ['ci-security.py', '--scanner', sys.executable, '--db', 'file:///offline', '--output', temporary]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(security.subprocess, 'call', side_effect=exits) as call:
                code = security.main()
            self.assertEqual(evidence.read_text(encoding='utf-8'), text)
            return code, call.call_args_list

    def test_native_gate_decides_findings_and_evidence_remains(self):
        code, calls = self.gate(VALID + '{"finding":{"osv":"GO-2099-0001"}}', (0, 3))
        self.assertEqual(code, 3)
        self.assertEqual(len(calls), 2)
        first, second = (c.args[0] for c in calls)
        self.assertIn('-json', first)
        self.assertNotIn('-json', second)
        self.assertEqual(first[first.index('--') + 1], second[second.index('--') + 1])
        self.assertEqual(first[-3:], second[-3:])

    def test_clean_native_scan_passes(self):
        self.assertEqual(self.gate()[0], 0)

    def test_malformed_truncated_empty_and_missing_sbom_fail(self):
        for text in ('', '{', VALID + '{"finding":', '{"config":{"protocol_version":"v1.0.0"}}', '[]',
                     '{"config":{"protocol_version":"unknown"}}\n{"SBOM":{}}', VALID + '{"config":{}}'):
            with self.subTest(text=text):
                code, calls = self.gate(text)
                self.assertNotEqual(code, 0)
                self.assertEqual(len(calls), 1)

    def test_scan_failures_are_exact_and_stop_the_gate(self):
        for status in (1, 2, 23):
            code, calls = self.gate(exits=(status,))
            self.assertEqual(code, status)
            self.assertEqual(len(calls), 1)

    def test_recorder_real_status_and_launch_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name, command, expected in (
                ('exit23', [sys.executable, '-c', 'import sys; print("retained"); sys.exit(23)'], 23),
                ('launch', [str(pathlib.Path(temporary) / 'missing-executable')], 1),
            ):
                child = subprocess.run([sys.executable, str(SCRIPTS / 'ci-command.py'), '--name', name,
                                        '--output', temporary, '--', *command], capture_output=True)
                self.assertEqual(child.returncode, expected)
                receipt = json.loads((pathlib.Path(temporary) / (name + '.json')).read_text())
                if name == 'launch':
                    self.assertIsNone(receipt['exitCode'])
                    self.assertIn('launchError', receipt)
                else:
                    self.assertEqual(receipt['exitCode'], 23)
                    self.assertEqual(child.stdout.strip(), b'retained')


if __name__ == '__main__':
    unittest.main()
