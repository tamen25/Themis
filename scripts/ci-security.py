#!/usr/bin/env python3
"""Retain structured govulncheck evidence, then run its native source gate."""
import argparse
import json
import pathlib
import subprocess
import sys


def validate_json(path):
    # Check transport integrity only. Findings are decided by the scanner's
    # native gate, never by the JSON command's successful exit or this decoder.
    text = path.read_text(encoding='utf-8')
    decoder = json.JSONDecoder()
    messages = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        if not isinstance(value, dict) or len(value) != 1:
            raise ValueError('expected a scanner message object')
        messages.append(value)
        text = text.lstrip()[end:]
    if not messages or messages[0].get('config', {}).get('protocol_version') != 'v1.0.0':
        raise ValueError('missing supported scanner configuration')
    if sum('config' in m for m in messages) != 1 or sum('SBOM' in m for m in messages) != 1:
        raise ValueError('missing or duplicate scanner configuration/SBOM')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', required=True)
    parser.add_argument('--db', required=True, help='explicit advisory database URL; use file:// for a frozen snapshot')
    parser.add_argument('--output', default='execution-evidence/ci')
    args = parser.parse_args()
    scanner = str(pathlib.Path(args.scanner).resolve(strict=True))
    recorder = pathlib.Path(__file__).with_name('ci-command.py')
    common = [sys.executable, str(recorder), '--output', args.output]
    code = subprocess.call(common + ['--name', 'vulnerabilities-json', '--', scanner,
                                    '-json', '-db', args.db, './...'])
    if code:
        return code
    try:
        validate_json(pathlib.Path(args.output) / 'vulnerabilities-json.stdout.txt')
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError) as error:
        print('Invalid scanner evidence: ' + str(error), file=sys.stderr)
        return 1
    # Separate processes, identical executable, working directory, environment
    # and database URL. No shell or pipeline can mask the native child status.
    return subprocess.call(common + ['--name', 'vulnerabilities-gate', '--', scanner,
                                     '-db', args.db, './...'])


if __name__ == '__main__':
    sys.exit(main())
