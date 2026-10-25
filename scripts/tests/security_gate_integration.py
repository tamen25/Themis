#!/usr/bin/env python3
"""Exercise the real scanner and CI gate against fixed offline controls."""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]


def messages(raw):
    decoder = json.JSONDecoder()
    values = []
    while raw.strip():
        item, end = decoder.raw_decode(raw.lstrip())
        values.append(item)
        raw = raw.lstrip()[end:]
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    out = pathlib.Path(args.output) if args.output else pathlib.Path(tempfile.mkdtemp(prefix='themis-security-gate-'))
    if args.output:
        out.mkdir()
    fixture = SCRIPTS / 'testdata/security-gate'
    scanner = str(pathlib.Path(args.scanner).resolve(strict=True))
    results = []
    for name, expected in (('affected', 3), ('clean', 0), ('malformed-db', 1)):
        db = fixture / 'db'
        source = fixture / ('clean' if name == 'clean' else 'affected')
        if name == 'malformed-db':
            db = out / 'malformed-db-input'
            shutil.copytree(fixture / 'db', db)
            (db / 'ID/GO-2099-0001.json').write_text('{"id":', encoding='utf-8')
        command = [sys.executable, str(SCRIPTS / 'ci-security.py'), '--scanner', scanner,
                   '--db', db.resolve().as_uri(), '--output', str((out / name).resolve())]
        child = subprocess.run(command, cwd=source, capture_output=True)
        (out / (name + '.stdout.txt')).write_bytes(child.stdout)
        (out / (name + '.stderr.txt')).write_bytes(child.stderr)
        assert child.returncode == expected, (name, child.returncode, child.stderr.decode(errors='replace'))
        receipt = json.loads((out / name / 'vulnerabilities-json.json').read_text())
        assert receipt['exitCode'] == (1 if name == 'malformed-db' else 0)
        if name != 'malformed-db':
            raw = (out / name / 'vulnerabilities-json.stdout.txt').read_text(encoding='utf-8')
            findings = [v['finding'] for v in messages(raw) if 'finding' in v]
            reachable = [f for f in findings if any(frame.get('function') for frame in f['trace'])]
            assert bool(reachable) == (name == 'affected')
            native = json.loads((out / name / 'vulnerabilities-gate.json').read_text())
            assert native['exitCode'] == expected
        results.append({'case': name, 'command': command, 'exitCode': child.returncode})
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(out), 'cases': results}))


if __name__ == '__main__':
    main()
