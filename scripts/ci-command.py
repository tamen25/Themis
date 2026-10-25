#!/usr/bin/env python3
"""Retain one CI command's actual exit, output and safe environment metadata."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', default='execution-evidence/ci')
    parser.add_argument('--proxy')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', args.name) or not command:
        parser.error('a safe command name and command after -- are required')
    if args.proxy:
        command = [args.proxy, 'proxy'] + command
    out = pathlib.Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tick = time.monotonic()
    record = {'argv': command, 'startedUTC': started, 'exitCode': None,
              'environment': {name: os.environ[name] for name in (
                  'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOMAXPROCS',
                  'GOENV', 'GOWORK', 'GOFLAGS', 'RUNNER_OS', 'RUNNER_ARCH',
                  'ImageOS', 'ImageVersion') if name in os.environ}}
    with (out / (args.name + '.stdout.txt')).open('xb') as stdout, (out / (args.name + '.stderr.txt')).open('xb') as stderr:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            record['exitCode'] = process.wait()
        except OSError as error:
            record['launchError'] = str(error)
    record['elapsedSeconds'] = time.monotonic() - tick
    for stream in ('stdout', 'stderr'):
        path = out / (args.name + '.' + stream + '.txt')
        data = path.read_bytes()
        record[stream] = {'file': path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        destination = sys.stdout.buffer if stream == 'stdout' else sys.stderr.buffer
        destination.write(data)
        destination.flush()
    with (out / (args.name + '.json')).open('x', encoding='utf-8') as receipt:
        json.dump(record, receipt, indent=2)
        receipt.write('\n')
    return record['exitCode'] if record['exitCode'] is not None else 1


if __name__ == '__main__':
    sys.exit(main())
