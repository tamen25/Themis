#!/usr/bin/env python3
"""Verify a single owned test root and reconcile leftovers through original authority."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('Postgres', 'Durable', 'PITR', 'Replication'), required=True)
    parser.add_argument('--state-root', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--proxy')
    args = parser.parse_args()
    endpoints = ('npipe:////./pipe/dockerDesktopLinuxEngine', 'unix:///var/run/docker.sock', 'unix:///run/docker.sock')
    if args.endpoint not in endpoints or len(args.engine) < 16:
        parser.error('an explicit supported local Docker endpoint and original engine are required')
    root = pathlib.Path(args.state_root)
    if root.is_symlink() or not root.is_dir():
        parser.error('the exact original test state root must exist and cannot be a link')
    root = root.resolve()
    binary = pathlib.Path(args.binary)
    if binary.is_symlink() or not binary.is_file() or binary.stat().st_size > 256 * 1024 * 1024:
        parser.error('an explicit original cleanup executable is required')
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    commands = []
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('DOCKER_')}

    def command(argv):
        actual = ([args.proxy, 'proxy'] if args.proxy else []) + list(map(str, argv))
        start = time.monotonic()
        result = subprocess.run(actual, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        commands.append({'argv': actual, 'exitCode': result.returncode, 'seconds': time.monotonic() - start,
                         'stdout': result.stdout.decode('utf-8', errors='replace'),
                         'stderr': result.stderr.decode('utf-8', errors='replace')})
        if result.returncode:
            raise RuntimeError('cleanup observation or original reconciliation failed')
        return result.stdout.decode('utf-8').split()

    def inventory():
        docker = ['docker', '--host', args.endpoint]
        if command(docker + ['info', '--format', '{{.ID}}']) != [args.engine]:
            raise RuntimeError('original Docker engine changed')
        result = {
            'containers': set(command(docker + ['container', 'ls', '--all', '--quiet', '--no-trunc'])),
            'volumes': set(command(docker + ['volume', 'ls', '--format', '{{.Name}}'])),
            'networks': set(command(docker + ['network', 'ls', '--no-trunc', '--format', '{{.ID}}'])),
        }
        if command(docker + ['info', '--format', '{{.ID}}']) != [args.engine]:
            raise RuntimeError('original Docker engine changed during observation')
        return result

    def lower_keys(value):
        if isinstance(value, dict):
            return {k.casefold(): lower_keys(v) for k, v in value.items()}
        if isinstance(value, list):
            return [lower_keys(v) for v in value]
        return value

    filename, prefix = {
        'Postgres': ('inventory.json', []), 'Durable': ('durable-ownership.json', ['durable']),
        'PITR': ('pitr-ownership.json', ['pitr']), 'Replication': ('replication-ownership.json', ['replication']),
    }[args.family]
    records = []
    failure = None
    try:
        current = inventory()
        directories = sorted(root.iterdir())
        if not directories or len(directories) > 1024:
            raise RuntimeError('missing or oversized original test inventory')
        for directory in directories:
            if directory.is_symlink() or not directory.is_dir() or not re.fullmatch('[a-f0-9]{64}', directory.name):
                raise RuntimeError('unrecognized child in original state root')
            path = directory / filename
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise RuntimeError('original protected inventory unavailable; no guessed cleanup')
            raw = path.read_bytes()
            data = lower_keys(json.loads(raw))
            if pathlib.Path(data['directory']).resolve() != directory.resolve() or data['engine'] != args.engine:
                raise RuntimeError('original inventory directory or engine mismatch')
            containers, volumes = [], []
            for role in ('source', 'restore', 'archive', 'primary', 'standby'):
                resource = data.get(role)
                if isinstance(resource, dict):
                    if resource.get('id'):
                        containers.append(resource['id'])
                    if resource.get('volume', {}).get('name'):
                        volumes.append(resource['volume']['name'])
            network = data['network']['id']
            if not containers or not volumes or not all(re.fullmatch('[a-f0-9]{64}', v) for v in containers + [network]):
                raise RuntimeError('original resource identities unavailable')
            record = {'run': data['run'], 'inventorySHA256': hashlib.sha256(raw).hexdigest(),
                      'containerIDs': containers, 'volumeNames': volumes, 'networkID': network}
            record['presentAfterTests'] = [x for x in containers if x in current['containers']] + [x for x in volumes if x in current['volumes']] + ([network] if network in current['networks'] else [])
            if record['presentAfterTests']:
                # This CLI independently rechecks protected original inventory,
                # identity seals and separate unexpired cleanup capability.
                command([args.binary] + prefix + ['reconcile', '--state', directory])
            records.append(record)
        current = inventory()
        for record in records:
            record['remaining'] = [x for x in record['containerIDs'] if x in current['containers']] + [x for x in record['volumeNames'] if x in current['volumes']] + ([record['networkID']] if record['networkID'] in current['networks'] else [])
        if any(r['remaining'] for r in records):
            raise RuntimeError('original resource absence unverified')
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        failure = str(error)
    result = {'family': args.family, 'engine': args.engine, 'cleanupBinarySHA256': binary_hash, 'complete': failure is None,
              'originalInventories': records, 'commands': commands, 'failure': failure,
              'historicalResultsRewritten': False,
              'scope': 'Exact original private inventory only; absence is a fresh observation, never a revised test verdict.'}
    destination = pathlib.Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return 0 if result['complete'] else 7


if __name__ == '__main__':
    raise SystemExit(main())
