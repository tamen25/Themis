#!/usr/bin/env python3
"""Build a local developer preview twice from separate source and cache directories."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLATFORMS = ('windows/amd64', 'linux/amd64', 'darwin/amd64')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new directory; never replaces existing output')
    parser.add_argument('--version', default='v0.0.0-preview')
    parser.add_argument('--platform', action='append', choices=PLATFORMS)
    parser.add_argument('--allow-dirty', action='store_true', help='label an uncommitted review build explicitly')
    parser.add_argument('--proxy', help='optional local executable proxy, e.g. rtk')
    args = parser.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9][A-Za-z0-9.-]{0,60}', args.version):
        parser.error('an explicit prerelease version is required')
    commands = []

    def command(argv, *, cwd=ROOT, env=None):
        actual = ([args.proxy, 'proxy'] if args.proxy else []) + list(map(str, argv))
        proc = subprocess.run(actual, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        commands.append({'argv': actual, 'exitCode': proc.returncode,
                         'stdout': proc.stdout.decode('utf-8', errors='replace'),
                         'stderr': proc.stderr.decode('utf-8', errors='replace')})
        if proc.returncode:
            raise RuntimeError(f'build command exited {proc.returncode}: {actual}')
        return proc.stdout

    def git(*arguments):
        return command(['git', '-c', 'core.excludesFile=/dev/null', *arguments])

    commit = git('rev-parse', 'HEAD').decode().strip()
    dirty = bool(git('status', '--porcelain').strip())
    if dirty and not args.allow_dirty:
        parser.error('working tree is dirty; commit reviewed changes or explicitly use --allow-dirty')
    names = sorted(set(git('ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().rstrip('\0').split('\0')))
    source = {}
    size = 0
    for name in names:
        relative = pathlib.PurePosixPath(name)
        if relative.is_absolute() or any(p in ('', '.', '..', '.git', '.cache', '.themis', 'review-artifacts', 'execution-evidence') for p in relative.parts):
            raise ValueError('unsafe source path: ' + name)
        if relative.name == 'THEMIS_IMPLEMENTATION_GUIDE.md' or relative.name == '.env' or relative.name.startswith('.env.') and relative.name != '.env.example' or relative.suffix in ('.kubeconfig', '.token'):
            raise ValueError('private source input is excluded: ' + name)
        path = ROOT
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('source symlink refused: ' + name)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024**2:
            raise ValueError('source file type/size rejected: ' + name)
        data = path.read_bytes()
        # The repository specifies text=auto/eol=lf. Keep binary fixtures intact.
        if b'\0' not in data[:8000]:
            try:
                data.decode('utf-8')
                data = data.replace(b'\r\n', b'\n')
            except UnicodeDecodeError:
                pass
        size += len(data)
        if size > 64 * 1024**2 or len(source) >= 4096:
            raise ValueError('source snapshot exceeds build budget')
        source[name] = data
    inventory = {name: {'bytes': len(data), 'sha256': digest(data)} for name, data in source.items()}
    source_digest = digest(encoded(inventory))
    label = f'{args.version}+{commit[:12]}.{source_digest[:12]}' + ('.dirty' if dirty else '')
    go_version = command(['go', 'env', 'GOVERSION']).decode().strip()
    required = re.search(rb'^go ([0-9.]+)$', source['go.mod'], re.M).group(1).decode()
    if go_version != 'go' + required:
        raise ValueError(f'exact toolchain required: go{required}; observed {go_version}')
    goroot = command(['go', 'env', 'GOROOT']).decode().strip()
    module_cache = command(['go', 'env', 'GOMODCACHE']).decode().strip()
    go = pathlib.Path(goroot) / 'bin' / ('go.exe' if os.name == 'nt' else 'go')
    graph_bytes = command([go, 'list', '-m', '-json', 'all'])
    decoder = json.JSONDecoder()
    graph_text = graph_bytes.decode()
    modules = []
    while graph_text.strip():
        item, end = decoder.raw_decode(graph_text.lstrip())
        if item.get('Error') or item.get('Replace'):
            raise ValueError('preview requires a completely resolved graph without module replacements')
        modules.append({key: item[key] for key in ('Path', 'Version', 'Main', 'Indirect', 'Sum', 'GoModSum', 'GoVersion') if key in item})
        graph_text = graph_text.lstrip()[end:]
    out = pathlib.Path(args.output).resolve()
    if out == ROOT or ROOT in out.parents and out.relative_to(ROOT).parts[0] in ('.git', '.themis'):
        raise ValueError('output must not replace the repository or private state')
    out.mkdir(parents=True, exist_ok=False)
    manifest = {'version': 'themis.developer-preview/v1alpha1', 'label': label,
                'commit': commit, 'workingTreeDirty': dirty, 'sourceDigest': source_digest,
                'sourceNormalization': 'UTF-8 text uses LF; binary fixtures retain original bytes',
                'sourceFiles': inventory, 'modules': modules, 'goVersion': go_version, 'goExecutableSHA256': digest(go.read_bytes()),
                'platforms': [], 'files': {}, 'buildCommands': commands,
                'executionAttestation': 'NOT_INDEPENDENTLY_ATTESTED',
                'limitations': ['Local checksum metadata is not a release approval or infrastructure attestation.',
                                'Matching binaries establish only these two builds on this builder/toolchain.',
                                'Cross compilation does not establish execution or tests on the target OS.']}
    try:
        for platform in args.platform or PLATFORMS:
            goos, goarch = platform.split('/')
            platform_name = goos + '-' + goarch
            platform_out = out / platform_name
            platform_out.mkdir()
            previous = None
            for attempt in (1, 2):
                with tempfile.TemporaryDirectory(prefix=f'{platform_name}-{attempt}-') as temporary:
                    work = pathlib.Path(temporary).resolve()
                    if work.parent != pathlib.Path(tempfile.gettempdir()).resolve() or work == pathlib.Path(work.anchor) or work == ROOT or ROOT in work.parents:
                        raise ValueError('independent build directory must be outside the source repository')
                    snapshot = work / 'source'
                    snapshot.mkdir()
                    for name, data in source.items():
                        target = snapshot / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                    target = work / 'bin'
                    target.mkdir()
                    env = {name: os.environ[name] for name in ('PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP') if name in os.environ}
                    env.update(GOOS=goos, GOARCH=goarch, CGO_ENABLED='0', GOTOOLCHAIN='local',
                               GOENV='off', GOWORK='off', GOFLAGS='-mod=readonly',
                               GOCACHE=str(work / 'cache'), GOMODCACHE=module_cache,
                               GOPATH=str(work / 'gopath'), HOME=str(work), USERPROFILE=str(work),
                               GOPROXY='off', GOSUMDB='sum.golang.org')
                    command([go, 'build', '-trimpath', '-buildvcs=false', '-ldflags',
                             '-buildid= -X main.version=' + label, '-o', str(target) + os.sep, './cmd/...'], cwd=snapshot, env=env)
                    expected = {pathlib.PurePosixPath(name).parts[1] + ('.exe' if goos == 'windows' else '')
                                for name in source if re.fullmatch(r'cmd/[^/]+/main\.go', name)}
                    actual = {path.name for path in target.iterdir()}
                    if actual != expected:
                        raise ValueError('build output does not match every CLI command')
                    hashes = {}
                    for name in sorted(actual):
                        path = target / name
                        if path.is_symlink() or not path.is_file():
                            raise ValueError('unexpected build file type')
                        data = path.read_bytes()
                        if re.search(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{40,}-----END', data):
                            raise ValueError('private key material detected in binary')
                        hashes[name] = {'bytes': len(data), 'sha256': digest(data)}
                        if attempt == 1:
                            destination = platform_out / name
                            destination.write_bytes(data)
                            destination.chmod(0o755)
                    if previous is not None and hashes != previous:
                        raise ValueError('independent build hashes differ for ' + platform)
                    previous = hashes
            for name, entry in previous.items():
                manifest['files'][platform_name + '/' + name] = entry
            manifest['platforms'].append({'goos': goos, 'goarch': goarch, 'independentBuilds': 2,
                                          'separateSourcesAndCaches': True, 'binariesMatch': True})
        for name, data in [('LICENSE', source['LICENSE']), ('PREVIEW.md', source['docs/developer-preview.md'])]:
            (out / name).write_bytes(data)
            manifest['files'][name] = {'bytes': len(data), 'sha256': digest(data)}
        manifest_bytes = encoded(manifest)
        (out / 'manifest.json').write_bytes(manifest_bytes)
        hashes = {name: entry['sha256'] for name, entry in manifest['files'].items()}
        hashes['manifest.json'] = digest(manifest_bytes)
        (out / 'SHA256SUMS.txt').write_text(''.join(f'{value}  {name}\n' for name, value in sorted(hashes.items())), encoding='utf-8')
    except Exception:
        (out / 'FAILED_BUILD_COMMANDS.json').write_bytes(encoded(commands))
        raise
    print(json.dumps({'output': str(out), 'label': label, 'sourceDigest': source_digest,
                      'platforms': manifest['platforms'], 'files': len(manifest['files'])}))


if __name__ == '__main__':
    main()
