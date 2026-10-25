#!/usr/bin/env python3
"""Freeze official advisories for the complete selected Go module graph."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new directory for a file-based scanner database')
    args = parser.parse_args()
    out = pathlib.Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    records = []

    def fetch(path, limit=8 * 1024 * 1024):
        url = 'https://vuln.go.dev/' + path
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.geturl() != url:
                raise ValueError('advisory redirect refused')
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('advisory response exceeds budget')
            records.append({'url': url, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                            'date': response.headers.get('Date')})
            return raw

    graph_raw = subprocess.check_output(['go', 'list', '-m', '-json', 'all'])
    remaining = graph_raw.decode('utf-8')
    decoder, graph = json.JSONDecoder(), []
    while remaining.strip():
        item, end = decoder.raw_decode(remaining.lstrip())
        if item.get('Error') or item.get('Replace'):
            raise ValueError('unresolved or replaced module graph refused')
        graph.append(item)
        remaining = remaining.lstrip()[end:]
    if not graph or len(graph) > 4096:
        raise ValueError('module graph exceeds budget or is empty')
    selected = {item['Path'] for item in graph} | {'stdlib', 'toolchain'}
    before = fetch('index/db.json', 65536)
    index = fetch('index/modules.json')
    ids = sorted({v['id'] for module in json.loads(index) if module['path'] in selected for v in module['vulns']})
    if len(ids) > 1500 or not all(re.fullmatch(r'GO-\d{4}-\d+', item) for item in ids):
        raise ValueError('advisory inventory refused')
    files = {'index/db.json': before, 'index/modules.json': index}
    for identifier in ids:
        path = 'ID/' + identifier + '.json'
        raw = fetch(path, 256 * 1024)
        if json.loads(raw)['id'] != identifier:
            raise ValueError('advisory identity mismatch')
        files[path] = raw
    if before != fetch('index/db.json', 65536) or sum(map(len, files.values())) > 32 * 1024 * 1024:
        raise ValueError('database changed during capture or exceeds budget')
    for name, raw in files.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    metadata = {'graph': graph, 'database': json.loads(before), 'fetches': records,
                'goVersion': subprocess.check_output(['go', 'env', 'GOVERSION']).decode().strip()}
    (out / 'snapshot.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(out.resolve().as_uri())


if __name__ == '__main__':
    main()
