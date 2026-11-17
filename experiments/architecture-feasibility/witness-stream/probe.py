"""PUBLIC fixed-endpoint selective witnesses; no private indices or remote query."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sys
import time
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
DEPTH = 40

def need(ok, why):
    if not ok:
        raise ValueError(why)

def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

class Frontier:
    def __init__(self, chain, count, targets, h):
        need(0 < count <= 1 << DEPTH, 'count')
        need(len(set(targets)) == len(targets), 'duplicate target')
        need(all(type(i) is int and 0 <= i < count for i in targets), 'target bounds')
        self.chain, self.count, self.h = chain, count, h
        self.empty = [[0] * 8]
        for d in range(DEPTH):
            self.empty.append(self.node(d, self.empty[-1], self.empty[-1]))
        self.wanted, self.paths = {}, {i: [None] * DEPTH for i in targets}
        for i in targets:
            for d in range(DEPTH):
                self.wanted.setdefault((((i >> d) ^ 1) << d, d), []).append(i)
        self.stack, self.seen, self.peak = [], 0, 0

    def node(self, d, a, b):
        return self.h(self.chain, 5, [d] + a + b)

    def capture(self, start, d, value):
        for target in self.wanted.get((start, d), ()):
            need(self.paths[target][d] is None, 'duplicate sibling')
            self.paths[target][d] = list(value)

    def subtree(self, start, d, value):
        need(start % (1 << d) == 0, 'alignment')
        self.capture(start, d, value)
        while self.stack and self.stack[-1][1] == d:
            old, _, left = self.stack.pop()
            need(old + (1 << d) == start and old % (2 << d) == 0, 'adjacency')
            value = self.node(d, left, value)
            start, d = old, d + 1
            self.capture(start, d, value)
        self.stack.append((start, d, value))
        self.peak = max(self.peak, len(self.stack))

    def append(self, value):
        need(self.seen < self.count, 'too many leaves')
        self.subtree(self.seen, 0, list(value))
        self.seen += 1

    def finish(self, root):
        need(self.seen == self.count, 'incomplete leaf stream')
        at = self.seen
        while at < 1 << DEPTH:
            d = (at & -at).bit_length() - 1
            self.subtree(at, d, self.empty[d])
            at += 1 << d
        need(len(self.stack) == 1 and self.stack[0][:2] == (0, DEPTH), 'final frontier')
        need(self.stack[0][2] == root, 'endpoint root mismatch')
        need(all(all(x is not None for x in v) for v in self.paths.values()), 'missing path')
        return self.paths



def public(root, item, cap, pins):
    name = Path(item['path'])
    need(not name.is_absolute() and name.parts and all(p not in ('.', '..') for p in name.parts), 'relative public path')
    p = root
    for part in name.parts:
        p = p / part
        need(not p.is_symlink(), 'no symlink fixture')
    need(p.is_file() and p.stat().st_size <= cap, 'bounded public file')
    raw = p.read_bytes()
    need(len(raw) <= cap and hashlib.sha256(raw).hexdigest() == item['sha256'], 'public file SHA256')
    pins[str(p)] = item['sha256']
    return raw

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--installation', type=Path, required=True)
    p.add_argument('--approve-installation', required=True)
    p.add_argument('--approve-source', required=True)
    p.add_argument('--workload', type=Path, required=True)
    p.add_argument('--approve-workload', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    need(not a.output.exists(), 'exclusive output')
    source_path = HERE / 'SOURCE.json'
    need(sha(source_path) == a.approve_source, 'explicit reviewed witness source')
    sources = json.loads(source_path.read_text())
    need(sources['format'] == 'CP03-PUBLIC-WITNESS-SOURCE01', 'source format')
    for name, digest in sources['files'].items():
        need(sha(HERE / name) == digest, 'witness source pin')
    spec = importlib.util.spec_from_file_location('public_common', REPOSITORY / 'scripts/common.py')
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    inst = common.load_installation(a.installation.resolve(strict=True), a.approve_installation)
    need(Path(inst['repository']) == REPOSITORY, 'this public repository installation')
    need(inst['pins'].get(str(REPOSITORY / 'scripts/common.py')) == sha(REPOSITORY / 'scripts/common.py'), 'approved lifecycle helper')
    root = Path(inst['source_root'])
    refpath = root / 'experiments/compact-arities-v3/reference.py'
    need(inst['pins'].get(str(refpath)) == sha(refpath), 'approved arity/hash reference')
    spec = importlib.util.spec_from_file_location('independent_cp03_reference', refpath)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    workload = a.workload.resolve(strict=True)
    need(sha(workload) == a.approve_workload, 'explicit public fixture approval')
    manifest = json.loads(workload.read_text())
    need(manifest['format'] == 'CP03-DISTINCT-BLOCK-WORKLOAD01', 'common public workload format')
    chain = bytes.fromhex(manifest['chain'])
    need(len(chain) == 32, 'chain')
    fixture_pins = {}
    genesis = public(workload.parent, manifest['genesis'], 42744, fixture_pins)
    need(genesis[:8] == b'CPGEN003', 'genesis magic')
    leaves, cases, negatives = [], [], 0
    started = time.monotonic()
    for height, block in enumerate(manifest['blocks'], 1):
        header = public(workload.parent, block['header'], 1232, fixture_pins)
        need(header[:8] == b'CPBLOCK3' and int.from_bytes(header[108:116], 'little') == height, 'header height/magic')
        need(header[12:44] == chain, 'header chain')
        need(1 <= len(block['bodies']) <= 16 and int.from_bytes(header[116:118], 'little') == len(block['bodies']), 'body count')
        for entry in block['bodies']:
            body = public(workload.parent, entry, 2106575, fixture_pins)
            need(body[:8] == b'CPBODY03', 'body magic')
            n = int.from_bytes(body[10:12], 'little')
            statement = ref.parse(body[20:20+n])
            need(bytes(statement['chain']) == chain, 'statement chain')
            _, origins = ref.core_origins(statement)
            leaves.extend(ref.h(chain, 4, origin + cm) for origin, cm in zip(origins, statement['commitments'], strict=True))
        count = int.from_bytes(header[120:128], 'little')
        expected = ref.base.canonical_words(header[128:192])
        need(count == len(leaves), 'authentic header leaf count')
        targets = sorted(set((0, count // 2, count - 1)))
        stream = Frontier(chain, count, targets, ref.h)
        for leaf in leaves:
            stream.append(leaf)
        paths = stream.finish(expected)
        oracle_root, oracle = ref.tree(chain, leaves, list(range(count)))
        need(oracle_root == expected, 'independent sparse root')
        for index, path in paths.items():
            need(path == oracle[index], 'independent sparse path')
            value = leaves[index]
            for depth, sibling in enumerate(path):
                left, right = (sibling, value) if (index >> depth) & 1 else (value, sibling)
                value = stream.node(depth, left, right)
            need(value == expected, 'membership equation')
        cases.append(dict(height=height, leaves=count, public_test_targets=targets, paths_matched=len(paths),
            peak_frontier_digests=stream.peak, retained_path_digests=len(paths)*DEPTH, remote_membership_queries=0,
            root_hex=ref.pack(expected).hex()))
    need(cases and manifest['endpoint']['height'] == str(len(cases)) and manifest['endpoint']['leaf_count'] == str(len(leaves)), 'manifest endpoint')
    mutations = [leaves[:-1], [leaves[1], leaves[0], *leaves[2:]],
                 [[(leaves[0][0] + 1) % ref.P, *leaves[0][1:]], *leaves[1:]]]
    for changed in mutations:
        stream = Frontier(chain, count, [0], ref.h)
        try:
            for leaf in changed:
                stream.append(leaf)
            stream.finish(expected)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('corrupt stream accepted')
    try:
        Frontier(chain, count, [count], ref.h)
    except ValueError:
        negatives += 1
    else:
        raise AssertionError('unfunded target accepted')
    for name, digest in sources['files'].items():
        need(sha(HERE / name) == digest, 'witness source post pin')
    for name, digest in fixture_pins.items():
        need(sha(Path(name)) == digest, 'public fixture post pin')
    common.load_installation(a.installation.resolve(strict=True), a.approve_installation)
    need(sha(workload) == a.approve_workload, 'workload post pin')
    result = dict(format='CP03-PUBLIC-LOCAL-WITNESS01', succeeded=True, cases=cases, negative_controls=negatives,
        installation_sha256=a.approve_installation, source_sha256=a.approve_source, workload_sha256=a.approve_workload,
        wall_seconds=time.monotonic()-started, self_maxrss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        private_material_read=False, canonical_source_changed=False, public_fixture_pins=fixture_pins,
        scope='new public fixed-endpoint witness check on generated genuine public bodies; full sparse oracle retained; not streaming RSS, private integration, network throughput or PQ theorem')
    with a.output.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps(dict(succeeded=True, checkpoints=len(cases), negative_controls=negatives)))

if __name__ == '__main__':
    main()
