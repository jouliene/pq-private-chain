"""Short actual-CP03 public fixture bridge; not new proof/wallet acceptance."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream import Block, Head, SelectiveFrontier, WalletWitnesses, WitnessError

REPOSITORY = Path(__file__).resolve().parents[3]
FIXTURE = REPOSITORY / 'fixtures/cp03-reference'


def need(ok, reason):
    if not ok:
        raise WitnessError(reason)


def h64(role, raw, suffix=b''):
    tag = b'PQPC/CP3/' + role
    return hashlib.sha3_512(len(tag).to_bytes(2, 'little') + tag + len(raw).to_bytes(4, 'little') + raw + suffix).digest()


class Fixture:
    """Only the published common public fixtures and scalar reference are read."""
    def __init__(self):
        self.inventory = json.loads((REPOSITORY / 'CORE_MANIFEST.json').read_text())['files']
        self.reads = {}
        reference = REPOSITORY / 'source/experiments/compact-arities-v3/reference.py'
        for name in ['source/experiments/compact-arities-v3/reference.py',
                     'source/experiments/compact-payment-v1/reference.py',
                     'source/experiments/compact-payment-v1/data/round-constants.json']:
            self.public(REPOSITORY / name, 1024 * 1024)
        spec = importlib.util.spec_from_file_location('public_scalar_cp03', reference)
        self.ref = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ref)
        self.expected = json.loads(self.public(FIXTURE / 'expected.json', 65536))
        self.chain = bytes.fromhex(self.expected['chain'])
        self.genesis_bytes = self.public(FIXTURE / self.expected['genesis'], 42744)
        need(self.genesis_bytes[:12] == b'CPGEN003\x03\0\0\0' and self.genesis_bytes[12:44] == self.chain,
             'public genesis context')
        self.genesis_id = h64(b'GENESIS', self.genesis_bytes)
        self.node = lambda level, left, right: tuple(self.ref.h(self.chain, 5, [level] + list(left) + list(right)))

    def public(self, path, cap):
        relative = str(path.relative_to(REPOSITORY))
        need(relative in self.inventory and path.is_file() and not path.is_symlink(), 'published fixed input')
        need(path.stat().st_size <= cap, 'bounded public fixture')
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        need(digest == self.inventory[relative]['sha256'], 'published fixture identity')
        self.reads[relative] = digest
        return raw

    def body(self, name):
        raw = self.public(FIXTURE / name, 2106575)
        need(raw[:10] == b'CPBODY03\x03\0' and raw[18:20] == b'\0\0', 'body version')
        size = int.from_bytes(raw[10:12], 'little')
        proof_size = int.from_bytes(raw[12:16], 'little')
        authorization = int.from_bytes(raw[16:18], 'little')
        need(size in (448, 464, 528) and 0 < proof_size <= 2097152, 'body bounds')
        statement = self.ref.parse(raw[20:20 + size])
        need(bytes(statement['chain']) == self.chain, 'statement chain')
        need(authorization == (4627 if len(statement['nullifiers']) == 0 else 0), 'source signature length')
        for ordinal in range(2):
            at = 20 + size + 2164 * ordinal
            need(raw[at:at + 8] == b'CPR3\x03\x01\0\0', 'receiving envelope version')
        proof_at = 20 + size + 4328 + authorization
        need(len(raw) == proof_at + proof_size, 'complete body length')
        identity = h64(b'BODY', raw[:proof_at], h64(b'PROOF', raw[proof_at:]))
        _, origins = self.ref.core_origins(statement)
        leaves = tuple(tuple(self.ref.h(self.chain, 4, origin + commitment))
                       for origin, commitment in zip(origins, statement['commitments'], strict=True))
        return identity, leaves

    def blocks(self):
        # This is a bounded public bridge, not the canonical future 96-body parser.
        prior = self.genesis_id
        count = 0
        need(len(self.expected['blocks']) == 4, 'fixed four-block fixture')
        for height, entry in enumerate(self.expected['blocks'], 1):
            header = self.public(FIXTURE / entry['header'], 1232)
            need(header[:12] == b'CPBLOCK3\x03\0\0\0', 'header version')
            need(header[12:44] == self.chain and header[44:108] == prior, 'header chain and parent')
            need(int.from_bytes(header[108:116], 'little') == height, 'header height')
            need(int.from_bytes(header[116:118], 'little') == 1 and header[118:120] == b'\0\0', 'single-body fixture framing')
            need(len(header) == 272, 'header exact length')
            body_id, leaves = self.body(entry['body'])
            need(header[208:] == body_id, 'body bytes committed by header')
            count += 2
            need(int.from_bytes(header[120:128], 'little') == count, 'funded occurrence count')
            root = tuple(self.ref.base.canonical_words(header[128:192]))
            identity = h64(b'BLOCK', header)
            yield Block(height, prior, identity, count, root, leaves)
            prior = identity
        endpoint = self.expected['endpoint']
        need(endpoint['chain'] == self.chain.hex() and endpoint['genesisId'] == self.genesis_id.hex(), 'independent published context')
        need(endpoint['height'] == '4' and endpoint['blockId'] == prior.hex(), 'independent published endpoint')

    def trusted_endpoint(self):
        header = self.public(FIXTURE / self.expected['blocks'][-1]['header'], 1232)
        identity = h64(b'BLOCK', header)
        need(identity.hex() == self.expected['endpoint']['blockId'], 'published final endpoint ID')
        return Head(4, identity, int.from_bytes(header[120:128], 'little'),
                    tuple(self.ref.base.canonical_words(header[128:192])))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists(), 'exclusive output')
    fixture = Fixture()
    empty = SelectiveFrontier(40, fixture.node, (0,) * 8, 4).view()[0]
    genesis = Head(0, fixture.genesis_id, 0, empty)
    wallet = WalletWitnesses(genesis, fixture.node, (0,) * 8, max_owned=4, rewind_blocks=4)
    epoch = wallet.epoch(fixture.trusted_endpoint())
    oracle_leaves = []  # Explicitly test-only, never supplied to the algorithm.
    checkpoints = []
    for block in fixture.blocks():
        # Public diagnostic selections, not actual wallet receipt discovery.
        selected = {0: 'public-first', 5: 'public-late'}
        epoch.apply(block, lambda index, _leaf: selected.get(index))
        oracle_leaves.extend(block.leaves)
        indices = list(epoch.state.frontier.indices.values())
        root, paths = fixture.ref.tree(fixture.chain, [list(value) for value in oracle_leaves], list(range(len(oracle_leaves))))
        need(tuple(root) == block.root, 'independent full oracle root')
        # Test-only tentative state inspection. The wallet's committed witness
        # API remains empty until the independently selected final endpoint.
        tentative_root, tentative_paths = epoch.state.frontier.view()
        need(tentative_root == block.root and not wallet.state.frontier.indices, 'no early committed discoveries')
        for token, index in epoch.state.frontier.indices.items():
            need(tentative_paths[token] == tuple(tuple(value) for value in paths[index]), 'independent full oracle path')
        checkpoints.append({'height': block.height, 'leaf_count': block.count,
                            'public_diagnostic_paths': len(indices), 'root_hex': fixture.ref.pack(block.root).hex()})
    epoch.finish()
    for token in wallet.state.frontier.indices:
        witness = wallet.witness(token)
        need(witness.siblings == tuple(tuple(value) for value in paths[witness.index]), 'committed final oracle path')
    for name, expected in fixture.reads.items():
        need(hashlib.sha256((REPOSITORY / name).read_bytes()).hexdigest() == expected, 'public input postcheck')
    result = {'format': 'WALLET-WITNESS-CP03-FIXTURE01', 'passed': True, 'checkpoints': checkpoints,
        'public_inputs': fixture.reads, 'uses_actual_cp03_tree_hashes_and_body_binding': True,
        'algorithm_receives_full_ledger_paths': False, 'full_oracle_only_in_harness': True,
        'payment_validity': 'delegated to existing published genuine-fixture validation; not reverified here',
        'consensus_freshness_and_availability_proved': False, 'actual_wallet_discovery': False,
        'genuine_new_proofs_or_admissions': False, 'actual_gate3_expiry_or_reorg_acceptance': False,
        'private_material_read_or_recorded': False,
        'scope': 'Short current-CP03 public correspondence only; not streaming RSS, actual wallet integration or Gate3 PASS'}
    with args.output.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'passed': True, 'actual_cp03_checkpoints': len(checkpoints), 'gate3_acceptance': False}))


if __name__ == '__main__':
    main()
