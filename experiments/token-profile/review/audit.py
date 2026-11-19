"""Independently replay the four public TKN1 fixture blocks and their authenticated openings."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


def u32(n):
    return n.to_bytes(4, 'little')


def u64(n):
    return n.to_bytes(8, 'little')


def hash32(raw):
    return sha256(raw).digest()


def run(source, runtime, helpers, evidence, approval):
    # These independent layout/full-tree readers predate TKN1. No TKN1 ledger or wallet module is imported.
    sys.path[:0] = [str(source / 'experiments/payment-architecture/review'),
                    str(source / 'experiments/advancing-payments/review'),
                    str(source / 'experiments/advancing-payments')]
    from direct_wire import dimensions, declared_size, parse_packet
    from public_chain import counted_hash, reference
    from wire import Role

    key = (source / 'experiments/token-profile/candidate/registry/token.vk').read_bytes()
    assert key == (runtime / 'registered/token.vk').read_bytes()
    profile = dimensions(key)
    expected = declared_size(profile)
    assert profile['verifier_sha256'] == 'f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b'
    pin = json.loads((runtime / 'BUILD.json').read_bytes())['binary_sha256']
    roots = helpers / 'roots'
    genesis = (evidence / 'genesis.bin').read_bytes()
    assert hash32(genesis).hex() == approval
    network = hash32(b'TKN1/network/v1\0' + hash32(key) + bytes([22, 8]))
    assert genesis[:40] == b'TKN1GEN1' + network and len(genesis) == 488
    funding = [row.split() for row in reference(helpers / 'founding', [], genesis[40:])]
    assert [(int(n), int(t)) for n, t, _ in funding] == [(100, 70), (100, 50), (100, 70), (100, 50)]
    commitments = [bytes.fromhex(c) for _, _, c in funding]
    assert len(set(commitments)) == len(commitments)
    for i in range(4):
        context = genesis[40 + 112*i:72 + 112*i]
        assert context == hash32(b'TKN1/endowment\0' + network + u32(i))

    def root():
        digest = reference(roots, [str(len(commitments))], b''.join(commitments))[0].split()[-1]
        return bytes.fromhex(digest)

    def anchor(header):
        return bytes.fromhex(reference(roots, ['--header-ids'], header)[0].split()[-1])

    state = counted_hash(b'TKN1/state0', network, genesis)
    initial = bytes(32) + u32(0) + state + counted_hash(b'TKN1/body0', genesis) + root()
    previous_work = hash32(b'TKN1/genesis-work-parent\0' + genesis)
    current = anchor(initial)
    spent, receipts = set(), set()
    observations = []
    fees = 0
    verify = Role(runtime / 'native', pin, ['verify', '/keys'], runtime / 'registered')
    try:
        blocks = sorted((evidence / 'blocks').glob('*.bin'), key=lambda p: int(p.stem))
        for i, path in enumerate(blocks, 1):
            raw = path.read_bytes()
            assert int(path.stem) == i and raw[:40] == b'TKN1BLK1' + network
            seal = hash32(b'TKN1/work\0' + hash32(b'TKN1/template\0' + raw[:-8]) + raw[-8:])
            assert int.from_bytes(seal, 'big') < 1 << 234
            packet = raw[176:-8]
            assert packet[:5] == b'TKN1\x01' and len(packet) == int.from_bytes(raw[172:176], 'little')
            assert len(packet) == 9 + expected + 3584
            # Layout is common to the two profiles. Cryptographic verification below receives the original bytes.
            parsed = parse_packet(b'DLF1' + packet[4:], profile)
            end = 9 + expected
            pi, receipt = packet[end-208:end], packet[end:]
            assert packet[end-216:end-208] == u64(26)
            assert pi[32:40] == u64(i-1) and pi[:32] == current and pi[168:176] == u64(3)
            assert reference(roots, ['--ciphertext-digests'], receipt) == [pi[-32:].hex()]
            public_effect = pi[:36] + pi[40:176]
            assert verify.call(packet) == b'1' + public_effect + receipt
            nullifiers = {pi[j:j+32] for j in (40, 72)}
            outputs = [pi[j:j+32] for j in (104, 136)]
            assert len(nullifiers) == 2 and spent.isdisjoint(nullifiers)
            assert len(set(outputs)) == 2 and set(outputs).isdisjoint(commitments) and bytes(32) not in outputs
            note_receipts = {receipt[:1792], receipt[1792:]}
            assert len(note_receipts) == 2 and receipts.isdisjoint(note_receipts)
            receipts.update(note_receipts)
            spent.update(nullifiers)
            commitments.extend(outputs)
            fees += 3
            state = counted_hash(b'TKN1/state', network, previous_work, state, u64(fees), public_effect)
            previous_work = seal
            body_hash = counted_hash(b'TKN1/body', network, packet)
            header = current + u32(i) + state + body_hash + root()
            assert header == raw[40:172]
            current = anchor(header)
            observations.append(dict(height=i, public_height=parsed['anchor_height'], work_id=seal.hex(),
                                     block_sha256=hash32(raw).hex(), canonical_packet_sha256=hash32(packet).hex(),
                                     proof_B=parsed['proof_B'], receipt_B=len(receipt), cum_fees=fees,
                                     distinct_salt_tuples=parsed['distinct_salt_tuples'], root=header[-32:].hex(),
                                     anchor=current.hex()))
        meters = verify.close()
    finally:
        verify.abort()
    assert len(observations) == 4 and fees == 12 and len(commitments) == 12 and len(spent) == 8 and len(receipts) == 8
    return dict(genesis_approval=approval, VK=profile, crypto_binary=pin, initial_native=400, initial_token=240,
                public_fee_sink=fees, commitments=len(commitments), spent_identifiers=len(spent),
                all_receipts_distinct=True, public_only_replayed=observations, verifier_meters=meters)


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Use without -O so public invariants are checked.')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'runtime', 'helpers', 'evidence'):
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    parser.add_argument('--genesis', required=True, help='SHA-256 of independently approved founding record')
    args = parser.parse_args()
    print(json.dumps(run(args.source, args.runtime, args.helpers, args.evidence, args.genesis), sort_keys=True, indent=2))
