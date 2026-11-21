"""Independently reconstruct the funded-upgrade PoW graph and check the registered proofs."""
import argparse
from collections import Counter
from contextlib import ExitStack
import json
from pathlib import Path
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parents[1]
sys.path.insert(0, str(EXPERIMENTS / 'atomic-swap/review'))
from audit import MANAGED_VK, SWAP_VK, mount, read_graph, selected_summary
from events import Event, Reader as ManagedReader, ZERO, ast1
from swaps import Frame, MANAGED, hash_bytes

PINS = {
    'MNG1': ('managed.vk', MANAGED_VK, ''),
    'SLG1': ('swap.vk', SWAP_VK, 'swap-'),
    'MNG2': ('managed.vk', '41711318f4777012b89a2331e4d92a3cf3145817c7e1f28a304f73a5532d2c84', 'b-'),
    'SLG2': ('swap.vk', 'e82c50ce0000ec7d508b7325473e08092e87d6b82c80833a9d490156a7941189', 'b-swap-'),
}
NETWORK = hash_bytes(b'AST1/PoW/network/v1\0' + bytes.fromhex(ast1.VK) + ast1.RULES)


class Reader:
    def __init__(self, roles, helpers, node):
        self.network = NETWORK
        self.roots = helpers / 'roots'
        self.roles = roles
        ast = ast1.Reader(roles['MNG1'], self.roots, NETWORK)
        self.historical = ManagedReader(roles['MNG1'], self.roots, NETWORK, node, ast)
        self.frames = {}
        self.kinds = {}
        self.groups = {}
        self.authorizations = set()
        self.bytes_by_id = {}
        self.calls = Counter()

    def payment(self, inner, suite, frame):
        is_swap = suite.startswith('SLG')
        count = 34 if is_swap else 31
        assert inner[:5] == suite.encode() + b'\x01'
        size, = struct.unpack_from('<I', inner, 5)
        end = 9 + size
        assert size > 8 * (count + 1) and len(inner) == end + 3584
        prefix, *words = struct.unpack_from(f'<{count+1}Q', inner, end - 8 * (count + 1))
        assert prefix == count and all(w < ast1.P for w in words) and words[4] < 2**32
        pi, receipts = inner[end-8*count:end], inner[end:]
        assert ast1.reference(self.roots, ['--ciphertext-digests'], receipts) == [pi[176:208].hex()]
        if is_swap:
            assert all(w < 2**32 for w in words[26:])
            suffix = struct.pack('<8I', *words[26:])
        else:
            assert words[21] == 3 and words[26:] == [0] * 5
            suffix = pi[208:]
        assert self.roles[suite].call(inner) == b'1' + pi[:36] + pi[40:176] + receipts + suffix
        self.calls[suite] += 1
        e = Event(hash_bytes(frame), 0, b'', 0, ZERO, words[4], pi[:32],
                  (pi[40:72], pi[72:104]), (pi[104:136], pi[136:168]), words[21], ZERO, 0, receipts)
        assert len(set(e.nullifiers)) == len(set(e.commitments)) == 2 and ZERO not in e.commitments
        return e, suffix

    def packet(self, raw):
        assert 5 < len(raw) <= 262144
        kind = raw[:4].decode('ascii')
        if kind in ('AST1','MSP1'):
            e = self.historical.packet(raw)
            self.calls['AST1' if kind == 'AST1' else 'MNG1'] += 1
        elif kind == 'MSP2':
            assert raw[:6] == b'MSP2\x01\x00'
            e, _ = self.payment(raw[6:], 'MNG2', raw)
        else:
            assert kind in ('SWF1','SWF2') and raw[4] == 1 and len(raw) > 17195
            side, payer, expiry = struct.unpack_from('<BBI', raw, 5)
            terms, other, sig, leg = raw[43:75], raw[75:107], raw[107:17195], raw[17195:]
            assert side in (0, 1) and payer in (0, 1) and expiry and raw[11:43] == NETWORK and terms != ZERO
            e, key = self.payment(leg, 'SLG' + kind[-1], raw)
            assert e.fee == (3 if side == payer else 0)
            f = Frame(raw, side, payer, expiry, NETWORK, terms, other, sig, leg, key, e)
            assert self.frames.setdefault(e.txid, f) == f
        self.kinds[e.txid] = kind
        self.bytes_by_id[e.txid] = len(raw)
        return e

    def validate_block(self, slots, height):
        pairs = 0
        remaining = iter(slots)
        for event in remaining:
            kind = self.kinds[event.txid]
            if kind in ('MSP2','SWF2'):
                assert height >= 13
            elif not event.op:
                assert height <= 14
            if not kind.startswith('SWF'):
                continue
            first = self.frames[event.txid]
            other = next(remaining, None)
            assert other and self.kinds[other.txid] == kind
            second = self.frames[other.txid]
            assert (first.side, second.side) == (0,1) and first.key != second.key
            assert (first.terms, first.payer, first.expiry) == (second.terms, second.payer, second.expiry)
            assert height <= first.expiry
            legs = (hash_bytes(first.leg), hash_bytes(second.leg))
            assert (first.partner_digest, second.partner_digest) == legs[::-1]
            domain = ('SWP' + kind[-1] + '/joint-authorization/v1\0').encode()
            message = hash_bytes(domain + NETWORK + first.terms + struct.pack('<IB', first.expiry, first.payer) + b''.join(legs))
            for f in (first, second):
                self.authorizations.add(f.key + message + f.signature)
            group = ('SWB' + kind[-1]).encode() + b'\x01' + b''.join(struct.pack('<I', len(f.encoded)) + f.encoded for f in (first,second))
            self.groups[hash_bytes(group)] = dict(frames=[event.txid.hex(), other.txid.hex()],
                fee_by_leg=[event.fee, other.fee], complete_B=len(group), frame_B=[len(first.encoded), len(second.encoded)])
            pairs += 1
        return pairs


def reconcile(public, deployment, helpers, node, disclosures=None):
    with ExitStack() as stack:
        roles = {name: mount(stack, deployment, name, *spec)[0] for name,spec in PINS.items()}
        reader = Reader(roles, helpers, node)
        states, blocks, tips, best = read_graph(public, reader, helpers)
        sigs = sorted(reader.authorizations | set(reader.historical.sigs))
        assert sigs and subprocess.check_output([node, MANAGED / 'verify_slh.mjs'], input=b''.join(sigs)) == b'1' * len(sigs)
        selected = states[best]
        assert len(tips) >= 2 and len(selected.ids) > 16
        swaps = {k.hex(): v for k,v in reader.groups.items()}
        assert hash_bytes((public / 'SWAP.bin').read_bytes()).hex() in swaps
        native_fees = Counter()
        for bid in selected.ids[1:]:
            block = blocks[bid]
            native_fees[block.miner.hex()] += block.amount - 100
        assert sum(native_fees.values()) == selected.fees
        assert sorted(rec.supply for rec in selected.assets.values()) == [80, 100]
        assert sorted(rec.mode for rec in selected.assets.values()) == ['fixed', 'managed']
        assert any(reader.kinds[tx] == 'MSP2' for tx in selected.locations)
        assert any(reader.kinds[tx] == 'SWF2' for tx in selected.locations)
        assert any(reader.kinds[tx] == 'MSP1' and not reader.historical.events[tx].op for tx in selected.locations)
        # The same consumable identity can occur on competing branches but only once on one history.
        a = {nf:tx for tx,e in reader.historical.events.items() if not e.op for nf in e.nullifiers}
        conflicts = []
        for b in blocks.values():
            for e in b.slots:
                if reader.kinds[e.txid] == 'MSP2':
                    for tx in {a[nf] for nf in e.nullifiers if nf in a}:
                        assert all(not ({tx, e.txid} <= s.locations.keys()) for s in states.values())
                        conflicts.append((tx.hex(), e.txid.hex()))
        assert conflicts
        extra = {}
        if disclosures is not None:
            sys.path.insert(0, str(HERE))
            from fixture_amounts import audit
            extra['disclosed_stages'] = audit(json.loads(disclosures.read_bytes()), states, blocks, reader, best)
        return dict(**extra, network=NETWORK.hex(), genesis=selected.ids[0].hex(), captured_blocks=len(blocks),
                    public_proof_calls=dict(reader.calls), independent_signatures=len(sigs),
                    cross_suite_spends=sorted(set(conflicts)), selected=selected_summary(selected, reader),
                    fork_tips=[selected_summary(states[t], reader) for t in sorted(tips)],
                    selected_miner_fees=dict(native_fees), signed_swaps=swaps,
                    selected_packet_bytes=sum(reader.bytes_by_id[tx] for tx in selected.locations),
                    captured_block_bytes=sum(p.stat().st_size for p in (public / 'blocks').glob('*.bin')))


if __name__ == '__main__':
    if not __debug__:
        sys.exit('run with Python assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('public', 'deployment', 'helpers', 'node'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--disclosures', type=Path, help='also check disclosed participant amounts against RUN.json')
    print(json.dumps(reconcile(**vars(parser.parse_args())), indent=2, sort_keys=True))
