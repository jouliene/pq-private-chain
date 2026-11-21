"""Independently verify every historical funded A/B/C branch and each C depth at its anchor."""
import argparse
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'funded-upgrade/review'))
from public import Event, Frame, MANAGED, NETWORK, PINS, Reader as ABReader, ZERO, ast1, hash_bytes, mount, read_graph, selected_summary
from audit import extend
from chain_audit import read_block
from events import BURN, MAX, label
sys.path.insert(0, str(HERE))
from economics_c import inspect


class Reader(ABReader):
    def __init__(self, roles, helpers, node):
        super().__init__(roles, helpers, node)
        self.depths = {}

    def c_proof(self, leg, raw, swap):
        suite, count = ('SLG3', 35) if swap else ('MNG3', 32)
        assert leg[:5] == suite.encode() + b'\x01'
        size, = struct.unpack_from('<I', leg, 5)
        end = 9 + size
        assert size > (count + 1) * 8 and len(leg) == end + 3584
        length, *words = struct.unpack_from(f'<{count+1}Q', leg, end - (count+1)*8)
        assert length == count and all(w < ast1.P for w in words) and words[4] < 2**32
        depth = words[-1]
        assert 1 <= depth <= 20
        pi, ct = leg[end-count*8:end], leg[end:]
        assert ast1.reference(self.roots, ['--ciphertext-digests'], ct) == [pi[176:208].hex()]
        if swap:
            assert all(w < 2**32 for w in words[26:-1])
            suffix = struct.pack('<8I', *words[26:-1])
        else:
            assert words[21] == 3
            suffix = pi[208:-8]
        assert self.roles[suite].call(leg) == b'1' + pi[:36] + pi[40:176] + ct + suffix + bytes([depth])
        self.calls[suite] += 1
        ident = hash_bytes(raw)
        assert self.depths.setdefault(ident, depth) == depth
        event = Event(ident,0,b'',0,ZERO,words[4],pi[:32],(pi[40:72],pi[72:104]),
                      (pi[104:136],pi[136:168]),words[21],ZERO if swap else pi[208:240],
                      0 if swap else words[30],ct)
        assert len(set(event.nullifiers)) == len(set(event.commitments)) == 2 and ZERO not in event.commitments
        return event, suffix

    def c_managed(self, raw):
        op = raw[5]
        assert op in range(5)
        if op in (2,3):
            key, seq, prev = raw[6:38], struct.unpack_from('<Q', raw, 38)[0], raw[46:78]
            signature, leg = raw[78:17166], raw[17166:]
            assert len(signature) == 17088 and seq < 1 << 63
            digest = hash_bytes(b'MNG3/supply-auth/v1\0' + NETWORK + bytes([op]) + key +
                                struct.pack('<Q', seq) + prev + hash_bytes(leg))
            self.authorizations.add(key + digest + signature)
        else:
            key, seq, prev, leg = b'', 0, ZERO, raw[6:]
        effect, _ = self.c_proof(leg, raw, False)
        e = replace(effect, op=op, issuer=key, sequence=seq, prior=prev)
        assert e.delta < 1 << 63 and bool(e.delta & BURN) == (op == 4)
        assert (op == 0) == (e.delta & MAX == 0) == (e.asset == ZERO)
        if op:
            assert all(octet < 128 for octet in e.asset[7::8])
        if op == 1:
            assert e.asset == label(b'AST1/issue-id/v1\0', NETWORK + e.nullifiers[0])
        if op == 2:
            assert e.asset == label(b'MNG1/managed-id/v1\0', NETWORK + key + e.nullifiers[0])
        return e

    def packet(self, raw):
        if raw[:4] not in (b'MSP3', b'SWF3'):
            return super().packet(raw)
        assert raw[4] == 1 and 6 < len(raw) <= 262144
        if raw.startswith(b'MSP3'):
            e = self.c_managed(raw)
        else:
            side, payer, expiry = struct.unpack_from('<BBI', raw, 5)
            net, terms, other, signature, leg = raw[11:43], raw[43:75], raw[75:107], raw[107:17195], raw[17195:]
            assert side in (0,1) and payer in (0,1) and expiry and net == NETWORK and terms != ZERO
            assert len(signature) == 17088
            e, key = self.c_proof(leg, raw, True)
            assert e.fee == (3 if side == payer else 0)
            frame = Frame(raw,side,payer,expiry,net,terms,other,signature,leg,key,e)
            assert self.frames.setdefault(e.txid, frame) == frame
        self.kinds[e.txid] = raw[:4].decode('ascii')
        self.bytes_by_id[e.txid] = len(raw)
        return e

    def validate_block(self, slots, height):
        assert all((e.txid in self.depths) == (height >= 25) for e in slots)
        if height < 25:
            return super().validate_block(slots, height)
        pairs = 0
        stream = iter(slots)
        for e in stream:
            if e.txid not in self.frames:
                continue
            other = next(stream, None)
            assert other and other.txid in self.frames
            a, b = self.frames[e.txid], self.frames[other.txid]
            assert a.side == 0 and b.side == 1 and a.key != b.key
            assert (a.payer,a.terms,a.expiry) == (b.payer,b.terms,b.expiry) and height <= a.expiry
            legs = hash_bytes(a.leg), hash_bytes(b.leg)
            assert (a.partner_digest,b.partner_digest) == legs[::-1]
            message = hash_bytes(b'SWP3/joint-authorization/v1\0' + NETWORK + a.terms +
                                 struct.pack('<IB', a.expiry, a.payer) + b''.join(legs))
            for frame in (a,b):
                self.authorizations.add(frame.key + message + frame.signature)
            group = b'SWB3\x01' + b''.join(struct.pack('<I', len(f.encoded)) + f.encoded for f in (a,b))
            self.groups[hash_bytes(group)] = dict(frames=[e.txid.hex(),other.txid.hex()],
                                                  fee_by_leg=[e.fee,other.fee],complete_B=len(group))
            pairs += 1
        return pairs


def eligibility(reader, states, blocks):
    observations = []
    for bid, block in sorted(blocks.items(), key=lambda pair:(pair[1].height,pair[0])):
        parent = states[block.parent]
        for e in block.slots:
            if e.txid not in reader.depths:
                continue
            basis = states[parent.ids[e.born]]
            count = len(basis.outs)
            depth, capacity = 1, 4
            while capacity < count:
                depth, capacity = depth + 1, capacity * 4
            assert 0 < count <= 4**20 and 1 <= block.height-e.born <= 8
            assert e.anchor == basis.anchors[-1] and reader.depths[e.txid] == depth
            observations.append(dict(block=bid.hex(), tx=e.txid.hex(), height=block.height, anchor_height=e.born,
                                     anchor_count=count, parent_count=len(parent.outs), proved_depth=depth))
    return observations


def replay(public, deployment, helpers, node):
    with ExitStack() as stack:
        pins = dict(PINS)
        for suite,name,prefix in (('MNG3','managed.vk','c-'),('SLG3','swap.vk','c-swap-')):
            digest = hash_bytes((HERE.parent/'registry'/name).read_bytes()).hex()
            pins[suite] = (name, digest, prefix)
        roles = {s:mount(stack, deployment, s, *spec)[0] for s,spec in pins.items()}
        reader = Reader(roles, helpers, node)
        states, blocks, tips, best = read_graph(public, reader, helpers)
        signatures = sorted(reader.authorizations | set(reader.historical.sigs))
        assert signatures
        assert subprocess.check_output([node, MANAGED/'verify_slh.mjs'], input=b''.join(signatures),
                                       timeout=60) == b'1' * len(signatures)
        opened = eligibility(reader, states, blocks)
        assert len(tips) >= 2 and opened and reader.calls['MNG3'] and reader.calls['SLG3']
        assert any(o['anchor_count'] == 64 and o['parent_count'] > 64 and o['proved_depth'] == 3 for o in opened)
        assert any(o['anchor_count'] > 64 and o['proved_depth'] == 4 for o in opened)
        bundle = (public/'SWAP.bin').read_bytes()
        assert bundle.startswith(b'SWB3\x01') and hash_bytes(bundle) in reader.groups
        packets = set()
        for path in (public/'packets').glob('*.bin'):
            data = path.read_bytes()
            ident = hash_bytes(data)
            assert ident.hex() == path.stem
            packets.add(ident)
        assert packets == {e.txid for b in blocks.values() for e in b.slots}
        assert {e.op for b in blocks.values() for e in b.slots if reader.kinds[e.txid] == 'MSP3'} == set(range(5))
        doc = json.loads((public/'RUN.json').read_bytes())
        comparison = doc['controls']['legacy_B']
        old_raw = (public/'controls/legacy-b-block.bin').read_bytes()
        ab = ABReader(roles, helpers, node)
        old = read_block(old_raw, bytes.fromhex(comparison['block']), NETWORK, ab)
        assert old.height == 25 and old.parent.hex() == doc['tips']['prefix']['tip']
        assert ast1.reference(helpers/'rewards', [], old.reward_record) == [old.reward.hex()]
        old_state = extend(states[old.parent], old, ab, helpers/'roots')
        single, = old.slots
        assert ab.kinds[single.txid] == 'MSP2' and single.txid.hex() == comparison['tx']
        assert hash_bytes((public/'controls/legacy-b.bin').read_bytes()) == single.txid
        assert list(ab.calls.items()) == [('MNG2', 1)]
        for name in ('paid','alternate'):
            row = doc['operations'][name]
            new_event, = blocks[bytes.fromhex(row['block'])].slots
            assert set(new_event.nullifiers) == set(single.nullifiers) and new_event.txid != single.txid
        assert all(single.txid not in state.locations for state in states.values())
        legacy = dict(valid_under_previous_rules=True, height=old.height, fee_total=old_state.fees,
                      shared_public_nullifiers=2, txid=single.txid.hex(),
                      present_in_c_graph=False)
        financial = inspect(doc, states, blocks, best, reader)
        return dict(disclosed_fixture=financial, legacy_comparison=legacy, network=NETWORK.hex(), genesis=states[best].ids[0].hex(), captured_blocks=len(blocks),
                    public_proof_calls=dict(reader.calls), distinct_signatures=len(signatures), c_depths=opened,
                    selected=selected_summary(states[best], reader),
                    branches=[selected_summary(states[t],reader) for t in sorted(tips)])


if __name__ == '__main__':
    if not __debug__:
        sys.exit('run with Python assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    for parameter in ('public','deployment','helpers','node'):
        parser.add_argument(parameter, type=Path)
    print(json.dumps(replay(**vars(parser.parse_args())), sort_keys=True, indent=2))
