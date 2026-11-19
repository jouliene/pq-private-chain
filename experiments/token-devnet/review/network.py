"""Independent finite TKN1 branch, PoW, issuance, native proof and selected-database replay."""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from effects import PublicVerifier, VK, compare
from public_chain import P, ZERO, counted_hash, reference

RULES = struct.pack('<BBBIQ', 22, 8, 4, 8, 100)
ASSET = sha256(b'TKNPOW/asset/v1\0fixed-research-token').digest()


def sha(raw):
    return sha256(raw).digest()


def u32(v):
    return struct.pack('<I', v)


def u64(v):
    return struct.pack('<Q', v)


def field(word):
    return len(word) == 32 and all(x < P for x in struct.unpack('<4Q', word))


def approved_genesis(raw, pin):
    assert len(raw) == 216 and sha(raw).hex() == pin
    assert raw[:72] == b'TKDEVGN1' + bytes.fromhex(VK) + ASSET
    row, root = raw[72:184], raw[184:]
    pk = row[32:64]
    assert field(pk) and pk != ZERO and row[:32] == sha(b'TKNPOW/founding/v1\0' + bytes.fromhex(VK) + ASSET + pk)
    assert row[64:80] == struct.pack('<QQ', 0, 240) and field(row[80:]) and row[80:] != ZERO
    net = sha(b'TKNPOW/network/v1\0' + bytes.fromhex(VK) + ASSET + sha(raw) + RULES)
    return net, sha(b'TKNPOW/genesis/v1\0' + net), row, root


@dataclass
class Block:
    parent: bytes
    height: int
    context: bytes
    miner: bytes
    amount: int
    cm: bytes
    state: bytes
    root: bytes
    effects: list

    @property
    def reward_record(self):
        return self.context + self.miner + u64(self.amount) + self.cm

    @property
    def typed_reward(self):
        return self.context + self.miner + u64(self.amount) + u64(0) + self.cm


def read_block(raw, bid, net, verifier):
    assert 222 <= len(raw) <= 222 + 4 * (4 + 256 * 1024)
    assert raw[:41] == b'TKDEVBL1' + net + bytes([22])
    calculated = sha(b'PQDEV1/work\0' + sha(b'PQDEV1/template\0' + raw[:-8]) + raw[-8:])
    assert bid == calculated and int.from_bytes(bid, 'big') < 2**234
    parent, height = raw[41:73], int.from_bytes(raw[73:77], 'little')
    miner, amount = raw[77:109], int.from_bytes(raw[109:117], 'little')
    cm, state, root = raw[117:149], raw[149:181], raw[181:213]
    assert all(field(v) for v in (miner, cm, state, root)) and miner != ZERO
    width = raw[213]
    assert width <= 4
    ptr = 214
    effects = []
    for _ in range(width):
        assert ptr + 4 <= len(raw) - 8
        length, = struct.unpack_from('<I', raw, ptr)
        ptr += 4
        assert 0 < length <= min(256 * 1024, len(raw)-8-ptr)
        effects.append(verifier.read(raw[ptr:ptr+length]))
        ptr += length
    assert ptr == len(raw) - 8
    ctx = sha(b'PQDEV1/reward-context\0' + net + parent + u32(height) + miner + sha(raw[213:ptr]))
    return Block(parent, height, ctx, miner, amount, cm, state, root, effects)


@dataclass
class Branch:
    ids: tuple
    anchors: tuple
    header: bytes
    outs: tuple
    spent: dict
    locations: dict
    fees: int
    credited: int

    def summary(self):
        return dict(tip=self.ids[-1].hex(), height=len(self.ids)-1, work=(len(self.ids)-1)*2**22,
                    root=self.header[-32:].hex(), anchor=self.anchors[-1].hex(), fees=self.fees,
                    issued=(len(self.ids)-1)*100, token_issued=240, miners_credited=self.credited,
                    spent=len(self.spent), spent_set_sha256=sha(b''.join(sorted(self.spent))).hex(),
                    notes=len(self.outs), payments=len(self.locations))


def header_id(roots, header):
    return bytes.fromhex(reference(roots, ['--header-ids'], header)[0].split()[1])


def full_root(roots, outputs):
    leaves = b''.join(row[0] for row in outputs)
    return bytes.fromhex(reference(roots, [str(len(outputs))], leaves)[0].split()[2])


def append(parent, block, bid, net, roots):
    h = block.height
    assert h == len(parent.ids) and block.parent == parent.ids[-1]
    outs, spent, loc = list(parent.outs), parent.spent.copy(), parent.locations.copy()
    cms = {row[0] for row in outs}
    sum_fees = 0
    for slot in block.effects:
        assert 1 <= h-slot.height <= 8 and slot.anchor == parent.anchors[slot.height]
        assert set(slot.nullifiers).isdisjoint(spent) and set(slot.commitments).isdisjoint(cms)
        assert ZERO not in slot.commitments and slot.txid not in loc
        spent.update((nf,h) for nf in slot.nullifiers)
        cms.update(slot.commitments)
        for i, cm in enumerate(slot.commitments):
            outs.append((cm, h, slot.receipt_pair[i*1792:(i+1)*1792], None))
        loc[slot.txid] = bid
        sum_fees += slot.fee
    assert block.amount == 100 + sum_fees and block.cm not in cms and block.cm != ZERO
    outs.append((block.cm,h,None,block.reward_record))
    fees = parent.fees + sum_fees
    credited = parent.credited + block.amount
    assert credited == 100*h + fees
    state = counted_hash(b'dev-state',net,parent.header[36:68],u64(len(outs)),u64(h*100),u64(fees),
                         block.reward_record,b''.join(e.transition() for e in block.effects))
    assert state == block.state and full_root(roots, outs) == block.root
    header = parent.anchors[-1] + u32(h) + state + counted_hash(b'dev-seal',net,bid) + block.root
    return Branch(parent.ids+(bid,), parent.anchors+(header_id(roots,header),), header,
                  tuple(outs), spent, loc, fees, credited)


def audit(public, pin, verifier, helpers, observations=None):
    net, gid, row, root = approved_genesis((public/'genesis.bin').read_bytes(), pin)
    header = bytes(36) + counted_hash(b'dev-genesis-state',net) + counted_hash(b'dev-genesis-body',net) + root
    outs = ((row[80:],0,None,None),)
    assert full_root(helpers/'roots', outs) == root
    branches = {gid: Branch((gid,), (header_id(helpers/'roots', header),), header, outs, {}, {}, 0, 0)}
    blocks = {}
    for file in sorted((public/'blocks').glob('*.bin')):
        bid = bytes.fromhex(file.stem)
        assert file.stem == bid.hex() and bid not in blocks
        blocks[bid] = read_block(file.read_bytes(), bid, net, verifier)
    assert blocks
    typed_rows = [row, *(b.typed_reward for b in blocks.values())]
    for start in range(0,len(typed_rows),128):
        rows = typed_rows[start:start+128]
        result = subprocess.check_output([helpers/'founding'],input=b''.join(rows),timeout=60).decode().splitlines()
        assert result == [f'{int.from_bytes(r[64:72],"little")} {int.from_bytes(r[72:80],"little")} {r[80:].hex()}' for r in rows]
    for bid, block in sorted(blocks.items(), key=lambda it: (it[1].height,it[0])):
        branches[bid] = append(branches[block.parent],block,bid,net,helpers/'roots')
    for file in sorted((public/'packets').glob('*.bin')):
        slot = verifier.read(file.read_bytes())
        assert slot.txid == file.stem
    tips = set(blocks) - {b.parent for b in blocks.values()}
    winner = min(tips, key=lambda bid: (-blocks[bid].height,bid))
    locations = {tid: sorted(bid.hex() for bid,b in blocks.items() if any(e.txid == tid for e in b.effects))
                 for tid in verifier.checked}
    effects = list(verifier.checked.values())
    pairs = []
    for i,a in enumerate(effects):
        for b in effects[i+1:]:
            comparison = compare(a,b)
            if comparison['shared_nf']:
                pairs.append({'first': a.txid, 'second': b.txid, **comparison})
    chosen = branches[winner]
    selected_ids = set(chosen.ids)
    selected_cms = {r[0] for r in chosen.outs}
    nonselected = {bid.hex(): dict(height=b.height,reward=b.amount,reward_cm=b.cm.hex(),
                                   reward_present_on_winner=b.cm in selected_cms,
                                   fees=sum(e.fee for e in b.effects),
                                   payments=[e.txid for e in b.effects])
                   for bid,b in blocks.items() if bid not in selected_ids}
    packet_status = {}
    for tid, effect in sorted(verifier.checked.items()):
        matching = [b.hex() for b,state in branches.items() if len(state.ids)-1 == effect.height
                    and state.anchors[-1] == effect.anchor]
        assert matching, 'captured packet anchor needs public history'
        tip_distance = len(chosen.ids)-effect.height
        packet_status[tid] = dict(anchor_height=effect.height,anchor_blocks=sorted(matching),
                                  selected_anchor=any(bytes.fromhex(v) in selected_ids for v in matching),
                                  age_at_next_selected_block=tip_distance,within_age_at_next=1<=tip_distance<=8,
                                  originating_packet_in_winner=tid in chosen.locations,
                                  selected_spent_nullifiers=len(set(effect.nullifiers).intersection(chosen.spent)))
    from observations import check
    walkthrough = check(public,branches,blocks,verifier,winner,observations)
    return dict(genesis_sha256=pin, genesis_id=gid.hex(), network=net.hex(), blocks=len(blocks), walkthrough=walkthrough,
                payments_checked=len(effects), register_sha256=VK, selected=branches[winner].summary(),
                branches=[branches[t].summary() for t in sorted(tips)], nonselected=nonselected,
                payment_blocks=locations, packet_status=packet_status, links=pairs), chosen


def compare_database(file, branch):
    with sqlite3.connect(file.resolve().as_uri()+'?mode=ro', uri=True) as db:
        selected = db.execute('SELECT h,id FROM sel ORDER BY h').fetchall()
        assert selected == list(enumerate(branch.ids))
        outs = db.execute('SELECT pos,cm,h,ct,reward FROM outs ORDER BY pos').fetchall()
        assert outs == [(i,*r) for i,r in enumerate(branch.outs)]
        assert dict(db.execute('SELECT nf,h FROM spent')) == branch.spent
        included = db.execute('SELECT tx,bid FROM txloc JOIN sel ON bid=id').fetchall()
        assert len(included) == len(branch.locations) and {t.hex():b for t,b in included} == branch.locations
        bid = branch.ids[-1]
        head, = db.execute('SELECT h,work,ap,header,fees,n FROM blocks WHERE id=?',(bid,)).fetchall()
        assert head == (len(branch.ids)-1,(len(branch.ids)-1)*2**22,branch.anchors[-1],
                        branch.header,branch.fees,len(branch.outs))
    return {'height':len(branch.ids)-1,'outputs':len(outs),'selected_payments':len(included)}


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Use without -O; the auditor validates with assertions.')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('public','binary','keys','helpers'):
        p.add_argument('--'+name,type=lambda s:Path(s).resolve(),required=True)
    p.add_argument('--genesis-sha',required=True)
    p.add_argument('--binary-sha',required=True)
    p.add_argument('--observations',type=Path)
    p.add_argument('--db',action='append',default=[],type=Path)
    args = p.parse_args()
    with PublicVerifier(args.binary,args.binary_sha,args.keys,args.helpers/'roots') as observer:
        summary, selected = audit(args.public,args.genesis_sha,observer,args.helpers,args.observations)
    summary['databases'] = [compare_database(f,selected) for f in args.db]
    print(json.dumps(summary,indent=2,sort_keys=True))
