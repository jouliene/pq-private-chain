"""Replay every captured AST1 PoW branch and public proof using local operator-approved code."""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT / 'experiments/advancing-payments/review'), str(ROOT / 'experiments/advancing-payments')]
from public_chain import P, ZERO, counted_hash, reference
from wire import Role

U32 = struct.Struct('<I')
U64 = struct.Struct('<Q')
RULES = struct.pack('<BBBIQ', 22, 8, 4, 8, 100)
RECEIPT = 1792
VK = '99ed868d5bd0f8541bb6467a210bf75140ec696e49e53044f7bca011ed59438a'


def sha(raw):
    return sha256(raw).digest()


def field(digest):
    return len(digest) == 32 and all(word < P for word in struct.unpack('<4Q', digest))


def asset_id(network, first_nf):
    words = struct.unpack('<4Q', sha(b'AST1/issue-id/v1\0' + network + first_nf))
    return struct.pack('<4Q', *(w & ((1 << 63) - 1) for w in words))


@dataclass(frozen=True)
class Effect:
    txid: bytes
    anchor: bytes
    born: int
    nullifiers: tuple
    commitments: tuple
    fee: int
    issue: bytes
    cap: int
    receipts: bytes

    def transition(self):
        return b''.join((*self.nullifiers, *self.commitments, U64.pack(self.fee), self.issue, U64.pack(self.cap)))


class Reader:
    def __init__(self, role, roots, network):
        self.role = role
        self.roots = roots
        self.network = network
        self.effects = {}
        self.calls = 0

    def packet(self, raw):
        assert 9 <= len(raw) <= 262144 and raw[:5] == b'AST1\x01'
        size, = U32.unpack_from(raw, 5)
        end = 9 + size
        assert size > 8 * 32 and len(raw) == end + 2 * RECEIPT
        length, *words = struct.unpack_from('<32Q', raw, end - 256)
        assert length == 31 and all(w < P for w in words)
        pi, ct = raw[end-248:end], raw[end:]
        assert reference(self.roots, ['--ciphertext-digests'], ct) == [pi[176:208].hex()]
        assert words[4] < 1 << 32 and words[21] == 3
        assert self.role.call(raw) == b'1' + pi[:36] + pi[40:176] + ct + pi[208:]
        self.calls += 1
        e = Effect(sha(raw), pi[:32], words[4], (pi[40:72], pi[72:104]),
                   (pi[104:136], pi[136:168]), words[21], pi[208:240], words[30], ct)
        assert len(set(e.nullifiers)) == len(set(e.commitments)) == 2 and ZERO not in e.commitments
        if e.cap:
            assert 0 < e.cap < 1 << 62 and e.issue == asset_id(self.network, e.nullifiers[0]) != ZERO
        else:
            assert e.issue == ZERO
        assert self.effects.setdefault(e.txid, e) == e
        return e


@dataclass
class Block:
    id: bytes
    parent: bytes
    height: int
    miner: bytes
    amount: int
    reward: bytes
    state: bytes
    root: bytes
    context: bytes
    slots: tuple

    @property
    def reward_record(self):
        return self.context + self.miner + U64.pack(self.amount) + self.reward


def parse_block(raw, bid, network, reader):
    assert 222 <= len(raw) <= 222 + 4 * (4 + 262144)
    assert raw[:41] == b'ASTPOW01' + network + bytes([22])
    assert sha(b'PQDEV1/work\0' + sha(b'PQDEV1/template\0' + raw[:-8]) + raw[-8:]) == bid
    assert int.from_bytes(bid, 'big') < 1 << 234
    parent, height, miner = raw[41:73], U32.unpack_from(raw, 73)[0], raw[77:109]
    amount = U64.unpack_from(raw, 109)[0]
    reward, state, root = (raw[i:i+32] for i in (117,149,181))
    assert all(field(v) for v in (miner,reward,state,root)) and ZERO not in (miner,reward)
    count, end = raw[213], len(raw)-8
    assert count <= 4
    ptr, slots = 214, []
    for _ in range(count):
        assert ptr + 4 <= end
        length, = U32.unpack_from(raw, ptr)
        ptr += 4
        assert 0 < length <= min(262144, end-ptr)
        slots.append(reader.packet(raw[ptr:ptr+length]))
        ptr += length
    assert ptr == end and amount == 100 + sum(e.fee for e in slots)
    context = sha(b'PQDEV1/reward-context\0' + network + parent + U32.pack(height) + miner + sha(raw[213:end]))
    return Block(bid,parent,height,miner,amount,reward,state,root,context,tuple(slots))


@dataclass
class Branch:
    ids: tuple
    anchors: tuple
    header: bytes
    outputs: tuple
    spent: dict
    locations: dict
    registry: dict
    fees: int
    credited: int

    def summary(self):
        height = len(self.ids)-1
        return dict(tip=self.ids[-1].hex(), height=height, work=height*(1 << 22), root=self.header[-32:].hex(),
                    anchor=self.anchors[-1].hex(), fees=self.fees, issued=height*100, miner_credits=self.credited,
                    notes=len(self.outputs), spent=len(self.spent), spent_set_sha256=sha(b''.join(sorted(self.spent))).hex(),
                    payments=len(self.locations), registry={aid.hex(): dict(cap=row[0], height=row[1], tx=row[2].hex())
                                                            for aid,row in sorted(self.registry.items())})


def header_id(roots, header):
    return bytes.fromhex(reference(roots, ['--header-ids'], header)[0].split()[1])


def extend(parent, block, network, roots):
    h = block.height
    assert h == len(parent.ids) and block.parent == parent.ids[-1]
    outputs, spent = list(parent.outputs), parent.spent.copy()
    registry, locations = parent.registry.copy(), parent.locations.copy()
    cms = {r[0] for r in outputs}
    for e in block.slots:
        assert 1 <= h - e.born <= 8 and e.anchor == parent.anchors[e.born]
        assert e.txid not in locations and set(e.nullifiers).isdisjoint(spent)
        assert cms.isdisjoint(e.commitments)
        if e.cap:
            assert e.issue not in registry
            registry[e.issue] = (e.cap, h, e.txid)
        spent.update((nf,h) for nf in e.nullifiers)
        cms.update(e.commitments)
        outputs.extend((cm,h,e.receipts[i*RECEIPT:(i+1)*RECEIPT],None) for i,cm in enumerate(e.commitments))
        locations[e.txid] = block.id
    assert block.reward not in cms
    outputs.append((block.reward,h,None,block.reward_record))
    fees = parent.fees + sum(e.fee for e in block.slots)
    paid = parent.credited + block.amount
    assert paid == h*100 + fees and fees == len(locations)*3
    assert len(outputs) == h + 2*len(locations) and len(spent) == 2*len(locations)
    state = counted_hash(b'dev-state',network,parent.header[36:68],U64.pack(len(outputs)),U64.pack(h*100),
                         U64.pack(fees),block.reward_record,b''.join(e.transition() for e in block.slots))
    root = bytes.fromhex(reference(roots,[str(len(outputs))],b''.join(r[0] for r in outputs))[0].split()[2])
    assert (state,root) == (block.state,block.root)
    header = parent.anchors[-1] + U32.pack(h) + state + counted_hash(b'dev-seal',network,block.id) + root
    return Branch(parent.ids+(block.id,),parent.anchors+(header_id(roots,header),),header,tuple(outputs),spent,
                  locations,registry,fees,paid)


def compare_database(file, state):
    db = sqlite3.connect(file.resolve(strict=True).as_uri()+'?mode=ro', uri=True)
    try:
        assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
        assert db.execute('SELECT h,id FROM sel ORDER BY h').fetchall() == list(enumerate(state.ids))
        assert db.execute('SELECT pos,cm,h,ct,reward FROM outs ORDER BY pos').fetchall() == [
            (i,*r) for i,r in enumerate(state.outputs)]
        assert dict(db.execute('SELECT nf,h FROM spent')) == state.spent
        selected = db.execute('SELECT tx,bid FROM txloc JOIN sel ON bid=id').fetchall()
        assert len(selected) == len(state.locations) and dict(selected) == state.locations
        assert db.execute('SELECT id,supply,h,tx FROM assets ORDER BY id').fetchall() == [
            (aid,*r) for aid,r in sorted(state.registry.items())]
        assert db.execute('SELECT h,work,ap,header,fees,n FROM blocks WHERE id=?',(state.ids[-1],)).fetchone() == (
            len(state.ids)-1,(len(state.ids)-1)*(1 << 22),state.anchors[-1],state.header,state.fees,len(state.outputs))
    finally:
        db.close()
    return dict(selected_height=len(state.ids)-1,asset_count=len(state.registry),outputs=len(state.outputs),
                payments=len(state.locations),integrity_check='ok')


def audit(public, reader, helpers):
    network = reader.network
    genesis = sha(b'AST1/PoW/genesis/v1\0'+network)
    header = bytes(36)+counted_hash(b'dev-genesis-state',network)+counted_hash(b'dev-genesis-body',network)+ZERO
    branches = {genesis: Branch((genesis,), (header_id(helpers/'roots',header),),header,(),{},{},{},0,0)}
    blocks = {}
    sizes = []
    for file in sorted((public/'blocks').glob('*.bin')):
        bid = bytes.fromhex(file.stem)
        assert file.stem == bid.hex() and bid not in blocks
        blocks[bid] = parse_block(file.read_bytes(),bid,network,reader)
    assert blocks
    for bid,b in sorted(blocks.items(),key=lambda pair:(pair[1].height,pair[0])):
        branches[bid] = extend(branches[b.parent],b,network,helpers/'roots')
    rewards = list(blocks.values())
    for start in range(0,len(rewards),128):
        group = rewards[start:start+128]
        assert reference(helpers/'rewards',[],b''.join(b.reward_record for b in group)) == [b.reward.hex() for b in group]
    in_blocks = set(reader.effects)
    by_file = set()
    for file in sorted((public/'packets').glob('*.bin')):
        raw = file.read_bytes()
        e = reader.packet(raw)
        assert e.txid.hex() == file.stem
        by_file.add(e.txid)
        sizes.append(dict(tx=file.stem,complete_B=len(raw),proof_B=U32.unpack_from(raw,5)[0],
                          receipt_B=2*RECEIPT,issue=e.cap>0))
    assert in_blocks <= by_file
    terminals = set(blocks)-{b.parent for b in blocks.values()}
    winner = min(terminals,key=lambda tip:(-blocks[tip].height,tip))
    transitions = {}
    for tip in sorted(terminals-{winner}):
        source, dest = branches[tip], branches[winner]
        common = next(a for a in reversed(source.ids) if a in dest.ids)
        fork = branches[common]
        removed = source.registry.keys()-fork.registry.keys()
        added = dest.registry.keys()-fork.registry.keys()
        transitions[tip.hex()] = dict(common=fork.summary(),removed_assets=sorted(x.hex() for x in removed),
                                      added_assets=sorted(x.hex() for x in added),
                                      surviving_assets=sorted(x.hex() for x in fork.registry),
                                      removed_transactions=sorted(x.hex() for x in source.locations.keys()-fork.locations.keys()),
                                      added_transactions=sorted(x.hex() for x in dest.locations.keys()-fork.locations.keys()),
                                      removed_fees=source.fees-fork.fees,added_fees=dest.fees-fork.fees,
                                      removed_miner_credits=source.credited-fork.credited,
                                      added_miner_credits=dest.credited-fork.credited)
    return dict(network=network.hex(), empty_genesis=genesis.hex(), blocks=len(blocks), packets=sizes,
                full_proof_calls=reader.calls, distinct_public_packets=len(reader.effects),
                selected=branches[winner].summary(),terminal_branches=[branches[t].summary() for t in sorted(terminals)],
                branch_switches=transitions), branches, blocks, winner


def check_statement_binding(public, reader):
    cases = {}
    selected = {}
    for e in reader.effects.values():
        selected.setdefault(bool(e.cap), e)
    assert set(selected) == {False,True}
    for issue,e in sorted(selected.items()):
        raw = (public/'packets'/(e.txid.hex()+'.bin')).read_bytes()
        end = 9 + U32.unpack_from(raw,5)[0]
        prefix = 'issuance' if issue else 'ordinary'
        for field,offset in [('issue_id',end-40),('cap',end-8),('receipt',end+100),('proof',9)]:
            variant = bytearray(raw)
            variant[offset] ^= 1
            assert reader.role.call(bytes(variant)) == b'0'
            cases[prefix+'_'+field] = 'rejected'
    return cases


def main():
    if not __debug__:
        sys.exit('assertions are required')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('public','binary','vk','helpers'):
        p.add_argument('--'+name,type=lambda s:Path(s).resolve(),required=True)
    p.add_argument('--approve-binary',required=True)
    p.add_argument('--approve-vk',required=True)
    p.add_argument('--db',type=Path,action='append',default=[])
    p.add_argument('--observations',type=Path)
    args = p.parse_args()
    vk = args.vk.read_bytes()
    assert sha(vk).hex() == args.approve_vk == VK
    sys.path.insert(0,str(ROOT/'experiments/token-profile'))
    from parameters import read_key
    profile = read_key(vk)
    assert profile['common']['pi'] == 31 and profile['config']['row_blinding'] == profile['leaf_hiding'] == 1
    net = sha(b'AST1/PoW/network/v1\0'+sha(vk)+RULES)
    with tempfile.TemporaryDirectory() as mount:
        (Path(mount)/'asset.vk').write_bytes(vk)
        role = Role(args.binary,args.approve_binary,['verify','/keys'],mount)
        try:
            reader = Reader(role,args.helpers/'roots',net)
            report, branches, blocks, winner = audit(args.public,reader,args.helpers)
            report['binding_controls'] = check_statement_binding(args.public,reader)
            report['native_meters'] = role.close()
        finally:
            role.abort()
    sys.path.insert(0,str(HERE))
    from disclosures import check
    report['disclosures'] = check(args.public,reader,blocks,branches,winner,args.observations)
    report['register_sha256'] = args.approve_vk
    report['decoded_registered_key'] = {k:profile[k] for k in ('bytes','config','common','trace_rows','lde_points',
                                                              'folds_bits','leaf_hiding')}
    report['binary_sha256'] = args.approve_binary
    report['databases'] = [compare_database(file,branches[winner]) for file in args.db]
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__ == '__main__':
    main()
