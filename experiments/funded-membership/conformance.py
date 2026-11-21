"""Compare the independent mathematical specification with real funded block and proof fields.

This is a conformance reader. Native proof and issuer verification run separately in review/replay.py.
"""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from reference import Authority, Input, Tree, ZERO, check_input, hash_bytes, need, reward, tree_depth

H = lambda b: sha256(b).digest()
NETWORK = H(b"AST1/PoW/network/v1\0" + bytes.fromhex(
    "99ed868d5bd0f8541bb6467a210bf75140ec696e49e53044f7bca011ed59438a") + struct.pack("<BBBIQ",22,8,4,8,100))
GENESIS = H(b"AST1/PoW/genesis/v1\0"+NETWORK)


def packets(raw):
    offset = 214
    for _ in range(raw[213]):
        n, = struct.unpack_from("<I",raw,offset)
        offset += 4
        need(0 < n <= 262144 and offset+n <= len(raw)-8,"payment frame")
        yield raw[offset:offset+n]
        offset += n
    need(offset == len(raw)-8,"block framing")


def public_inputs(raw):
    versions = {b"AST1":31,b"MNG1":31,b"MNG2":31,b"MNG3":32,b"SLG1":34,b"SLG2":34,b"SLG3":35}
    if raw.startswith(b"SWF"):
        inner = raw[17195:]
    elif raw.startswith(b"MSP"):
        inner = raw[17166:] if raw[5] in (2,3) else raw[6:]
    else:
        inner = raw
    k = versions[inner[:4]]
    end = 9+int.from_bytes(inner[5:9],"little")
    need(end+3584==len(inner) and int.from_bytes(inner[end-8*(k+1):end-8*k],"little")==k,
         "funded proof public word count")
    pi = inner[end-8*k:end]
    return inner[:4].decode(),pi


def inspect(public, backup=None):
    by_pk = {}
    if backup:
        for name in ("miner-a","miner-b"):
            seed = (backup/name).read_bytes()
            need(len(seed)==32,"fixture backup length")
            auth = Authority(hash_bytes(b"qnero/ask"+seed),hash_bytes(b"qnero/nk"+seed))
            by_pk[auth.pk] = auth
    blocks = []
    for path in (public/"blocks").glob("*.bin"):
        raw = path.read_bytes()
        need(raw[:8]==b"ASTPOW01" and raw[8:40]==NETWORK and raw[40]==22 and len(raw)>=222,"block schema")
        bid = H(b"PQDEV1/work\0"+H(b"PQDEV1/template\0"+raw[:-8])+raw[-8:])
        need(bid.hex()==path.stem and int.from_bytes(bid,"big") < 2**234,"work identity")
        blocks.append((int.from_bytes(raw[73:77],"little"),bid,raw))
    need(blocks,"empty graph")
    history = {GENESIS:((),frozenset(),(),{})}
    classes = Counter()
    owned_checks = 0
    empty_checks = 0
    depths = set()
    for height,bid,raw in sorted(blocks):
        old,spent,bases,owners = history[raw[41:73]]
        need(height==len(bases)+1,"height sequence")
        leaves = list(old)
        spent = set(spent)
        owners = dict(owners)
        for packet in packets(raw):
            tag,pi = public_inputs(packet)
            classes[tag] += 1
            anchor_height = int.from_bytes(pi[32:40],"little")
            need(1 <= height-anchor_height <= 8 and anchor_height>0,"funding anchor age")
            anchor = bases[anchor_height-1]
            if tag in ("MNG3","SLG3"):
                need(int.from_bytes(pi[-8:],"little") == tree_depth(anchor.count),"anchored funded depth")
            for nf in (pi[40:72],pi[72:104]):
                need(nf not in spent,"spent identity reappeared on one branch")
                if nf in owners:
                    authority, note, index = owners[nf]
                    witness = Input(authority,note,nf,index,anchor.path(index))
                    need(check_input(anchor,witness,spent)==nf,"real authorizing opening")
                    owned_checks += 1
                spent.add(nf)
            leaves.extend((pi[104:136],pi[136:168]))
        context = H(b"PQDEV1/reward-context\0"+NETWORK+raw[41:77]+raw[77:109]+H(raw[213:-8]))
        note = reward(context,raw[77:109],int.from_bytes(raw[109:117],"little"))
        need(note.commitment == raw[117:149],"funded reward opening")
        if by_pk:
            authority = by_pk[note.pk]
            owners[note.nullifier(authority.nk)] = (authority,note,len(leaves))
        leaves.append(note.commitment)
        tree = Tree(leaves)
        need(tree.root == raw[181:213],"independent funded root")
        need(tree.root!=ZERO and all(ZERO not in row for row in tree.levels),"occupied zero digest in this graph")
        empty_checks += sum(map(len,tree.levels))+1
        depths.add(tree_depth(tree.count))
        history[bid] = (tuple(leaves),frozenset(spent),(*bases,tree),owners)
    need(not by_pk or owned_checks>0,"no funded private authorization exercised")
    return dict(block_roots=len(blocks),depths=sorted(depths),payment_proof_fields=dict(sorted(classes.items())),
                occupied_values_checked_across_snapshots=empty_checks,
                owned_mining_reward_inputs_matched=owned_checks if by_pk else None)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("public",type=Path)
    p.add_argument("--miner-backups",type=Path,help="optional private oracle; emits counts only")
    a = p.parse_args()
    print(json.dumps(inspect(a.public,a.miner_backups),indent=2,sort_keys=True))
