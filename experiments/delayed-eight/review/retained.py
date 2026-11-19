"""Cold independent D8ARCH01 replay from compact evidence, including loss of each source individually."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / 'experiments/advancing-payments'))
from wire import Role
from certificate import Wire, layout, read_certificate
from ledger import GENESIS, decode_core, dissect, evaluate, public_packet, reference, sid


def sections(archive):
    data = Wire(archive)
    assert data.take(8) == b'D8ARCH01'
    counts = [data.integer(4) for _ in range(2)]
    assert max(counts) <= len(archive) // 4
    contents = [[data.take(data.integer(4)) for _ in range(n)] for n in counts]
    assert not data.read()
    return contents


def verify_sources(items, direct, outer, direct_sha, outer_sha, roots):
    inner = direct / 'keys/direct.vk'
    approved = json.loads((HERE.parent / 'crypto/registry.json').read_bytes())['key_sha256']
    assert sha256(inner.read_bytes()).hexdigest() == approved['direct.vk']
    assert sha256((outer/'keys/eight.vk').read_bytes()).hexdigest() == approved['eight.vk']
    params = layout((outer/'keys/eight.vk').read_bytes())
    direct_role = Role(direct/'runtime/native', direct_sha, ['verify','/keys'], direct/'keys')
    wrapper = Role(outer/'native', outer_sha, ['verify','/keys'], outer/'keys')
    verified = {}
    try:
        assert wrapper.get() == b'READY'
        for item in items:
            if item.startswith(b'DLF1'):
                row, digest = public_packet(item)
                assert reference(roots, ['--ciphertext-digests'], row[172:]) == [digest.hex()]
                rows = [row]
                role = direct_role
            else:
                rows = read_certificate(item, params, roots)
                role = wrapper
            assert role.call(item) == b'1' + b''.join(rows)
            cid = sha256(item).hexdigest()
            assert cid not in verified
            verified[cid] = {sid(row):row for row in rows}
        direct_role.close()
        wrapper.close()
    finally:
        direct_role.abort()
        wrapper.abort()
    return verified


def available_chains(cores, rows, roots, rewards):
    paths = {GENESIS: []}
    heads = set()
    waiting = []
    for raw in sorted(cores, key=lambda b: int.from_bytes(b[73:77], 'little')):
        parent = raw[41:73]
        wanted = [raw[i:i + 32] for i in range(214, len(raw) - 8, 32)]
        if parent not in paths:
            continue
        absent = [k for k in wanted if k not in rows]
        if absent:
            waiting.append(dict(height=int.from_bytes(raw[73:77], 'little'), missing_sids=[s.hex() for s in absent]))
            continue
        block = decode_core(raw, [rows[s] for s in wanted], len(raw))
        h = block['id']
        assert h not in paths
        paths[h] = [*paths[parent], block]
        heads.discard(parent)
        heads.add(h)
    branches = [evaluate(paths[h], roots, rewards) for h in sorted(heads)]
    assert branches
    winner = min(branches, key=lambda b:(-b['work'], b['tip']))
    return dict(validated_cores=len(paths)-1, tips=branches, best=winner['tip'], best_height=winner['height'],
                missing_parent_ready=waiting)


def check(archive, direct, outer, direct_sha, outer_sha, roots, rewards, successor=None):
    raw = archive.read_bytes()
    cores, sources = sections(raw)
    validated = verify_sources(sources, direct, outer, direct_sha, outer_sha, roots)
    def unlocked(skip=None):
        rows = {}
        for cid, paid in validated.items():
            if cid != skip:
                for key, value in paid.items():
                    assert key not in rows or rows[key] == value
                    rows[key] = value
        return available_chains(cores, rows, roots, rewards)
    full = unlocked()
    assert full['validated_cores'] == len(cores)
    outages = {}
    for cid in validated:
        result = unlocked(cid)
        outages[cid] = {k:result[k] for k in ('best','best_height','validated_cores','missing_parent_ready')}
    extension = None
    if successor is not None:
        summary = json.loads((successor/'SUMMARY.json').read_bytes())
        assert summary['parent'] == full['best']
        payment = (successor/'payment.bin').read_bytes()
        all_rows = {s:v for group in validated.values() for s,v in group.items()}
        after = verify_sources([payment], direct, outer, direct_sha, outer_sha, roots)
        added = next(iter(after.values()))
        assert list(added)[0].hex() == summary['payment'] and not (set(all_rows) & set(added))
        all_rows.update(added)
        suffix = []
        for blockid in summary['selected']:
            encoded = (successor / (blockid + '.bin')).read_bytes()
            b = dissect(encoded, roots)
            assert b['id'].hex() == blockid
            suffix.append(encoded[:214] + b''.join(b['sids']) + encoded[-8:])
        final = available_chains(cores + suffix, all_rows, roots, rewards)
        last = next(b for b in final['tips'] if b['tip'] == final['best'])
        assert last['sids'][-1] == summary['payment'] and last['root'] == summary['state']['header'][-64:]
        for key in ('tip','height','issued','fees','spent','spent_set_sha256'):
            assert last[key] == summary['state'][key]
        extension = dict(tip=last['tip'], height=last['height'], root=last['root'], fees=last['fees'], issued=last['issued'],
                         spent=last['spent'], new_sid=summary['payment'], blocks=len(suffix))
    return dict(verified_successor=extension, archive_sha256=sha256(raw).hexdigest(), total_B=len(raw), core_B=sum(map(len,cores)),
                source_B=sum(map(len,sources)), frame_B=16+4*(len(cores)+len(sources)), source_slots={c:len(v) for c,v in validated.items()},
                all_sources=full, drop_single_source=outages)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('archive','direct_deploy','outer_runtime','roots','rewards'):
        ap.add_argument(name,type=Path)
    ap.add_argument('--direct-sha',required=True)
    ap.add_argument('--outer-sha',required=True)
    ap.add_argument('--successor', type=Path)
    args = ap.parse_args()
    print(json.dumps(check(args.archive,args.direct_deploy.resolve(),args.outer_runtime.resolve(),args.direct_sha,args.outer_sha,
                           args.roots.resolve(),args.rewards.resolve(),args.successor),indent=2,sort_keys=True))
