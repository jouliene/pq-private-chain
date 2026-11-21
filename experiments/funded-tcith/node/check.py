"""Revalidate public funding and two signed registrations in isolated PoW databases."""
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import resource
import sqlite3
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), '/deploy/devnet']
import chain
import registration as reg
sys.path.insert(0, str(chain.AP))
from run import Resources
from runtime import config
from wallet_sync import role_sample
# Pin the wallet effect decoder to the same policy as the two signing wallets.
sys.path.insert(0, str(HERE.parents[1]/'atomic-swap/wallet'))
import swap_wallet


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def stamp(db):
    return (db.status(), db.pending(), [tuple(r) for r in db.db.execute('SELECT * FROM assets ORDER BY id,sequence')])


def reject(db, raw, reason):
    previous = stamp(db)
    try:
        db.offer(raw)
    except ValueError as err:
        check(reason in str(err), f'unexpected rejection: {err}')
    else:
        raise ValueError('unexpected admission: ' + reason)
    check(stamp(db) == previous, 'rejection changed ledger or pool')
    return reason


def proof_controls(db, mixed):
    a,b = reg.ft.split(mixed)

    def change_leg(offset):
        leg = bytearray(a.leg)
        leg[offset] ^= 1
        return reg.ft.assemble(a.network,a.terms,a.expiry,a.payer,
                               (bytes(leg),b.leg),(a.signature,b.signature))
    changed_sig = bytearray(a.signature)
    changed_sig[-1] ^= 1
    altered = reg.ft.assemble(a.network,a.terms,a.expiry,a.payer,(a.leg,b.leg),(bytes(changed_sig),b.signature))
    return dict(auxiliary_root=reject(db,change_leg(9+34*8),'funded root'),
                receipt=reject(db,change_leg(-1),'ordered ciphertext digest'),
                proof=reject(db,change_leg(9+38*8),'verify rejected'),
                authorization=reject(db,altered,'owner authorization'))


def measured_offer(db, raw, candidate):
    role = db.swap_verifier()
    # Prime both registries identically for this pair's complete offer.
    # check_funding is read-only here; the next call exercises actual durable pool admission.
    list(db.group_effects(reg.split(raw),db._head()))
    before, _, _ = role_sample(role)
    started, cpu = time.perf_counter(), time.process_time()
    res = db.offer(raw)
    parent = time.process_time()-cpu
    elapsed = time.perf_counter()-started
    after, hwm, _ = role_sample(role)
    check(not res['duplicate'] and db.status()['mempool'] == 2, 'missing atomic pool publication')
    native = after-before
    costs = dict(bundle_B=len(raw),wall_s=elapsed,parent_cpu_s=parent,
                 signature_and_SLG1_service_cpu_s=native,service_lifetime_peak_KiB=hwm,
                 parent_lifetime_peak_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    engine_cpu = 0
    if candidate:
        costs['registered'] = db.ft_metrics
        engine = db.ft_metrics['engine']['candidate']
        engine_cpu = engine['user_s']+engine['system_s']
    costs['instrumented_CPU_s'] = parent + native + engine_cpu
    return costs


def mined(db, pk, packets=None):
    raw = chain.mine(db.template(pk, packets))
    check(db.accept(raw)['selected'], 'self-mined block was not selected')
    return raw


def campaign():
    events = Path('/events')
    # SOURCE is a comparison oracle, never an input to the verifier's branch selection.
    source = json.loads((events/'SOURCE.json').read_text())
    raws = sorted((p.read_bytes() for p in (events/'blocks').glob('*.bin')), key=lambda raw:chain.decode_block(raw).height)
    check(len(raws) >= 2 and len(raws) == source['common']['height'], 'funding prefix shape')
    mixed, released = [(events/f'{name}.swap').read_bytes() for name in ('mixed','released')]
    pk = chain.decode_block(raws[-1]).pk
    other_pk = next(chain.decode_block(r).pk for r in raws if chain.decode_block(r).pk != pk)
    result = {}
    with ExitStack() as stack:
        actors = Resources(config(Path('/deploy/runtime')))
        stack.callback(actors.close)
        def node(name):
            ledger = chain.Chain('/tmp/'+name+'.sqlite', actors.backend)
            stack.callback(ledger.close)
            return ledger
        fork, left, right = [node(k) for k in ('fork','left','right')]
        for i, raw in enumerate(raws):
            for db in (left,right,fork) if i+1<len(raws) else (left,right):
                check(db.accept(raw)['selected'], 'invalid public funding branch')
        base = left.status()
        check(base == right.status() and base['network'] == source['network'] and
              all(base[k] == v for k,v in source['common'].items()), 'public oracle disagrees with mined funding')
        unrelated = mined(left,pk,())
        check(right.accept(unrelated)['selected'], 'unrelated block')
        result['controls'] = proof_controls(left, mixed)
        result['orders'] = {}
        for db, first, other, label in ((left,mixed,released,'mixed_first'),(right,released,mixed,'released_first')):
            costs = measured_offer(db,first,label=='mixed_first')
            check(db.offer(first)['duplicate'], 'idempotent offer')
            pool_conflict = reject(db,other,'pool conflict')
            before = db.status()
            raw = mined(db,pk)
            after = db.status()
            check(after['spent'] == before['spent']+4 and after['fees'] == before['fees']+3
                  and after['notes'] == before['notes']+5 and not db.pending(), 'incorrect admitted effects')
            check(chain.decode_block(raw).packets == reg.split(first) and chain.decode_block(raw).amount == chain.SUBSIDY+3,
                  'block contents or reward')
            ids = [sha256(f).digest() for f in reg.split(first)]
            observation = db.supply_observation(ids)
            check(all(e and e['op']=='swap' and e['quantity']==0 for e in observation['events']),
                  'wrong archived swap supply effects')
            spent = reject(db,other,'spent nullifier')
            result['orders'][label] = dict(meter=costs,pool_rejection=pool_conflict,chain_rejection=spent,
                 tip=after['tip'],height=after['height'],spent=after['spent'],spent_set_sha256=after['spent_set_sha256'],
                 fees=after['fees'],notes=after['notes'],block_B=len(raw))
        check(left.status()['spent_set_sha256'] == right.status()['spent_set_sha256'], 'registered nullifiers differ')
        # Validate competing PoW from the parent of the original funding anchor.
        while fork.status()['height'] < right.status()['height']+1:
            rival = mined(fork,other_pk,())
            left.accept(rival)
        check(left.status()['tip'] == fork.status()['tip'] and left.status()['work'] > right.status()['work'],
              'failed heavier-branch selection')
        check(left.status()['spent_set_sha256'] == fork.status()['spent_set_sha256'] and
              left.status()['fees'] == fork.status()['fees'] and not left.pending(), 'failed reorg rollback')
        result['orphan'] = dict(height=left.status()['height'],tip=left.status()['tip'],
                 reason=reject(left,mixed,'anchor branch'),released_reason=reject(left,released,'anchor branch'),
                 fees=left.status()['fees'],spent=left.status()['spent'])
        # A disposable copy contains the orphan as well as the winning branch.
        # Remove only its derived public index, then reconstruct it through normal startup.
        def records(conn):
            return {bid:sha256(blob).hexdigest() for bid,blob in
                    conn.execute('SELECT bid,record FROM wallet_history_v2')}
        expected = records(left.db)
        copy = sqlite3.connect('/tmp/backfill.sqlite')
        try:
            left.db.backup(copy)
            copy.execute('DROP TABLE wallet_history_v2')
            copy.commit()
        finally:
            copy.close()
        recovered = node('backfill')
        check(records(recovered.db) == expected and recovered.status()==left.status(),
              'archived branch-specific projection differs')
        result['archived_records_rebuilt'] = len(expected)
        registration = result['orders']['mixed_first']['meter']['registered']
        check(registration['aux_root']==source['aux_root'] and registration['leaf_count']==base['notes'] and
              registration['endpoint']==base['tip'], 'independent branch derivation differed')
        result['funding'] = dict(blocks=len(raws),tip=base['tip'],anchored_leaves=base['notes'],
                                 at_offer_height=base['height']+1,at_offer_leaves=base['notes']+1)
        result['public_inputs_sha256'] = {k:sha256(v).hexdigest() for k,v in [('mixed',mixed),('released',released)]}
    return result


if __name__=='__main__':
    print(json.dumps(campaign(),sort_keys=True,indent=2))
