"""Funded, single-seed owner. The coordinator sees public offers and signatures only."""
from contextlib import closing, ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import secrets
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
EX = HERE.parents[1]
sys.path[:0] = [str(HERE), str(EX/'funded-whir/wallet'), '/deploy/devnet']
from fixtures import Inventory, actor, commitment, compact, inputs, need, private_capture, selected_blocks, swap_policy, tail_statement
import chain, history, runtime
from run import Resources
from wallet_sync import role_sample
sw = swap_policy()
import ftl_wire as wire
from funded_projection import pivot, receipt_hash

NAMES = ('alice', 'bob')
OUTPUT = Path('/own')
EXCHANGE = Path('/exchange')
ENGINE, SHAPE = Path('/engine'), Path('/shape')
ZERO = bytes(32)


def phase(name):
    # Only public timing labels/timestamps cross the owner boundary.
    with (OUTPUT/'phases').open('a') as out:
        out.write(f'{name} {time.monotonic_ns()}\n')


def timed_call(role, fn):
    before = role_sample(role)
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter()-start
    after = role_sample(role)
    return result, dict(wall_s=round(elapsed, 6), cpu_s=round(after[0]-before[0], 4), max_rss_KiB=after[1])


def candidate_proof(w, rows, leaves, root, params, receipts, tip):
    phase('candidate_frontend')
    start = time.perf_counter()
    need(tuple(w['public'][22:26]) == receipt_hash(params, receipts), 'released receipt projection')
    w['public'].extend(struct.unpack('<4Q', root))
    for i, note in enumerate(w['inputs']):
        if note['dummy']:
            need(i >= len(rows), 'unexpected dummy input')
            continue
        pos = rows[i]['pos']
        derived, siblings, positions = pivot.tree(params, leaves, pos)
        need(derived == root and len(positions) == w['depth'], 'wrong auxiliary path')
        note.update(siblings=siblings, positions=positions)
    circuit = pivot.compile_full('SLG1', params, w)
    need(not circuit.failures and len(circuit.z) == 1 + 38 + 16818 and list(circuit.z[:39]) == [1, *w['public']],
         'funded private assignment/statement mismatch')
    payload = (wire.proof_context(chain.NETWORK, tip, len(leaves), receipts) + wire.WORDS.pack(*w['public'])
               + pivot.f.words_as_bytes(circuit.z[39:]))
    frontend = time.perf_counter()-start
    phase('candidate_prove')
    proof, metric = wire.engine_call(ENGINE, SHAPE, 'prove', payload)
    result = wire.encode_leg(w['public'], proof, receipts)
    phase('candidate_done')
    return result, dict(frontend_wall_s=round(frontend, 6), prove=metric, proof_B=len(proof))


def prove_released(side, seed, address, nonce, fee, header, asset, roster, rows, verifier):
    capture = Path('/capture/native')
    fifo = Path('/tmp/capture')
    os.mkfifo(fifo, 0o600)
    fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        started = time.perf_counter()
        with actor(capture, Path('/deploy/swap-keys'), seed, fifo) as (wallet, restored):
            need(restored == address, 'capture wallet address')
            public = wallet.call(b'E'+nonce)
            native, quantity = (0,20) if side == 0 else (8,0)
            req = (b'P'+nonce+bytes([fee])+header+struct.pack('<QQ', native, quantity)+(asset if quantity else ZERO)
                   +roster[NAMES[1-side]]+compact(rows))
            raw, prove_metric = timed_call(wallet, lambda: wallet.call(req))
            w = private_capture(os.read(fd, 8192), 'SLG1')
        cold_wall = time.perf_counter() - started
    finally:
        os.close(fd)
    effect, verify_metric = timed_call(verifier, lambda: sw.verify(verifier, raw))
    orig = tail_statement(raw, 'SLG1')
    need(struct.pack('<34Q', *w['public']) == orig and public == effect.public and public != ZERO
         and tuple(r['nf'] for r in rows) == effect.nfs[:len(rows)], 'released proof differs from sources or signing key')
    return raw, w, effect, dict(prove=prove_metric, prove_with_actor_init_close_wall_s=round(cold_wall,6),
                                verify=verify_metric, proof_B=len(raw)-9-wire.sw.CT_PAIR)


def check_receipt_refusals(holder, own_effect, incoming, native, currency, quantity):
    # Both data/identity failures exercise the same pre-authorization policy used to release signatures.
    tests = ((incoming, native+1, currency, quantity), (own_effect, native, currency, quantity),
             (incoming, native, b'\x01'*32, quantity if quantity else 1))
    for effect, n, asset, q in tests:
        try:
            sw.opened(holder, effect, 0, n, asset, q)
        except ValueError:
            continue
        raise ValueError('wrong agreement or recipient key passed the wallet')


def main(side):
    owner = NAMES[side]
    seed = Path('/owner/seed')
    roster = {name:(Path('/peers')/name).read_bytes() for name in NAMES}
    meta = json.loads((EXCHANGE/'SOURCE.json').read_text())
    head = meta['common']
    asset = bytes.fromhex(meta['disposable_fixture_agreement']['token_asset'])
    tip = bytes.fromhex(head['tip'])
    expiry = head['height']+4
    terms = commitment(chain.NETWORK, asset, expiry, bytes.fromhex(sys.stdin.readline().strip()), roster)
    need(asset == Path('/peers/managed_asset').read_bytes() and tip == Path('/peers/funded_tip').read_bytes(),
         'offer diverges from the independently provisioned asset or funded branch')
    need(meta['network'] == chain.NETWORK.hex() and meta['terms'] == terms.hex() and meta['payer'] == 1
         and meta['expiry'] == expiry and len(set(roster.values())) == 2, 'private agreement or role mismatch')
    cfg = runtime.config(Path('/deploy/runtime'))
    official = Path('/deploy/swap-runtime/native')
    need(sha256(official.read_bytes()).hexdigest() == Path('/deploy/devnet/approved-swap-native.sha256').read_text().strip(),
         'swap signer installation differs')
    params = pivot.f.constants(Path('/constants.rs'))
    with ExitStack() as resources:
        roles = resources.enter_context(closing(Resources(cfg)))
        verifier = resources.enter_context(sw.actor('verify'))
        ledger = resources.enter_context(closing(chain.Chain(Path('/tmp/ledger.sqlite'), roles.backend)))
        holder, address = resources.enter_context(actor(cfg.binary, cfg.keys, seed))
        need(roster[owner] == address, 'private wallet address differs')
        inventory = Inventory(roles.h, {owner:holder})
        leaves = []
        for page in selected_blocks(ledger, Path('/origin'), head):
            for block in history.decode_range(page):
                inventory.apply(block)
                leaves.extend(cm for slot in block['slots'] for cm in slot['cms'])
                leaves.append(block['reward'][-32:])
        header = block['header']
        anchor = roles.h.call(b'H'+header)
        need(block['id'] == tip and header.hex() == head['header'] and anchor.hex() == head['anchor']
             and len(leaves) == inventory.tree.n == head['notes'], 'different eligible funding block')
        root = pivot.tree(params, leaves, 0)[0]
        rows = inputs(inventory.live[owner], owner, asset)
        fee = 3*side
        given_native, given_token = (0,20) if side==0 else (8,0)
        nc = sum(r['value'] for r in rows) - given_native - fee
        tc = sum(r['token'] for r in rows) - given_token
        change_asset = asset if tc else ZERO
        nonce = secrets.token_bytes(32)
        raw, w, own_effect, released_metric = prove_released(side,seed,address,nonce,fee,header,asset,roster,rows,verifier)
        need(own_effect.anchor == anchor and own_effect.height == head['height'] and own_effect.fee == fee,
             'released proof header or fee differs')
        sw.opened(holder, own_effect, 1, nc, change_asset, tc)
        (OUTPUT/'released.leg').write_bytes(raw)
        metrics = dict(released=released_metric, leaf_count=len(leaves), aux_root=root.hex())
        if side == 0:
            proposed, metrics['candidate'] = candidate_proof(w,rows,leaves,root,params,raw[-wire.sw.CT_PAIR:],tip)
            (OUTPUT/'candidate.leg').write_bytes(proposed)
        del w
        phase('waiting')
        print('prepared', flush=True)
        need(sys.stdin.readline().strip() == 'authorize', 'missing owner authorization request')
        phase('authorization')
        released = [(EXCHANGE/('leg-'+label+'.released')).read_bytes() for label in ('a','b')]
        candidate = (EXCHANGE/'leg-a.candidate').read_bytes()
        need(released[side] == raw and (side == 1 or candidate == proposed), 'owner offer was substituted')
        effects = [sw.verify(verifier, leg) for leg in released]
        words, metrics['candidate_verify'] = wire.verify_candidate(ENGINE,SHAPE,candidate,chain.NETWORK,tip,len(leaves),root,params)
        need(struct.pack('<34Q', *words[:34]) == tail_statement(released[0],'SLG1') and
             candidate[-wire.sw.CT_PAIR:] == b''.join(effects[0].cts), 'candidate differs from verified released effects')
        need(all(e.anchor == anchor and e.height == head['height'] and e.fee == 3*i for i,e in enumerate(effects)) and
             expiry >= head['height']+1 and effects[0].public != effects[1].public and
             len({nf for e in effects for nf in e.nfs}) == len({cm for e in effects for cm in e.cms}) == 4 and
             all(ledger.db.execute('SELECT 1 FROM spent WHERE nf=?',(nf,)).fetchone() is None for e in effects for nf in e.nfs),
             'ineligible, conflicting or duplicated swap effects')
        incoming_native, incoming_asset, incoming_token = (8,ZERO,0) if side == 0 else (0,asset,20)
        sw.opened(holder, effects[1-side], 0, incoming_native,incoming_asset,incoming_token)
        sw.opened(holder, effects[side], 1, nc, change_asset, tc)
        check_receipt_refusals(holder, effects[side], effects[1-side],incoming_native,incoming_asset,incoming_token)
        mixed = (candidate, released[1])
        need(all(len(leg) + wire.sw.SIG + wire.sw.HEADER <= wire.sw.LIMIT for leg in (*released,candidate)), 'frame exceeds limit')
        with actor(official, Path('/deploy/swap-keys'), seed) as (signer, restored):
            need(restored == address and signer.call(b'E'+nonce) == effects[side].public,'signer not bound to funded leg')
            for label,legs in [('released', released), ('mixed',mixed)]:
                digest = wire.sw.digest(chain.NETWORK,terms,expiry,1,legs)
                signature, metrics[label+'_sign'] = timed_call(signer,lambda: signer.call(b'S'+nonce+digest))
                need(verifier.call(b'V'+effects[side].public+digest+signature) == b'1','owner signature rejected')
                (OUTPUT/(label+'.signature')).write_bytes(signature)
        metrics.update(one_seed=True,checked_receipt_under_own_spend_key=True,wrong_receipt_amount_asset_key_rejected=True)
        (OUTPUT/'metrics.json').write_text(json.dumps(metrics))
        phase('teardown')
        print('signed', flush=True)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    main(('alice','bob').index(sys.argv[1]))
