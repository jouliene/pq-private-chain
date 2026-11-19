"""Exercise the live fixed-token network using ordinary CLI wallet processes."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HOME = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(HOME / 'deployment/devnet'))
from chain import GENESIS, block_id, decode_block
from cli import Lab, wait
from transport import control

LAB = Lab(HOME, HOME / 'deployment/runtime')
PUBLIC = HOME / 'public'
KEYS = ('network', 'genesis', 'tip', 'height', 'work', 'anchor', 'header', 'notes', 'spent',
        'spent_set_sha256', 'issued', 'token_issued', 'fees')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def command(*args):
    result = subprocess.run([ROOT / 'pqd', 'token', '--home', HOME, *map(str, args)],
                            capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise RuntimeError('wallet command ' + str(args[0]) + ' failed: ' + result.stderr[-1500:])
    return json.loads(result.stdout)


def money(info):
    return dict(native=info['balance'], token=info['token_balance'])


def status(node):
    return {k: v for k, v in LAB.status(node).items() if k in KEYS}


def converge(nodes):
    states = wait(lambda: [status(n) for n in nodes], lambda s: all(x == s[0] for x in s),
                  'autonomous convergence on ' + nodes)
    return states[0]


def hold():
    for n in 'ab':
        LAB.mining(n, 0)


def evidence_file(path, raw):
    if path.exists():
        require(path.read_bytes() == raw, 'public evidence identity collision')
    else:
        path.write_bytes(raw)


def retain_branch(node, tip):
    bid = bytes.fromhex(tip)
    while bid != GENESIS:
        target = PUBLIC / 'blocks' / (bid.hex() + '.bin')
        if target.exists():
            return
        raw = LAB.request(node, 'block', id=bid.hex())[1]
        require(block_id(raw) == bid, 'public block identity')
        block = decode_block(raw)
        evidence_file(target, raw)
        for packet in block.packets:
            retain_packet(packet)
        bid = block.parent


def retain_packet(packet):
    tx = hashlib.sha256(packet).hexdigest()
    evidence_file(PUBLIC / 'packets' / (tx + '.bin'), packet)
    return tx


def dest(name):
    return '@' + str(HOME / (name + '.addr'))


def stable_selection(nodes, start, limit):
    # Fixture observation through public RPC only. Exclude the last two selected blocks at each miner.
    suffixes = []
    for node in nodes:
        depth = max(0, min(limit, status(node)['height'] - 2 - start + 1))
        suffixes.append(LAB.request(node, 'selected', start=start, limit=depth)[0] if depth else [])
    return [col[0] for col in zip(*suffixes) if all(b == col[0] for b in col)]


def settled(owner, intent, node, result):
    cache = {}
    def contains(txid, bid):
        if bid not in cache:
            raw = LAB.request(node,'block',id=bid)[1]
            require(block_id(raw).hex() == bid, 'observed selected block identity')
            cache[bid] = {hashlib.sha256(p).hexdigest() for p in decode_block(raw).packets}
        return txid in cache[bid]
    # The wallet acknowledgement may arrive just before a transient competing tip.
    for attempt in range(3):
        start = result['anchor_height'] + 1
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if any(contains(result['tx'], b) for b in stable_selection('abc',start,8)):
                return result
            if status(node)['height'] >= start+10:
                break
            time.sleep(.3)
        if attempt < 2:
            result = command('resume',owner,intent,'--node',node,'--wait',180)
    raise ValueError('no shared selected payment with two successors for '+intent)


def mature_funding():
    pks = {LAB.address(n)[1:33] for n in ('miner-a','miner-b')}
    def funded():
        seen = set()
        limit = min(status(n)['height'] for n in 'abc')
        for start in range(1,limit+1,128):
            for bid in stable_selection('abc',start,128):
                raw = LAB.request('c','block',id=bid)[1]
                require(block_id(raw).hex() == bid, 'funding block identity')
                seen.add(decode_block(raw).pk)
                if pks <= seen:
                    return True
        return False
    wait(funded, bool, 'mined rewards with two common selected successors')


def send(owner, name, native, token, intent, node='c'):
    result = command('send', owner, dest(name), native, token, '--intent', intent, '--node', node, '--wait', 180)
    require(result['status'] == 'confirmed', intent + ' confirmation')
    if node == 'c':
        result = settled(owner,intent,node,result)
    return disclosure(owner, result)


def disclosure(owner, result):
    info = {k: result[k] for k in ('tx', 'amount', 'token_amount', 'fee', 'change', 'token_change',
                                     'real_inputs', 'input_total', 'token_input_total', 'packet_B',
                                     'proving_wall_s', 'anchor_height')}
    # Participants disclose amounts and origin categories only. Never export private state or input IDs.
    directory = LAB.walletdir(owner)
    with sqlite3.connect((directory/'typed-intents.sqlite').as_uri()+'?mode=ro', uri=True) as out:
        pins = json.loads(out.execute('SELECT pinned FROM intents WHERE id=?', (result['intent'],)).fetchone()[0])
    with sqlite3.connect((directory/'typed-wallet-state.sqlite').as_uri()+'?mode=ro', uri=True) as db:
        info['input_sources'] = [dict(zip(('kind','native','token'), db.execute(
            'SELECT kind,amount,token FROM owned WHERE cm=?', (bytes.fromhex(cm),)).fetchone())) for cm in pins]
    return info


def retry_link(first, second):
    def effect(tx):
        raw = (PUBLIC/'packets'/(tx+'.bin')).read_bytes()
        end = 9 + int.from_bytes(raw[5:9], 'little')
        require(raw[:5] == b'TKN1\x01' and len(raw)-end == 3584, 'TKN1 retry packet framing')
        pi = raw[end-208:end]
        return pi[:32], {pi[40:72], pi[72:104]}, {pi[104:136], pi[136:168]}, pi[176:208], raw[end:]
    a,b = effect(first),effect(second)
    facts = dict(first=first, second=second, shared_nullifiers=len(a[1] & b[1]),
                 shared_commitments=len(a[2] & b[2]), same_anchor=a[0] == b[0],
                 same_receipt_digest=a[3] == b[3], same_ciphertexts=a[4] == b[4])
    require(first != second and facts['shared_nullifiers'] == 1 and not facts['same_anchor'], 'real retry linkage')
    return facts


def exercise():
    require(not (HOME/'nodes').exists() and not PUBLIC.exists(), 'walkthrough requires a fresh home')
    for sub in ('blocks','packets'):
        (PUBLIC/sub).mkdir(parents=True)
    genesis = HOME/'deployment/devnet/genesis.bin'
    shutil.copyfile(genesis, PUBLIC/'genesis.bin')
    run = dict(genesis_sha256=hashlib.sha256(genesis.read_bytes()).hexdigest(), payments={}, tips={}, miner_keys={})
    p, tips = run['payments'], run['tips']
    LAB.start()
    names = ('mira','next','payee','shop','fork-miner','winning-miner')
    for name in names:
        command('create', name)
        command('export-address', name, HOME/(name+'.addr'))
    for name in ('miner-a','miner-b','fork-miner','winning-miner'):
        run['miner_keys'][name] = LAB.address(name)[1:33].hex()
    for name in ('mira','next'):
        seed = HOME/(name+'.seed')
        command('backup', name, seed)
        require(seed.stat().st_size == 32 and not (LAB.walletdir(name)/'typed-wallet-state.sqlite').exists(), 'offline seed-only recipient setup')
    mature_funding()
    p['token-only'] = send('miner-a','mira',0,70,'token-only')
    mira = command('restore','mira-restored', HOME/'mira.seed', '--node','c')
    run['offline_restore'] = money(mira)
    require(money(mira) == dict(native=0,token=70) and mira['incoming_notes'] == 1, 'seed-only token receipt')
    p['native-only'] = send('miner-b','mira',23,0,'native-only')
    require(all(v['kind'] == 'reward' and v['token'] == 0 for v in p['native-only']['input_sources']), 'genuine native mining origin')
    require(money(command('balance','mira-restored')) == dict(native=23,token=70), 'two incoming lanes')
    p['combined'] = send('mira-restored','next',9,45,'combined')
    combined = p['combined']
    require(combined['real_inputs'] == 2 and sorted((v['native'],v['token']) for v in combined['input_sources']) == [(0,70),(23,0)]
            and (combined['change'],combined['token_change']) == (11,25), 'two real inputs and joint change')
    nxt = command('restore','next-restored', HOME/'next.seed', '--node','c')
    require(money(nxt) == dict(native=9,token=45), 'next recipient recovery')
    p['onward'] = send('next-restored','payee',4,13,'onward')
    require(money(command('balance','payee')) == dict(native=4,token=13), 'second-generation spend')
    run['continuous_mining'] = {n: {k: LAB.status(n)[k] for k in ('found','remaining')} for n in 'ab'}
    require(all(s['remaining'] == -1 and s['found'] > 0 for s in run['continuous_mining'].values()), 'both continuous CPU miners')
    hold()
    tips['common'] = converge('abc')
    for n, peers in [('a',[]),('b',['c']),('c',['b'])]:
        LAB.links(n,peers)
    LAB.mining('a',-1,'fork-miner')
    LAB.mining('b',-1,'winning-miner')
    wait(lambda: status('a'), lambda s:s['height'] > tips['common']['height'], 'losing branch anchor')
    p['branch-first'] = send('mira-restored','shop',3,7,'branch-invoice','a')
    LAB.mining('a',0)
    tips['loser'] = status('a')
    retain_branch('a',tips['loser']['tip'])
    run['losing_miner_before'] = money(command('balance','fork-miner','--node','a'))
    require(run['losing_miner_before']['native'] > 0, 'orphan miner was paid')
    wait(lambda:status('b'), lambda s:s['height'] >= max(tips['loser']['height']+2, tips['common']['height']+10), 'higher-work competitor')
    LAB.mining('b',0)
    tips['winner'] = converge('bc')
    require(tips['winner']['work'] > tips['loser']['work'] and tips['loser']['fees'] == tips['winner']['fees']+3, 'fork weight and fees')
    retain_branch('b',tips['winner']['tip'])
    require(not (HOME/'nodes/d/chain.sqlite').exists(), 'fresh peer database')
    run['fresh_genesis'] = {k:v for k,v in LAB.launch('d').items() if k in KEYS}
    require(run['fresh_genesis']['height'] == 0 and run['fresh_genesis']['issued'] == 0, 'new peer starts at genesis')
    LAB.links('d',['a'])
    require(converge('da') == tips['loser'], 'fresh node independently validates losing history')
    LAB.links('d',['b'])
    require(converge('db') == tips['winner'], 'fresh node adopts heavier valid history')
    for n in 'abcd':
        LAB.links(n,[other for other in 'abcd' if other != n])
    require(converge('abcd') == tips['winner'], 'four-node convergence on heavier fork')
    run['losing_miner_after'] = money(command('balance','fork-miner','--node','a'))
    require(run['losing_miner_after'] == dict(native=0,token=0), 'losing miner rollback')
    failed = subprocess.run([ROOT/'pqd','token','--home',HOME,'send','fork-miner',dest('shop'),'1','0',
                             '--node','a','--intent','orphan-reward-check'],capture_output=True,text=True,timeout=120)
    reason = 'insufficient funds within two unreserved inputs'
    require(failed.returncode != 0 and reason in failed.stderr and status('a') == tips['winner'],
            'orphan-only funding refused without monetary mutation')
    run['orphan_wallet_refusal'] = reason
    previous_pid = LAB.status('a')['pid']
    LAB.admin('a','stop')
    wait(lambda:control(HOME,'a').exists(), lambda present:not present, 'node shutdown')
    require(LAB.launch('a')['pid'] != previous_pid and status('a') == tips['winner'], 'persistent monetary state after restart')
    retry = command('resume','mira-restored','branch-invoice','--node','a')
    require(retry['status'] == 'submitted', 'reanchored submission')
    p['branch-retry'] = disclosure('mira-restored',retry)
    pending = LAB.request('a','tx',id=retry['tx'])[1]
    require(retain_packet(pending) == retry['tx'], 'public retry identity')
    reply = LAB.request('a','submit',pending)[0]
    require(reply['duplicate'] and reply['id'] == retry['tx'] and LAB.status('a')['mempool'] == 1, 'duplicate is idempotent')
    run['duplicate'] = reply
    run['retry_observer'] = retry_link(p['branch-first']['tx'],retry['tx'])
    for n in 'ab':
        LAB.mining(n,-1,'miner-'+n)
    confirmed = command('resume','mira-restored','branch-invoice','--node','a','--wait',180)
    confirmed = settled('mira-restored','branch-invoice','a',confirmed)
    require(confirmed['status'] == 'confirmed', 'retried intent mined')
    if confirmed['tx'] != retry['tx']:
        # Preserve the idempotent pending transmission and identify the eventual settled attempt separately.
        run['pre_confirmation_retry'] = p['branch-retry']
        p['branch-retry'] = disclosure('mira-restored',confirmed)
        additional = LAB.request('a','tx',id=confirmed['tx'])[1]
        require(retain_packet(additional) == confirmed['tx'], 'later retry identity')
        run['retry_observer'] = retry_link(p['branch-first']['tx'],confirmed['tx'])
    hold()
    tips['final'] = converge('abcd')
    retain_branch('d',tips['final']['tip'])
    participants = ('miner-a','miner-b','fork-miner','winning-miner','mira-restored','next-restored','payee','shop')
    run['wallets'] = {n:money(command('balance',n,'--node','d')) for n in participants}
    expect = {'mira-restored':(5,18), 'next-restored':(2,32), 'payee':(4,13), 'shop':(3,7)}
    for n,(native,token) in expect.items():
        require(run['wallets'][n] == dict(native=native,token=token), n+' final wallet')
    require(sum(v['native'] for v in run['wallets'].values()) == tips['final']['height']*100 and
            sum(v['token'] for v in run['wallets'].values()) == 240 and tips['final']['fees'] == 15, 'final monetary reconciliation')
    run['restarted_node'] = 'a'
    run['fresh_node_path'] = [run['fresh_genesis']['tip'], tips['loser']['tip'], tips['winner']['tip'],tips['final']['tip']]
    (PUBLIC/'RUN.json').write_text(json.dumps(run,indent=2,sort_keys=True)+'\n')
    return dict(result='passed', public=str(PUBLIC), network=tips['final']['network'], height=tips['final']['height'],
                canonical_payments=5, fees=tips['final']['fees'], issued=tips['final']['issued'], token_supply=240)


if __name__ == '__main__':
    # Avoid stopping an existing operator network if the user supplies a non-fresh home.
    if (HOME/'nodes').exists():
        sys.exit('walkthrough requires a fresh home')
    try:
        print(json.dumps(exercise(),indent=2))
    finally:
        if (HOME/'network.json').exists():
            LAB.stop()
