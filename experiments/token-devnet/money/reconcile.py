"""Reconcile monetary state and undo/reapply across captured typed devnet branches using public bytes."""
import argparse
from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import struct

VK=bytes.fromhex('f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b')
ASSET=sha256(b'TKNPOW/asset/v1\0fixed-research-token').digest()
SUBSIDY, FEE, WORK, CAP = 100, 3, 1 << 22, 240


def require(ok,msg):
    if not ok:
        raise ValueError(msg)


def sha(data):
    return sha256(data).digest()


def founder(raw, approved):
    require(len(raw)==216 and raw[:72]==b'TKDEVGN1'+VK+ASSET and sha(raw).hex()==approved, 'approved genesis')
    ctx,pk=raw[72:104],raw[104:136]
    require(ctx==sha(b'TKNPOW/founding/v1\0'+VK+ASSET+pk) and struct.unpack_from('<QQ',raw,136)==(0,CAP),'founding amounts')
    rules=struct.pack('<BBBIQ',22,8,4,8,SUBSIDY)
    network=sha(b'TKNPOW/network/v1\0'+VK+ASSET+sha(raw)+rules)
    return network,sha(b'TKNPOW/genesis/v1\0'+network),raw[152:184]


@dataclass(frozen=True)
class Block:
    id: bytes
    parent: bytes
    height: int
    miner_pk: bytes
    reward: int
    reward_cm: bytes
    tx: tuple
    nfs: tuple
    cms: tuple
    fees: int


def parse(raw,network):
    require(222<=len(raw)<=1048814 and raw[:41]==b'TKDEVBL1'+network+bytes([22]), 'block framing')
    identity=sha(b'PQDEV1/work\0'+sha(b'PQDEV1/template\0'+raw[:-8])+raw[-8:])
    require(int.from_bytes(identity,'big') < 1 << 234,'positive work')
    height=struct.unpack_from('<I',raw,73)[0]
    reward=struct.unpack_from('<Q',raw,109)[0]
    reward_cm=raw[117:149]; count=raw[213]; pos=214; nfs=[]; cms=[]; tx=[]; fees=0
    require(count<=4,'block slots')
    for _ in range(count):
        size=struct.unpack_from('<I',raw,pos)[0]; pos+=4
        require(0<size<=262144 and pos+size<=len(raw)-8,'transaction framing')
        packet=raw[pos:pos+size]; pos+=size
        require(packet[:5]==b'TKN1\1' and len(packet)>=9,'registered payment framing')
        plen=struct.unpack_from('<I',packet,5)[0]
        require(plen>=216 and 9+plen+3584==size,'complete proof and receipts')
        end=9+plen
        require(packet[end-216:end-208]==struct.pack('<Q',26),'public statement length')
        pi=packet[end-208:end]
        fee=struct.unpack_from('<Q',pi,168)[0]
        require(fee==FEE,'native fee')
        tx.append(sha(packet));fees+=fee
        nfs.extend([pi[40:72],pi[72:104]]);cms.extend([pi[104:136],pi[136:168]])
    require(pos+8==len(raw) and reward==SUBSIDY+fees,'exact reward and complete payload')
    return Block(identity,raw[41:73],height,raw[77:109],reward,reward_cm,tuple(tx),tuple(nfs),tuple(cms),fees)


@dataclass
class Account:
    genesis: bytes
    founder: bytes
    path: list = field(default_factory=list)
    notes: set = field(default_factory=set)
    spent: set = field(default_factory=set)
    payments: set = field(default_factory=set)
    fees: int = 0
    rewards: int = 0

    def __post_init__(self):
        self.notes.add(self.founder)

    @property
    def tip(self):
        return self.path[-1].id if self.path else self.genesis

    def apply(self,b):
        require(b.parent==self.tip and b.height==len(self.path)+1,'branch linkage')
        for known,values in [(self.spent,b.nfs),(self.notes,b.cms+(b.reward_cm,)),(self.payments,b.tx)]:
            require(not known.intersection(values) and len(set(values))==len(values),'duplicate branch effect')
            known.update(values)
        self.fees+=b.fees;self.rewards+=b.reward;self.path.append(b)

    def undo(self):
        b=self.path.pop()
        for known,values in [(self.spent,b.nfs),(self.notes,b.cms+(b.reward_cm,)),(self.payments,b.tx)]:
            require(set(values).issubset(known),'rollback effect missing')
            known.difference_update(values)
        self.fees-=b.fees;self.rewards-=b.reward

    def summary(self):
        h=len(self.path); native=self.rewards-self.fees
        require(native==h*SUBSIDY and self.fees==len(self.payments)*FEE, 'per-asset supply induction')
        require(len(self.notes)==1+h+2*len(self.payments) and len(self.spent)==2*len(self.payments),'state cardinalities')
        return dict(tip=self.tip.hex(),height=h,work=h*WORK,fees=self.fees,issued=native,token_issued=CAP,
                    notes=len(self.notes),spent=len(self.spent),spent_set_sha256=sha(b''.join(sorted(self.spent))).hex(),
                    payments=len(self.payments),gross_native_miner_credits=self.rewards,
                    native_fees_recaptured_once=self.fees,net_native_after_transfer_debits=native,
                    funded_commitments_set_sha256=sha(b''.join(sorted(self.notes))).hex())


def ancestry(tip,blocks,genesis):
    path=[];seen=set()
    while tip!=genesis:
        require(tip not in seen and tip in blocks,'missing parent or cycle')
        seen.add(tip);b=blocks[tip];path.append(b);tip=b.parent
    return path[::-1]



# Direction is an explicit public disclosure by the disposable scenario participants.
PARTIES={'token-only': ('miner-a','mira-restored'), 'native-only': ('miner-b','mira-restored'),
         'combined': ('mira-restored','next-restored'), 'onward': ('next-restored','payee'),
         'branch-first': ('mira-restored','shop'), 'branch-retry': ('mira-restored','shop')}


def compare_capture(run,blocks,genesis,cm,founding_pk):
    observations=json.loads(run.read_bytes())
    miners={bytes.fromhex(pk):name for name,pk in observations['miner_keys'].items()}
    require(len(miners)==len(observations['miner_keys']) and miners[founding_pk]=='miner-a','approved founding owner')
    by_tx={}
    for name,(payer,payee) in PARTIES.items():
        row=observations['payments'][name]
        n,t,fee=row['amount'],row['token_amount'],row['fee']
        require(0<=n<1<<62 and 0<=t<1<<62 and fee==FEE,'disclosed payment values')
        require(row['input_total']==n+fee+row['change'] and row['token_input_total']==t+row['token_change'],
                'wallet disclosed lane equations')
        src=row['input_sources']
        require(len(src)==row['real_inputs'] and sum(v['native'] for v in src)==row['input_total']
                and sum(v['token'] for v in src)==row['token_input_total'],'consumed note category amounts')
        tx=bytes.fromhex(row['tx']);require(tx not in by_tx,'duplicated disclosure')
        by_tx[tx]=(name,payer,payee,n,t)
    results={}; wallets_by_tip={}; note_sets={}
    for label in ('common','loser','winner','final'):
        snapshot=observations['tips'][label]; tip=bytes.fromhex(snapshot['tip'])
        state=Account(genesis,cm)
        accounts={name:[0,0] for name in observations['wallets']}; accounts[miners[founding_pk]][1]=CAP
        gross={name:0 for name in miners.values()};selected=[]
        for b in ancestry(tip,blocks,genesis):
            who=miners[b.miner_pk];gross[who]+=b.reward
            for tx in b.tx:
                name,payer,payee,n,t=by_tx[tx]; selected.append(name)
                accounts[payer][0]-=n+FEE;accounts[payer][1]-=t
                require(min(accounts[payer])>=0,'overdrawn reconstructed actor')
                accounts[payee][0]+=n;accounts[payee][1]+=t
            accounts[who][0]+=b.reward
            state.apply(b)
        monetary=state.summary()
        note_sets[label]=set(state.notes)
        for key in ('tip','height','work','fees','issued','token_issued','notes','spent','spent_set_sha256'):
            require(snapshot[key]==monetary[key],f'{label}: reported {key}')
        require(sum(v[0] for v in accounts.values())==state.summary()['issued'] and sum(v[1] for v in accounts.values())==CAP,
                'participant account reconciliation')
        results[label]=dict(branch_monetary=monetary,selected_disclosed_intents=selected,miners_gross_native_credit=gross)
        wallets_by_tip[label]={n:dict(native=v[0],token=v[1]) for n,v in accounts.items()}
    require(wallets_by_tip['final']==observations['wallets'],'selected wallet inventory readback')
    require(wallets_by_tip['loser']['fork-miner']==observations['losing_miner_before'] and
            wallets_by_tip['winner']['fork-miner']==observations['losing_miner_after'],'orphan miner inventory readback')
    retry_names=set(['branch-first','branch-retry'])
    expected={'common':set(),'loser':{'branch-first'},'winner':set(),'final':{'branch-retry'}}
    for label,data in results.items():
        require(set(data['selected_disclosed_intents']).intersection(retry_names)==expected[label],'fork invoice selection')
    loser_path=ancestry(bytes.fromhex(observations['tips']['loser']['tip']),blocks,genesis)
    orphan_rewards=[b.reward_cm for b in loser_path if miners[b.miner_pk]=='fork-miner']
    require(bool(orphan_rewards) and all(c in note_sets['loser'] and c not in note_sets['winner'] and c not in note_sets['final']
            for c in orphan_rewards),'orphan miner credit persists on selected path')
    return {'orphan_miner_public_reward_cms_removed':[c.hex() for c in orphan_rewards], 'public_snapshot_agreement':results,'final_disclosed_wallet_inventories_match':wallets_by_tip['final'],
            'orphan_miner_before_after_match':[observations['losing_miner_before'],observations['losing_miner_after']],
            'all_four_tip_public_status_and_disclosed_lanes_match':True}

def reconcile(public,approved):
    raw_genesis=(public/'genesis.bin').read_bytes()
    network,g,cm=founder(raw_genesis,approved)
    directory=public/'blocks'
    blocks={}
    for file in sorted(directory.glob('*.bin')):
        b=parse(file.read_bytes(),network)
        require(b.id not in blocks,'duplicate archival block')
        blocks[b.id]=b
    require(bool(blocks),'empty archive')
    leaves=set(blocks)-{b.parent for b in blocks.values()}
    trees={tip:ancestry(tip,blocks,g) for tip in leaves}
    winner=min(trees,key=lambda tip:(-len(trees[tip]),tip))
    dest=trees[winner]
    fresh=Account(g,cm)
    for b in dest:fresh.apply(b)
    final=fresh.summary(); branches={}; switches=[]
    for tip,source in sorted(trees.items()):
        state=Account(g,cm)
        for b in source:state.apply(b)
        before=state.summary();branches[tip.hex()]=before
        if tip==winner:continue
        fork=0
        while fork<min(len(source),len(dest)) and source[fork].id==dest[fork].id:fork+=1
        for _ in source[fork:]:state.undo()
        at_fork=state.summary()
        for b in dest[fork:]:state.apply(b)
        require(state.summary()==final,'incremental branch switch differs from fresh monetary replay')
        switches.append(dict(from_tip=tip.hex(),common_height=fork,detached_blocks=len(source)-fork,
                             attached_blocks=len(dest)-fork,
                             removed_fees=before['fees']-at_fork['fees'],added_fees=final['fees']-at_fork['fees'],
                             removed_reward_credits=before['gross_native_miner_credits']-at_fork['gross_native_miner_credits'],
                             added_reward_credits=final['gross_native_miner_credits']-at_fork['gross_native_miner_credits'],
                             detached_payment_ids=[x.hex() for b in source[fork:] for x in b.tx],
                             attached_payment_ids=[x.hex() for b in dest[fork:] for x in b.tx],
                             exact_winner_from_undo_apply=True))
    readback=compare_capture(public/'RUN.json',blocks,g,cm,raw_genesis[104:136])
    require(readback['public_snapshot_agreement']['final']['branch_monetary']==final,'winner vs observed final')
    return dict(network=network.hex(),approved_genesis_sha256=approved,captured_blocks=len(blocks),**readback,
                founding_native=0,founding_token=CAP,all_terminal_branches=branches,switches=switches,final=final)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('public',type=Path);p.add_argument('--approve-genesis',required=True)
    args=p.parse_args()
    print(json.dumps(reconcile(args.public,args.approve_genesis),indent=2,sort_keys=True))
