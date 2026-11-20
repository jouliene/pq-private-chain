"""Feed an allowlisted public capture to the existing SWP1 node from an empty genesis."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile

REGISTERED={'keys/managed.vk':'1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d',
            'swap-keys/swap.vk':'0527447637fa2f34d9585606501c4a55883c0ceaf58adb2d3e9834c66ab19837'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def replay(deployment,public):
    dep=deployment.resolve(strict=True)
    for name,digest in REGISTERED.items():
        need(sha256((dep/name).read_bytes()).hexdigest()==digest,'wrong historical verifier key')
    sys.path.insert(0,str(dep/'devnet'))
    import chain
    import runtime
    from run import Resources
    from swap_wire import split
    doc=json.loads((public/'RUN.json').read_bytes())
    need(doc['network']==chain.NETWORK.hex() and doc['genesis']==chain.GENESIS.hex(),'network identity')
    signed=(public/'SWAP.bin').read_bytes()
    sid=sha256(signed).hexdigest()
    fs=split(signed)
    need(sid==doc['settlement']['bundle_id'] and [sha256(f).hexdigest() for f in fs]==doc['settlement']['frame_ids'],'swap identity')
    ordinary=doc['ordinary']
    need(set(ordinary)=={'managed','fund-taker','fund-maker','fund-other','restored-payment'},'ordinary transfers')
    raw_blocks=[]
    for path in (public/'blocks').glob('*.bin'):
        data=path.read_bytes()
        ident=chain.block_id(data).hex()
        need(ident+'.bin'==path.name,'block identity')
        raw_blocks.append((chain.decode_block(data).height,ident,data))
    transactions={}
    states=doc['branch']
    wanted={st['tip']:st for st in states.values()}
    reached=set()
    fees=[]
    with ExitStack() as stack:
        temp=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        resources=Resources(runtime.config(dep/'runtime'))
        stack.callback(resources.close)
        ledger=chain.Chain(temp/'chain.sqlite',resources.backend)
        stack.callback(ledger.close)
        need(ledger.status()['tip']==chain.GENESIS.hex(),'expected empty genesis')
        for idx,(height,ident,raw) in enumerate(sorted(raw_blocks),1):
            b=chain.decode_block(raw)
            need(height==idx and b.parent.hex()==ledger.status()['tip'],'incomplete public history')
            ledger.accept(raw)
            state=ledger.status()
            need(state['tip']==ident,'node failed to select accepted block')
            if ident in wanted:
                need(all(state[k]==v for k,v in wanted[ident].items()),'reported branch state mismatch')
                reached.add(ident)
            ids=[sha256(p).hexdigest() for p in b.packets]
            for tx,packet in zip(ids,b.packets,strict=True):
                need(tx not in transactions and packet==(public/'packets'/(tx+'.bin')).read_bytes(),'packet capture mismatch')
                transactions[tx]=ident
            if states['funded']['height']<height<=states['abandoned']['height']:
                need(not ids,'abandoned negotiation wrote a payment frame')
            if ident==doc['settlement']['block']:
                need(tuple(b.packets)==tuple(fs) and b.amount==103,'incorrect atomic swap block')
                fees.append(3)
            if ordinary['restored-payment']['tx'] in ids:
                need(ids==[ordinary['restored-payment']['tx']] and b.amount==103,'incorrect onward payment block')
                fees.append(3)
        need(reached==set(wanted) and sorted(fees)==[3,3],'missing expected checkpoints')
        need(set(transactions)=={v['tx'] for v in ordinary.values()}|set(doc['settlement']['frame_ids']),'unexpected payment')
        need(set(transactions)=={p.stem for p in (public/'packets').glob('*.bin')},'unexpected packet in archive')
        need(state['fees']==18 and state['issued']==100*state['height'],'supply and fee accounting')
    return dict(blocks=len(raw_blocks),tip=state['tip'],issued=state['issued'],fees=state['fees'],
                user_fees=fees,logical_payments=6,abandoned_payment_frames=0,previous_registered_keys=REGISTERED)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('deployment',type=Path)
    parser.add_argument('public',type=Path)
    args=parser.parse_args()
    print(json.dumps(replay(args.deployment,args.public),indent=2))
