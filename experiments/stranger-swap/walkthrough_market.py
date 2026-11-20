"""Mine a funded stranger exchange using two maker services, two relay instances and ordinary wallets."""
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SWAP=HERE.parent/'atomic-swap'
from lab_hosts import CiphertextLink, Meter, Remote, Service, free_ports
from directory import NETWORK


def require(ok,why):
    if not ok:
        raise ValueError(why)


def cli(home,command,*args,remote=None,fail=False):
    argv=[command,'--home',home,*args]
    if remote:
        p=remote.run(remote.command(*argv))
    else:
        p=subprocess.run([ROOT/'pqd',*map(str,argv)],text=True,capture_output=True,timeout=240)
    if not fail and p.returncode:
        raise ValueError(f'{command} {args[0]} failed: '+(p.stderr or p.stdout)[-500:])
    if fail:
        require(p.returncode!=0,'unexpected wallet acceptance')
    return json.loads(p.stdout)


def checked_heads(lab):
    from cli import wait
    return wait(lambda:[lab.status(k) for k in 'abc'],lambda v:len({x['tip'] for x in v})==1,'validating peers agree')[0]


def provision(a,home):
    sys.path.insert(0,str(SWAP))
    from stage import build,install
    args=(a.managed_build,a.managed_sha,a.swap_build,a.swap_sha)
    if any(args) and not all(args):
        raise ValueError('provide both builds and both local SHA-256 approvals')
    install(home,*(args if all(args) else build(home)))


class Demo:
    def __init__(self,h,stack,remote):
        from cli import Lab
        self.h,self.stack,self.remote=h,stack,remote
        self.lab=Lab(h,h/'deployment/runtime')
        self.pub=h/'public'
        for sub in ('blocks','packets'):
            (self.pub/sub).mkdir(parents=True)
        self.out={'scenario':'stranger-token-for-native-v1','network':NETWORK,'ordinary':{},'wallets':{},
                  'checks':{},'meter':{'discovery':[],'negotiation':[]},'branch':{}}
        self.relay_a,self.relay_b,self.remote_maker_port,self.other_port=free_ports(4)
        self.relays=[f'127.0.0.1:{x}' for x in (self.relay_a,self.relay_b)]
        self.topology='two physical Linux hosts with loopback-only SSH forwards' if remote else 'one Linux host with separate homes and processes'
        self.out['topology']=self.topology
        self.homes={s:h/'participants'/s for s in ('taker','maker','other')}

    def start(self):
        self.lab.start(manual=True)
        self.stack.callback(self.lab.stop)
        self.gateway=Meter(self.lab.cfg['ports']['c'])
        self.stack.callback(self.gateway.server_close)
        threading.Thread(target=self.gateway.serve_forever,daemon=True).start()
        self.stack.callback(self.gateway.shutdown)
        port=self.gateway.server_address[1]
        boot={'version':1,'ports':{'c':port},'market_relays':self.relays}
        for role,place in self.homes.items():
            if role=='maker' and self.remote:
                continue
            place.mkdir(parents=True,mode=0o700)
            (place/'network.json').write_text(json.dumps(boot))
            shutil.copytree(self.h/'deployment',place/'deployment')
        if self.remote:
            import market_transport
            self.remote.prepare(ROOT,self.h/'deployment',Path(market_transport._command('identity')[0]))
            self.homes['maker']=self.remote.base/'maker'
            self.remote.forward('-R',port,port)
            self.remote.forward('-R',self.relay_a,self.relay_a)
            self.remote.forward('-L',self.relay_b,self.relay_b)
            self.remote.forward('-L',self.remote_maker_port,self.remote_maker_port)
            self.remote.run(['python3','-c','import sys;from pathlib import Path;Path(sys.argv[1]).write_text(sys.argv[2])',
                             self.homes['maker']/'network.json',json.dumps(boot)])
        self.rel_a=self.service('relay-a',['market','relay','--listen',self.relays[0]],False)
        self.rel_b=self.service('relay-b',['market','relay','--listen',self.relays[1]],bool(self.remote))
        self.rel_a.ready()
        self.rel_b.ready()

    def service(self,name,args,away):
        log=self.h/(name+'.log')
        if away:
            return self.remote.service(args,name,log)
        proc=Service([ROOT/'pqd',*map(str,args)],log)
        self.stack.callback(proc.stop)
        return proc

    def participant(self,role,command,*args,fail=False):
        return cli(self.homes[role],command,*args,remote=self.remote if role=='maker' else None,fail=fail)

    def checkpoint(self,name):
        head=checked_heads(self.lab)
        self.out['branch'][name]={k:head[k] for k in ('tip','height','issued','fees','spent','notes','spent_set_sha256')}
        return head

    def wallet_balance(self,role,alias):
        v=self.participant(role,'swap','balance',alias)
        return {'native':v['balance'],'assets':v['assets']}

    def fund(self):
        lab=self.lab
        pubaddresses={}
        for role,name in (('taker','alice'),('maker','maker'),('other','other')):
            self.participant(role,'swap','create',name)
            path=self.homes[role]/'funding-address'
            self.participant(role,'swap','export-address',name,path)
            if role=='maker' and self.remote:
                # Only the faucet needs this public destination. The taker never receives it from the operator.
                import base64
                pubaddresses[role]=self.h/'funding-remote-address'
                pubaddresses[role].write_bytes(base64.b64decode(self.remote.run(['base64','-w0',path]).stdout,validate=True))
            else:
                pubaddresses[role]=path
        self.participant('taker','swap','backup','alice',self.homes['taker']/'offline-seed')
        lab.mine('a',3)
        checked_heads(lab)
        def pay(label,*args):
            row=cli(self.h,'swap',*args,'--intent',label,'--node','a','--wait',0)
            require(row['tx'] in lab.request('a','pending')[0],'missing funding submission')
            lab.mine('a',1)
            checked_heads(lab)
            self.out['ordinary'][label]={k:row[k] for k in ('tx','packet_B','fee')}
            return row
        asset=pay('managed','register','miner-a',100)['asset_id']
        pay('fund-taker','send','miner-a','@'+str(pubaddresses['taker']),0,asset,100)
        for role in ('maker','other'):
            pay('fund-'+role,'send','miner-a','@'+str(pubaddresses[role]),25,'native',0)
        funds=self.wallet_balance('taker','alice')
        require(funds=={'native':0,'assets':{asset:100}},'wrong initial taker holdings')
        self.asset,=funds['assets']
        self.out['asset']=self.asset
        self.out['wallets']['funded']=funds
        self.checkpoint('funded')

    def makers(self):
        self.cipher_links={}
        ads={}
        for role,price,port,blocks in [('maker',8,self.remote_maker_port,8),('other',7,self.other_port,2)]:
            link=CiphertextLink(port)
            self.cipher_links[role]=link
            threading.Thread(target=link.serve_forever,daemon=True).start()
            self.stack.callback(link.server_close)
            self.stack.callback(link.shutdown)
            proc=self.service(role,['market','--home',self.homes[role],'maker',role,'--asset',self.asset,
                            '--quantity','20','--native',str(price),'--quote-ttl','300','--blocks',str(blocks),
                            '--listen',f'127.0.0.1:{port}','--endpoint',f'127.0.0.1:{link.server_address[1]}'],role=='maker' and self.remote)
            started=proc.ready()
            require(all(s['ok'] for s in started['discovery']),'each maker must register independently with both relays')
            self.out['meter']['discovery'].append({'operation':'register','maker':role,'endpoints':started['discovery']})
            ads[role]=started['advert']
            if role=='other':
                self.other_service=proc
        require(len(set(ads.values()))==2,'distinct advertisements required')
        self.rel_a.stop()
        discovery=self.participant('taker','market','discover','alice')
        require(set(discovery['makers'])==set(ads.values()) and
                [m['ok'] for m in discovery['discovery']]==[False,True],'discovery did not survive one relay being unavailable')
        self.out['ads']=json.loads((self.homes['taker']/'wallets/alice/market-directory.json').read_bytes())
        self.out['meter']['discovery'].append({'operation':'discover','endpoints':discovery['discovery']})
        self.ads=ads

    def market(self,label,op,*args,fail=False):
        offset={k:len(v.rows) for k,v in self.cipher_links.items()}
        row=self.participant('taker','market',op,'alice',*args,fail=fail)
        views=[r for k,v in self.cipher_links.items() for r in v.rows[offset[k]:]]
        self.out['meter']['negotiation'].append({'operation':label,'calls':row['private_transport'],'forwarder':views})
        return row

    def quote(self,label,role):
        return self.market(label,'quote',self.ads[role],'--asset',self.asset,'--quantity',20)

    def settle(self,label,q,*extra,fail=False):
        return self.market(label,'settle',q['quote'],'--asset',self.asset,'--quantity',20,
                           '--native',q['native'],'--expiry',q['expiry_height'],*extra,fail=fail)

    def before_settlement(self):
        head=self.checkpoint('abandoned')
        require(head['fees']==self.out['branch']['funded']['fees'] and
                head['spent_set_sha256']==self.out['branch']['funded']['spent_set_sha256'],'abandoned session affected ledger')
        require(not any(x['op']=='submit' for x in self.gateway.rows),'abandoned session submitted data')
        pending={k:len(self.lab.request(k,'pending')[0]) for k in 'abc'}
        require(not any(pending.values()),'unexpected payment in a mempool')
        self.out['checks']['before_settle']={'wallet_rpc_rows':len(self.gateway.rows),'pending':pending}
        return head

    def negotiate(self):
        selected=self.cipher_links['maker']
        selected.target=self.other_port
        try:
            refused=self.market('substituted-endpoint','quote',self.ads['maker'],'--asset',self.asset,'--quantity',20,fail=True)
            m,=refused['private_transport']
            require(not m['authenticated'] and m['request_B']==0 and m['wire_reply_B']>0,'peer substitution released a private request')
        finally:
            selected.target=self.remote_maker_port
        self.out['checks']['wrong_live_peer_rejected_before_private_request']=True
        stale=self.quote('stale-firm','other')
        self.lab.mine('a',stale['expiry_height']-checked_heads(self.lab)['height'])
        checked_heads(self.lab)
        refused=self.settle('expired-approval',stale,fail=True)
        require('expir' in refused['error'],'stale quote refused for an unrelated reason')
        self.market('expired-cancel','cancel',stale['quote'],'--offline')
        quotes=[self.quote('firm-'+str(i),'maker' if ad==self.ads['maker'] else 'other')
                for i,ad in enumerate(sorted(self.out['ads']))]
        require(sorted(q['native'] for q in quotes)==[7,8] and all(q['fee']==3 for q in quotes),'competing quotes incorrect')
        chosen=max(quotes,key=lambda q:q['native'])
        alternative=min(quotes,key=lambda q:q['native'])
        self.out['quotes']=[{k:q[k] for k in ('native','quantity','fee','payer','expiry_height','advert')} for q in quotes]
        self.settle('prepare-disconnect',alternative,'--prepare-only')
        self.other_service.stop()
        refused=self.settle('maker-disconnect',alternative,fail=True)
        require(any(not m['authenticated'] for m in refused['private_transport']),'disconnect did not exercise a network attempt')
        state=self.market('after-disconnect','status',alternative['quote'])
        require(state['state']=='prepared','taker authorized after maker disconnect')
        self.market('cancel-unsigned','cancel',alternative['quote'],'--offline')
        self.before_settlement()
        self.out['checks'].update(stale_quote_rejected=True,disconnected_before_signature=True,
                                  abandoned_consensus_payment_bytes=0,abandoned_submit_requests=0)
        return chosen

    def finish(self,chosen):
        import sqlite3
        from chain import block_id,decode_block,GENESIS
        from cli import wait
        from swap_wire import split
        from swap_ledger import public_role,verify_pair
        import transport as node_rpc
        stop=threading.Event()
        errors=[]
        def independent_miner():
            # The timer requests nonce searches. Only winning validated PoW advances the chain.
            # The miner never sees quotes, desired inclusion height, or a target transaction ID.
            try:
                while not stop.wait(12):
                    self.lab.mine('a',1)
            except Exception as error:
                errors.append(error)
        miner=threading.Thread(target=independent_miner,daemon=True)
        miner.start()
        begin=time.monotonic()
        try:
            result=self.settle('selected-settlement',chosen)
            raw=Path(result['packet']).read_bytes()
            frames=split(raw)
            frame_ids=[sha256(f).hexdigest() for f in frames]
            def locate(ids):
                tip=self.lab.status('c')
                ident=tip['tip']
                while ident!=self.out['branch']['abandoned']['tip'] and ident!=GENESIS.hex():
                    data=self.lab.request('c','block',id=ident)[1]
                    b=decode_block(data)
                    if ids==[sha256(p).hexdigest() for p in b.packets]:
                        return b,ident,len(data)
                    ident=b.parent.hex()
                if errors:
                    raise errors[0]
                return None
            found=wait(lambda:locate(frame_ids),bool,'autonomous PoW swap inclusion',150)
            observed=time.time_ns()
            b,bid,size=found
            require(b.amount==103 and len(b.packets)==2,'incorrect swap fee or group')
            self.out['settlement']=dict(bundle_id=result['ack'],frame_ids=frame_ids,wire_B=len(raw),
                submit=result['submit'],height=b.height,block=bid,block_B=size,
                submit_to_observed_inclusion_s=(observed-result['submitted_ns'])/1e9,
                selection_to_observed_inclusion_s=time.monotonic()-begin,miner_period_s=12)
            with (self.pub/'SWAP.bin').open('xb') as f:
                f.write(raw)
            # An actual peer inventory/fetch of the public settlement group is measured separately.
            # After mining, nodes serve its physical frames by their confirmed identifiers.
            fetches=[]
            for fid,frame in zip(frame_ids,frames,strict=True):
                meter={}
                _,wire=node_rpc.rpc(self.lab.cfg['ports']['c'],'tx',id=fid,meter=meter)
                require(wire==frame,'confirmed frame readback mismatch')
                fetches.append(meter)
            self.out['settlement']['confirmed_frame_fetches']=fetches
            verifier=public_role()
            try:
                pair=verify_pair(frames,verifier,bytes.fromhex(NETWORK),b.height)
                require([p.fee for p in pair]==[0,3],'released verifier rejected fee allocation')
                incoming=pair[1].cms[0]
                verifier.close()
            finally:
                verifier.abort()
            self.checkpoint('swap')
            taker=self.homes['taker']
            require(not (taker/'wallets/alice-restored').exists(),'used recovery destination')
            restored=self.participant('taker','swap','restore','alice-restored',taker/'offline-seed')
            require(restored['balance']==8 and restored['assets']=={self.asset:80},'incorrect recovered funds')
            funds=self.wallet_balance('maker','maker')
            require(funds=={'native':14,'assets':{self.asset:20}},'maker received wrong assets')
            self.out['wallets']['maker_settled']=funds
            self.participant('taker','swap','create','forward')
            p=self.participant('taker','swap','send','alice-restored','forward',5,'native',0,'--intent','first-native-fee','--wait',0)
            require(p['fee']==3 and p['real_inputs']==1,'ordinary fee or input count')
            pb,paid,size=wait(lambda:locate([p['tx']]),bool,'autonomous restored payment inclusion',150)
            require(pb.amount==103,'ordinary miner credit incorrect')
            self.out['ordinary']['restored-payment']={k:p[k] for k in ('tx','packet_B','fee')}
            self.out['wallets']['after_restore']={'native':8,'assets':{self.asset:80}}
            self.out['wallets']['final_taker']=self.wallet_balance('taker','alice-restored')
            self.out['wallets']['forward']=self.wallet_balance('taker','forward')
            require(self.out['wallets']['final_taker']=={'native':0,'assets':{self.asset:80}} and
                    self.out['wallets']['forward']=={'native':5,'assets':{}},'final holdings')
            with sqlite3.connect((taker/'wallets/alice-restored/mng1-wallet-state.sqlite').as_uri()+'?mode=ro',uri=True) as db:
                rows=db.execute('SELECT cm,amount,token,creator FROM owned WHERE spender=?',(bytes.fromhex(p['tx']),)).fetchall()
                require(rows==[(incoming,8,0,bytes.fromhex(frame_ids[1]))],'ordinary payment did not consume only the swap note')
            self.out['checks']['restored_only_input_was_acquired_8']=True
        finally:
            stop.set()
            miner.join(40)
        if errors:
            raise errors[0]
        require(not miner.is_alive(),'miner did not stop')
        head=self.checkpoint('final')
        require(head['fees']==18,'four setup fees and two user fees required')
        self.out['genesis']=GENESIS.hex()
        self.out['miner_keys']={k:(self.h/'nodes'/k/'miner.pk').read_text().strip() for k in 'abc'}
        ident=head['tip']
        seen=[]
        while ident!=GENESIS.hex():
            raw=self.lab.request('c','block',id=ident)[1]
            require(block_id(raw).hex()==ident,'incorrect archived PoW block')
            (self.pub/'blocks'/(ident+'.bin')).write_bytes(raw)
            b=decode_block(raw)
            for p in b.packets:
                tid=sha256(p).hexdigest()
                seen.append(tid)
                (self.pub/'packets'/(tid+'.bin')).write_bytes(p)
            ident=b.parent.hex()
        require(sorted(seen)==sorted([v['tx'] for v in self.out['ordinary'].values()]+frame_ids),'unexpected payment in full history')
        self.out['checks']['all_history_reconciled']=True
        self.out['meter']['wallet_node_rpc']=list(self.gateway.rows)
        require([r['id'] for r in self.gateway.rows if r['op']=='submit']==
                [self.out['settlement']['bundle_id'],self.out['ordinary']['restored-payment']['tx']],'unexpected wallet submission')
        tcp={k:l.rows for k,l in self.cipher_links.items()}
        self.out['meter']['encrypted_link_observer']=tcp
        reported=[m for group in self.out['meter']['negotiation'] for m in group['calls']]
        observed=[m for seq in tcp.values() for m in seq]
        a=sorted((m['wire_request_B'],m['wire_reply_B']) for m in reported)
        b=sorted((m['to_maker_B'],m['to_taker_B']) for m in observed)
        # A server may send its encrypted exporter signature while the taker is closing
        # an unauthenticated connection. Keep peer-side and taker-side observations separate.
        (self.h/'wire-observations.json').write_text(json.dumps(self.out['meter']['negotiation'],indent=2))
        for item in self.out['meter']['negotiation']:
            calls=item['calls']
            observed=item['forwarder']
            require(len(calls)==len(observed),'wallet request missing independent link observation')
            for m,v in zip(calls,observed,strict=True):
                if m['authenticated']:
                    require((m['wire_request_B'],m['wire_reply_B'])==(v['to_maker_B'],v['to_taker_B']),
                            'authenticated exchange byte counts differ in '+item['operation'])
        self.out['meter']['all_socket_and_forwarder_counts_agree']=a==b
        self.out['meter']['totals']={
            'directory_sent_B':sum(m['request_B'] for x in self.out['meter']['discovery'] for m in x['endpoints']),
            'directory_received_B':sum(m['reply_B'] for x in self.out['meter']['discovery'] for m in x['endpoints']),
            'private_TCP_sent_B':sum(x for x,y in a),'private_TCP_received_B':sum(y for x,y in a),
            'settlement_submit_sent_B':self.out['settlement']['submit']['request_B'],
            'settlement_submit_received_B':self.out['settlement']['submit']['reply_B']}
        (self.pub/'RUN.json').write_text(json.dumps(self.out,sort_keys=True,indent=2)+'\n')
        return dict(public=str(self.pub),tip=head['tip'],fees=head['fees'],native_sent=5,final_token=80,
                    actual_swap_bytes=self.out['settlement']['wire_B'],topology=self.topology)


def run(args):
    h=args.home.resolve()
    h.mkdir(parents=True,exist_ok=True,mode=0o700)
    require(not any(h.iterdir()) and not h.stat().st_mode&0o077,'walkthrough needs a fresh private home')
    provision(args,h)
    sys.path.insert(0,str(h/'deployment/devnet'))
    with ExitStack() as stack:
        remote=Remote(args.remote_ssh,args.ssh_config) if args.remote_ssh else None
        if remote:
            stack.callback(remote.close)
        demo=Demo(h,stack,remote)
        demo.start()
        demo.fund()
        demo.makers()
        chosen=demo.negotiate()
        return demo.finish(chosen)
