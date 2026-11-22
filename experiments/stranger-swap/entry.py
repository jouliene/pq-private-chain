"""Ordinary wallet commands for discovering makers, requesting private quotes and settling SWP1."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from directory import PARTIAL, DEFAULT_RELAYS, MAX_TTL, NETWORK, SERVICE, Relay, directory_round, endpoint, validate
import market_transport


def publish(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def atomic(path, value):
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as buf:
        json.dump(value, buf)
        buf.flush()
        os.fsync(buf.fileno())
    os.replace(buf.name, path)


def boot(home):
    config = json.loads((home/'network.json').read_bytes())
    relays = config.get('market_relays', DEFAULT_RELAYS)
    if not isinstance(relays,(list,tuple)) or not 2 <= len(relays) <= 4:
        raise ValueError('expected two to four bootstrap relays')
    if len(set(map(endpoint,relays))) != len(relays):
        raise ValueError('duplicate bootstrap relay')
    return relays


def wallet_folder(home, name):
    if not name or not name.isascii() or any(not(c.isalnum() or c in '-_') for c in name):
        raise ValueError('invalid wallet name')
    folder=home/'wallets'/name
    if not (folder/'address').is_file() or folder.is_symlink() or folder.stat().st_mode & 0o077:
        raise ValueError('expected a private initialized wallet')
    return folder


def parser():
    p=argparse.ArgumentParser(description=__doc__,prog='pqd market')
    p.add_argument('--home',type=Path)
    subs=p.add_subparsers(dest='op',required=True)
    relay=subs.add_parser('relay',help='run one independent public directory instance')
    relay.add_argument('--listen',required=True)
    for name in ('maker','discover','quote','settle','cancel','status'):
        sub=subs.add_parser(name)
        sub.add_argument('wallet')
        sub.add_argument('--node',choices=list('abcd'),default='c')
        if name=="discover":
            sub.add_argument("--partial",action="store_true",help="discover private lot order services")
        if name in ('maker','quote','settle'):
            sub.add_argument('--asset',required=True)
            sub.add_argument('--quantity',type=int,required=True)
        if name in ('maker','settle'):
            sub.add_argument('--native',type=int,required=True)
        if name=='maker':
            sub.add_argument('--endpoint',required=True)
            sub.add_argument('--listen')
            sub.add_argument('--lifetime',type=int,default=MAX_TTL)
            sub.add_argument('--quote-ttl',type=int,default=120)
            sub.add_argument('--blocks',type=int,default=8)
        if name=='quote':
            sub.add_argument('advert')
        if name in ('settle','cancel','status'):
            sub.add_argument('quote')
        if name=='settle':
            sub.add_argument('--expiry',type=int,required=True)
            sub.add_argument('--prepare-only',action='store_true',help='reserve a funded offer without signing or submitting')
        if name=='cancel':
            sub.add_argument('--offline',action='store_true',help='cancel a locally unsigned offer without contacting the maker')
    from partial_wallet import add_commands
    add_commands(subs)
    subs.add_parser('partial-walkthrough',help='run the funded C partial-fill scenario in an explicitly supplied new --home')
    walk=subs.add_parser('walkthrough')
    walk.add_argument('--remote-ssh',help='optional SSH-config host used for the second relay and winning maker')
    walk.add_argument('--ssh-config',type=Path)
    for suite in ('managed','swap'):
        walk.add_argument('--'+suite+'-build',type=Path)
        walk.add_argument('--'+suite+'-sha')
    return p


def main():
    os.umask(0o077)
    cli=parser()
    a=cli.parse_args()
    if a.op=="partial-walkthrough":
        if a.home is None or a.home.exists() or a.home.is_symlink():
            cli.error("partial-walkthrough requires an explicitly supplied new --home directory")
        import subprocess
        return subprocess.call(["bash",str(HERE.parent/"partial-fills"/"reproduce.sh"),str(a.home.absolute())])
    h=(a.home or HERE.parents[1]/".work/atomic-swap-devnet").resolve()
    a.home=h
    if a.op=='walkthrough':
        from walkthrough_market import run
        return publish(run(a))
    if a.op=='relay':
        with Relay(a.listen) as service:
            publish({'ready':True})
            service.serve_forever()
        return
    folder=wallet_folder(h,a.wallet)
    relays=boot(h)
    if a.op=='discover':
        ads,meters=directory_round(relays,service=PARTIAL if a.partial else SERVICE)
        atomic(folder/("partial-directory.json" if a.partial else "market-directory.json"),ads)
        return publish({'makers':sorted(ads),'discovery':meters})
    if a.op in ("offer","serve-offer","offer-status","cancel-offer","recover-fill","inspect-offer","reserve","fill","cancel-fill","fill-status","list-fills"):
        from partial_wallet import commands
        try:
            return commands(a,h,folder,relays,publish)
        except (ValueError,OSError,KeyError) as exc:
            publish({"ok":False,"error":str(exc)})
            return 1
    from negotiation import Maker,Taker
    if a.op=='maker':
        if not 5 <= a.lifetime <= MAX_TTL:
            raise ValueError('invalid advertisement lifetime')
        here=Path(tempfile.mkdtemp(dir=folder,prefix='market-advert-'))
        now=int(time.time())
        ad=market_transport.make_advert(here,a.endpoint,dict(network=NETWORK,version=1,service=SERVICE,issued=now,expires=now+a.lifetime))
        ident=validate(ad)
        policy=dict(asset=a.asset,quantity=a.quantity,native=a.native,ttl=a.quote_ttl,blocks=a.blocks)
        maker=Maker(h,a.wallet,a.node,ad,policy)
        def ready():
            _,meters=directory_round(relays,ad)
            publish({'ready':True,'advert':ident,'discovery':meters})
        return market_transport.serve(here,ad,maker.handle,listen=a.listen,ready=ready)
    taker=Taker(h,a.wallet,a.node)
    private=[]
    def request(ad,body):
        meter={}
        private.append(meter)
        return market_transport.request(ad,body,meter=meter)
    try:
        if a.op=='quote':
            cache=json.loads((folder/'market-directory.json').read_bytes())
            ad=cache.get(a.advert)
            if ad is None or validate(ad)!=a.advert:
                raise ValueError('maker is absent from the wallet discovery results')
            result=taker.quote(ad,request,asset=a.asset,quantity=a.quantity)
        elif a.op=='settle':
            result=taker.settle(a.quote,request,asset=a.asset,quantity=a.quantity,native=a.native,expiry=a.expiry,
                                stage='prepared' if a.prepare_only else 'complete')
            if a.prepare_only:
                publish(dict(result,private_transport=private))
                return 0
            signed=Path(result['packet']).read_bytes()
            # This is public submission to the participant's validating node, independent of either relay.
            sys.path.insert(0,str(h/'deployment/devnet'))
            from transport import rpc
            ident=sha256(signed).hexdigest()
            if result['sha256']!=ident:
                raise ValueError('local bundle identity mismatch')
            meter={}
            started=time.time_ns()
            accepted,_=rpc(json.loads((h/'network.json').read_bytes())['ports'][a.node], 'submit', signed,meter=meter)
            if accepted['id']!=ident:
                raise ValueError('validating node returned unexpected bundle identity')
            result=dict(result,submit=meter,submitted_ns=started,ack=accepted['id'])
        elif a.op=='cancel':
            result=taker.cancel(a.quote,None if a.offline else request)
        else:
            result=taker.status(a.quote)
    except (ValueError, OSError, KeyError) as exc:
        publish({'ok':False,'error':str(exc),'private_transport':private})
        return 1
    publish(dict(result,private_transport=private))
    return 0


if __name__=='__main__':
    sys.exit(main())
