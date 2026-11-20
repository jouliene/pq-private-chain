"""Verify one archived stranger-swap public data folder. Optional local wallet joins produce only aggregate observations."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adverts
import settlement
import traffic


def write(path,data):
    with path.open('x') as out:
        json.dump(data,out,sort_keys=True,indent=2)
        out.write('\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for option in ('public','deployment','helpers','node','provider-wheel','output'):
        p.add_argument('--'+option,required=True,type=Path)
    p.add_argument('--require-published-elf',action='store_true')
    p.add_argument('--db',action='append',default=[],type=Path)
    p.add_argument('--private-home',type=Path)
    a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=True)
    pub=a.public.resolve(strict=True)
    run=json.loads((pub/'RUN.json').read_bytes(),object_pairs_hook=adverts.unique)
    ads=list(run['ads'].values())
    write(a.output/'adverts.json',adverts.check(ads,a.provider_wheel))
    bundle=pub/'SWAP.bin'
    payment=pub/'packets'/(run['ordinary']['restored-payment']['tx']+'.bin')
    write(a.output/'settlement.json',settlement.check(pub,bundle,payment,a.deployment,a.helpers,a.node,a.db,a.require_published_elf))
    write(a.output/'traffic.json',traffic.check(pub,a.output/'settlement.json'))
    if a.private_home:
        import tempfile
        from quotes import check as check_quotes
        from wallet import attribution
        h=a.private_home.resolve(strict=True);taker=h/'participants/taker'
        seed=taker/'offline-seed'; wallets=taker/'wallets'
        with tempfile.TemporaryDirectory() as scratch:
            paths=[Path(scratch)/('advert-%d'%i) for i in range(2)]
            for name,obj in zip(paths,ads,strict=True):
                write(name,obj)
            write(a.output/'quotes.json',check_quotes(h,bundle,seed,paths))
        write(a.output/'wallet.json',attribution(bundle,payment,seed,h/'participants/maker/wallets/maker/seed',
                                                 wallets/'alice-restored',wallets/'forward',a.deployment))
    print(json.dumps(dict(public_bundle_SHA256=sha256(bundle.read_bytes()).hexdigest(),public_verified=True,
                          participant_local_joins=bool(a.private_home),receipts=str(a.output))))


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    main()
