"""Give a new production validator exactly the winning blocks starting at the original AST1 genesis."""
import argparse
import json
from pathlib import Path
import sys


def run(deployment,public,replay,dest):
    doc=json.loads(replay.read_bytes())
    target=doc['selected']
    dest.mkdir(mode=0o700,exist_ok=False)
    sys.path.insert(0,str(deployment/'devnet'))
    import chain
    import runtime
    from run import Resources
    head=bytes.fromhex(target['tip']); ancestry=[]
    while head!=chain.GENESIS:
        assert len(ancestry)<target['height']
        raw=(public/'blocks'/(head.hex()+'.bin')).read_bytes()
        assert chain.block_id(raw)==head
        ancestry.append((head,raw));head=raw[41:73]
    assert len(ancestry)==target['height'] and head.hex()==doc['genesis']
    cfg=runtime.config(deployment/'runtime')
    assert cfg.binary_sha==doc['binary_sha256'] and cfg.profile_sha==doc['vk_sha256']
    res=Resources(cfg)
    try:
        ledger=chain.Chain(dest/'chain.sqlite',res.backend)
        try:
            initial=ledger.status()
            assert (initial['tip'],initial['notes'],initial['issued'],initial['spent'],initial['fees'])==(head.hex(),0,0,0,0)
            assert ledger.public_assets(bytes(32),32,head.hex())['entries']==[]
            for bid,raw in reversed(ancestry):
                rec=ledger.accept(raw)
                assert rec['tip']==bid.hex() and rec['selected']
            final=ledger.status()
            assert all(final[k]==target[k] for k in ('height','tip','work','anchor','notes','issued','spent','fees','spent_set_sha256'))
            assert final['deep_replays']==0
            assert ledger.public_assets(bytes(32),32,target['tip'])['entries']==list(target['registry'].values())
        finally:
            ledger.close()
        meters=res.finish('verifier')['meters']
        res.finish('hash')
    finally:
        res.close()
    return dict(empty_genesis=initial['tip'],same_as_AST1=True,final_height=final['height'],final_tip=final['tip'],
                final_native=final['issued'],fees=final['fees'],registry=target['registry'],
                delivered_only_winning_blocks=len(ancestry),native_operation_counts={k:sum(x['operation']==k for x in meters)
                    for k in sorted({x['operation'] for x in meters})})


if __name__=='__main__':
    if not __debug__:
        sys.exit('assertions are required')
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('deployment','public','replay','new_directory'):
        p.add_argument(arg,type=lambda s:Path(s).resolve())
    a=p.parse_args()
    print(json.dumps(run(a.deployment,a.public,a.replay,a.new_directory),sort_keys=True,indent=2))
