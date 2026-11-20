"""Apply just the independently selected winning ancestry to a new production node database."""
import argparse
import json
from pathlib import Path
import sys


def check(deployment, public, result, destination):
    if destination.exists():
        raise ValueError('use a new empty database directory')
    destination.mkdir(mode=0o700)
    sys.path.insert(0,str(deployment/'devnet'))
    import chain
    import runtime
    from run import Resources

    review = json.loads(result.read_bytes())
    winner = review['selected']
    parent = bytes.fromhex(winner['tip'])
    path = []
    while parent != chain.GENESIS:
        assert len(path) < winner['height']
        raw = (public/'blocks'/(parent.hex()+'.bin')).read_bytes()
        assert chain.block_id(raw) == parent
        path.append((parent,raw))
        parent = raw[41:73]
    assert len(path) == winner['height']
    runtime_config = runtime.config(deployment/'runtime')
    assert runtime_config.binary_sha == review['binary_sha256'] and runtime_config.profile_sha == review['register_sha256']
    resources = Resources(runtime_config)
    try:
        store = chain.Chain(destination/'chain.sqlite',resources.backend)
        try:
            boot = store.status()
            assert (boot['tip'],boot['height'],boot['notes'],boot['spent'],boot['fees'],boot['issued']) == (
                review['empty_genesis'],0,0,0,0,0)
            assert store.public_assets(bytes(32),32,boot['tip'])['entries'] == []
            for bid,raw in reversed(path):
                accepted = store.accept(raw)
                assert accepted['tip'] == bid.hex() and accepted['selected']
            tip = store.status()
            assert all(tip[k] == winner[k] for k in ('tip','height','work','anchor','notes','spent','fees','issued','spent_set_sha256'))
            assert tip['deep_replays'] == 0
            page = store.public_assets(bytes(32),32,tip['tip'])
            assert page['entries'] == [dict(id=key,supply=row['cap'],height=row['height'],tx=row['tx'])
                                       for key,row in sorted(winner['registry'].items())]
            assert page['next'] is None
        finally:
            store.close()
        meters = resources.finish('verifier')['meters']
        accepted_count = sum(row['operation']=='public_verify' for row in meters)
        assert accepted_count == winner['payments']
        resources.finish('hash')
    finally:
        resources.close()
    return dict(genesis=boot['tip'],initial_native=0,initial_assets=0,final_assets=len(page['entries']),
                selected_tip=tip['tip'],selected_height=tip['height'],final_native=tip['issued'],
                fees=tip['fees'],registered_public_verifications=accepted_count,delivered_nonwinning_blocks=0)


if __name__ == '__main__':
    if not __debug__:
        sys.exit('assertions are required')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('deployment','public','public_replay_result','new_database_dir'):
        p.add_argument(name,type=lambda s:Path(s).resolve())
    a=p.parse_args()
    print(json.dumps(check(a.deployment,a.public,a.public_replay_result,a.new_database_dir),sort_keys=True,indent=2))
