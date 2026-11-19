"""Exercise typed coin selection, owning a token-only genesis, and private journal atomicity."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

def check(home):
    dev=home/"deployment/devnet"
    sys.path.insert(0,str(dev))
    import chain
    import runtime
    from intents import Outbox
    from typed import MAX,select_amounts
    from wallet import Wallet
    from wallet_sync import WalletSync
    binary=runtime.prepare(home/"deployment/runtime")
    folder=home/"wallets/miner-a"
    with Wallet(binary.binary,binary.binary_sha,binary.keys,folder) as wallet:
        state=WalletSync(wallet,folder,chain.NETWORK,chain.GENESIS,chain.GENESIS_HEADER)
        try:
            assert state.inventory()["token_balance"]==240 and state.inventory()["balance"]==0
            assert state.witness(chain.FOUNDING_ROW[-32:].hex())==(0,[(bytes(32),)*3])
        finally:
            state.close()
        address=wallet.address
    c=[bytes([i])*32 for i in (1,2,3)]
    rows=[(c[0],0,200),(c[1],80,0),(c[2],MAX,MAX)]
    assert select_amounts(rows,(1,100),lambda cm:cm==c[2].hex())==tuple(x.hex() for x in c[:2])
    assert select_amounts(rows,(0,100),lambda _:False)==(c[2].hex(),)
    with Outbox(folder) as out:
        out.register("check",address,(0,120))
        try:out.register("check",address,(0,121))
        except ValueError:pass
        else:raise AssertionError("intent changed")
        pins=[x.hex() for x in c[:2]]
        account=dict(amount=0,token_amount=120,fee=3,input_total=80,token_input_total=200,
                     change=77,token_change=80,real_inputs=2,input_commitments=pins)
        out.db.execute("CREATE TEMP TRIGGER check_abort BEFORE INSERT ON attempts BEGIN SELECT RAISE(ABORT,'test'); END")
        try:out.prepare("check",b"unused-local-write-control",SimpleNamespace(height=0,tip=chain.GENESIS),account,0,pins)
        except sqlite3.IntegrityError:pass
        else:raise AssertionError("expected rollback")
        assert out.get("check")["pinned"] is None and not out.attempts("check")
        assert not any(out.reserved(cm,"another") for cm in pins)
    return dict(genesis_token_balance=240,genesis_native_balance=0,token_only_witness_depth=1,
                two_lane_selection=True,outbox_conflicting_token_amount_rejected=True,
                exclusive_reservations_rolled_back=True)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("disposable_home",type=Path,help="already staged, fresh wallet home not used for real intents")
    print(json.dumps(check(p.parse_args().disposable_home.resolve()),sort_keys=True))
