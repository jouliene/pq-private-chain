"""Reconcile the two actual spendable receipts, 8-unit source and 5-unit beneficiary using private disposable wallets."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'atomic-swap/review'))
from native_currency_wallet import open_note
from swaps import ZERO,ast1,decode_pair
from wallet_joins import dbread,effects


def restore_role(stack,backup,dep):
    assert backup.is_file() and not backup.is_symlink() and backup.stat().st_size==32
    assert not backup.stat().st_mode & 0o077
    sandbox=Path(stack.enter_context(tempfile.TemporaryDirectory()))
    shutil.copyfile(backup,sandbox/'seed');(sandbox/'seed').chmod(0o600)
    program=dep/'runtime/native';key=dep/'keys/managed.vk'
    pin=(dep/'devnet/approved-native.sha256').read_text().strip()
    assert sha256(program.read_bytes()).hexdigest()==pin
    assert sha256(key.read_bytes()).hexdigest()=='1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d'
    role=ast1.Role(program,pin,['wallet','/keys','/private/seed','restore'],key.parent,private=sandbox)
    stack.callback(role.abort)
    address=role.get()
    assert len(address)==1601 and address[0]==1
    return role,address


def attribution(swap,ordinary,seller_seed,maker_seed,restored,recipient,dep):
    seller,maker=decode_pair(swap.read_bytes())
    payment=ordinary.read_bytes()
    tx=sha256(payment).digest()
    assert payment[:6]==b'MSP1\x01\x00'
    maker_tx=sha256(maker).digest()
    with ExitStack() as stack:
        a,addr_a=restore_role(stack,seller_seed,dep)
        b,addr_b=restore_role(stack,maker_seed,dep)
        assert addr_a!=addr_b
        token=open_note(b,seller,0); token_change=open_note(a,seller,1)
        cash=open_note(a,maker,0); cash_change=open_note(b,maker,1)
        assert token[1]==0 and token[2]==20 and token[3]!=ZERO and token[4]==2
        assert token_change[1:]==(0,80,token[3],3)
        assert cash[1:]==(8,0,ZERO,2)
        assert cash_change and cash_change[1]>=0 and cash_change[2:]==(0,ZERO,3)
        assert open_note(a,seller,0) is None and open_note(b,maker,0) is None
        forward,addr_forward=restore_role(stack,recipient/'seed',dep)
        assert len({addr_a,addr_b,addr_forward})==3
        # Ordinary outputs may appear in either position. Identify the recipient with its actual receipt.
        received=[(i,v) for i in range(2) if (v:=open_note(forward,payment,i)) is not None]
        (recipient_index,onward_note),=received
        assert onward_note[1:]==(5,0,ZERO,2)
        assert open_note(a,payment,recipient_index) is None
        forward.close();a.close();b.close()
    with dbread(restored/'mng1-wallet-state.sqlite') as inv:
        sources=inv.execute('SELECT cm,nf,amount,token,asset,kind,creator FROM owned WHERE spender=?',(tx,)).fetchall()
        assert sources==[(effects(maker)[1][0],cash[0],8,0,ZERO,'incoming',maker_tx)]
        assert cash[0] in effects(payment)[0]
        change=inv.execute('SELECT cm,amount,token,asset FROM owned WHERE spent IS NULL AND (amount>0 OR token>0)').fetchall()
        assert change==[(effects(seller)[1][1],0,80,token[3])]
    with dbread(restored/'mng1-intents.sqlite') as out:
        row,=out.execute('SELECT accounting,pinned FROM attempts JOIN intents ON intents.id=attempts.intent WHERE tx=?',(tx.hex(),)).fetchall()
        metrics=json.loads(row[0])
        assert json.loads(row[1])==[effects(maker)[1][0].hex()]
        assert (metrics['input_total'],metrics['real_inputs'],metrics['amount'],metrics['fee'],metrics['change'])==(8,1,5,3,0)
    with dbread(recipient/'mng1-wallet-state.sqlite') as inv:
        row,=inv.execute('SELECT amount,token,asset,kind,creator FROM owned WHERE cm=?',(effects(payment)[1][recipient_index],)).fetchall()
        assert row==(5,0,ZERO,'incoming',tx)
    return dict(regenerated_seed_owners=3,checked_swap_outputs=4,wrong_owners_missed=2,actual_spent_native_receipt=8,
                restored_real_sources=1,ordinary_native_delivered=5,ordinary_native_fee=3,restored_positive_native_change=0,
                seller_managed_change=80,onward_receipt_position=recipient_index,onward_receiver_reopened=True,buyer_received_managed=20,maker_native_change=cash_change[1])


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('swap','ordinary','seller_seed','maker_seed','restored_wallet','onward_wallet','deployment'):
        p.add_argument(name,type=Path)
    a=p.parse_args()
    print(json.dumps(attribution(a.swap,a.ordinary,a.seller_seed,a.maker_seed,a.restored_wallet,a.onward_wallet,a.deployment),
                     indent=2,sort_keys=True))
