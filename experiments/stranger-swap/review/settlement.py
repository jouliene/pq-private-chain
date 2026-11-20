"""Reconstruct the signed SWP1 exchange and the dependent ordinary payment from public blocks and keys."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
SWAP=HERE.parents[1]/'atomic-swap/review'
sys.path.insert(0,str(SWAP))
from audit import (MANAGED_VK, SWAP_VK, HistoricalReader, Reader, ast1, database, group_rows, mount, read_graph,
                   selected_summary)
from swaps import decode_pair

NETWORK=bytes.fromhex('7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac')
ELFS=['360fa89587ec7dd6d349516ad26ccc29178c32e82f583568fc38c9520f59d8f5',
      '46ee4c569abe6eea973843713444a759075534de169fa3a6177f0f869973cc1a']


def check(public,submission,ordinary,deploy,helpers,node,databases,exact_elf):
    raw=submission.read_bytes()
    parts=decode_pair(raw)
    txids=[sha256(v).digest() for v in parts]
    bundle=sha256(raw).digest()
    ordinary_raw=ordinary.read_bytes();tx=sha256(ordinary_raw).digest()
    assert ordinary_raw.startswith(b'MSP1\x01\x00')
    assert sha256(b'AST1/PoW/network/v1\0'+bytes.fromhex(ast1.VK)+ast1.RULES).digest()==NETWORK
    with ExitStack() as stack:
        mng,mkey=mount(stack,deploy,'MNG1','managed.vk',MANAGED_VK)
        slg,skey=mount(stack,deploy,'SLG1','swap.vk',SWAP_VK,'swap-')
        same_elf=[v['approved_binary'] for v in (mkey,skey)]==ELFS
        if exact_elf:
            assert same_elf
        reader=Reader(HistoricalReader(mng,helpers/'roots',NETWORK,node),slg)
        states,blocks,tips,winner=read_graph(public,reader,helpers)
        final=states[winner]
        assert reader.groups.keys()=={bundle}
        g=reader.groups[bundle]
        assert g['payer']==1 and g['fee_by_leg']==[0,3] and g['leg_txids']==list(map(bytes.hex,txids))
        first_block=final.locations[txids[0]]
        assert first_block==final.locations[txids[1]]
        pay_block=final.locations[tx]
        assert final.ids.index(first_block)<final.ids.index(pay_block)
        sb,pb=blocks[first_block],blocks[pay_block]
        assert sum(x.fee for x in sb.slots if x.txid in txids)==3
        pay=reader.legacy.events[tx]
        assert (pay.op,pay.fee,pay.asset,pay.delta)==(0,3,bytes(32),0)
        assert all(x.amount==100+sum(event.fee for event in x.slots) for x in (sb,pb))
        # A historical reader verifies the packet independently of the label used by the harness.
        assert reader.legacy.packet(ordinary_raw)==pay
        seen=group_rows(reader,blocks)
        assert sum(block in final.ids for (_,block) in seen)==1
        counts=selected_summary(final,reader)
        signatures=reader.verify_independent(node)
        assert signatures['valid_distinct']==2
        checks=reader.public_controls()
        output=dict(network=NETWORK.hex(),genesis=final.ids[0].hex(),recorded_blocks=len(blocks),branch_tips=len(tips),
                    selected=counts,swap=g,ordinary=dict(tx=tx.hex(),bytes=len(ordinary_raw),fee=pay.fee,height=pb.height),
                    swap_height=sb.height,winning_chain_fees=final.fees,winning_chain_native_miner_credits=final.rewards,
                    spent_nullifiers_on_selected_history=len(final.spent),old_approved_verification_roles=[mkey,skey],
                    previous_ELFs_byte_identical=same_elf,independent_signatures=signatures,
                    public_receipt_and_role_checks=checks,databases=[database(p,final,seen) for p in databases],
                    winning_public_physical_txids=sorted(x.hex() for x in final.locations),
                    all_public_physical_txids=sorted(x.hex() for x in set(reader.legacy.events)|set(txids)))
        mng.close();slg.close()
        return output


if __name__=='__main__':
    if not __debug__: sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('public','submission','ordinary','deployment','helpers','node'):
        p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--db',action='append',default=[],type=Path)
    p.add_argument('--require-published-elf',action='store_true')
    a=p.parse_args()
    print(json.dumps(check(a.public,a.submission,a.ordinary,a.deployment,a.helpers,a.node,a.db,a.require_published_elf),
                     indent=2,sort_keys=True))
