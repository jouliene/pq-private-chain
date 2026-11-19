"""Generate or replay isolated fixed-supply TKN1 public evidence; wallet seeds live on temporary tmpfs."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from ledger import ALLOC, BLOCK, GEN, NETWORK, VK, Ledger, Role, context, need, pieces, sha, u32, u64, unpack

def dump(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")

def role(stack,rt,args,private=None):
    build=json.loads((rt/"BUILD.json").read_text())
    obj=Role(rt/"native",build["binary_sha256"],args,rt/"registered" if args[0]!="hash" else None,private)
    stack.callback(obj.abort)
    return obj

def scan(actor,ledger,rows=None):
    response=actor.call(b"S",ledger.head,ledger.endowments,b"".join(ledger.rows if rows is None else rows),b"".join(ledger.nfs))
    need(response[:4]==b"SCAN","scan reply")
    return [struct.unpack("<IQQ",r) for r in pieces(response[4:],20)]

def sums(inventory):
    return [sum(row[i] for row in inventory) for i in [1,2]]

def replay(runtime,public,approved):
    with ExitStack() as stack:
        hashes=role(stack,runtime,["hash"])
        verify=role(stack,runtime,["verify","/keys"])
        state=Ledger(hashes,verify,(public/"genesis.bin").read_bytes(),approved)
        blocks=sorted((public/"blocks").glob("*.bin"),key=lambda p:int(p.stem))
        need(len(blocks)==4,"complete four spends")
        for height,path in enumerate(blocks,1):
            need(path.stem==str(height),"contiguous replay")
            state.accept(path.read_bytes())
        sample=unpack(blocks[0].read_bytes())[1]
        # Structural shape and ordered receipts stay fixed. This changes canonical public PI #21,
        # in the last 26 field limbs of the proof. Check canonical reserialization in native verify().
        n=int.from_bytes(sample[5:9],"little")
        idx=9+n-26*8+21*8
        need(sample[idx:idx+8]==u64(3),"located verified fee PI")
        altered=sample[:idx]+u64(4)+sample[idx+8:]
        need(verify.call(altered)==b"0","canonical changed fee PI rejected")
        need(verify.call(b"DLF1"+sample[4:])==b"0","old frame refused")
        before=state.head
        try:state.transition(sample)
        except ValueError as error:need(str(error)=="spentness and fee","expected current spentness")
        else:raise ValueError("already consumed inputs")
        need(state.head==before,"atomic rejection")
        return dict(approved_genesis_sha256=approved,network=NETWORK.hex(),registered_vk_sha256=VK,blocks=state.logs,
                    canonical_proof_pi_control="fee 3 to 4, same field width, parseable canonical proof; fails cryptographic verifier before fee codec",
                    cross_profile_frame_rejected=True,duplicate_spend_refused=True,public_verifier_meters=verify.close(),
                    final_fee_sink_native=state.fees,state_hash=sha(state.head))

def generate(rt,out):
    out.mkdir(parents=True,exist_ok=False)
    (out/"blocks").mkdir()
    result={"network":NETWORK.hex(),"profile_vk_sha256":VK,"synthetic_allocations":ALLOC,"transfers":[],"role_meters":{}}
    with tempfile.TemporaryDirectory(prefix="tkn1-wallets-",dir="/dev/shm") as temp, ExitStack() as stack:
        base=Path(temp)
        hashes=role(stack,rt,["hash"])
        verifier=role(stack,rt,["verify","/keys"])
        wallets={}
        addresses={}
        def wallet(label,mode="create"):
            folder=base/(label if mode=="create" else label+"-restored")
            folder.mkdir(mode=0o700)
            if mode=="restore":
                source=base/label
                need([p.name for p in source.iterdir()]==["seed"],"unexpected wallet files")
                shutil.copy2(source/"seed",folder/"seed")
            obj=role(stack,rt,["wallet","/keys","/private/seed",mode],folder)
            addr=obj.get()
            need(len(addr)==1601,"public address")
            if mode=="restore":need(addr==addresses[label],"seed restoration")
            wallets[label]=obj
            addresses[label]=addr
        for label in ("A","B","C","D"):wallet(label)
        for label in ("C","D"):
            result["role_meters"][label+"_offline_before_funding"]=wallets.pop(label).close()
        result["offline_restore"]={"recipients_offline_at_payment":["C","D"],
                                   "private_files_imported_per_recipient":1,"new_private_directory":True}
        gen=bytearray(GEN+NETWORK)
        for i,(n,t) in enumerate(ALLOC):
            pk=addresses["AB"[i//2]][1:33]
            row=context(i)+pk+u64(n)+u64(t)
            gen.extend(row+hashes.call(b"C"+row))
        gen=bytes(gen)
        (out/"genesis.bin").write_bytes(gen)
        approved=sha(gen)
        state=Ledger(hashes,verifier,gen,approved)
        result["genesis_sha256"]=approved
        def payment(payer,payee,n,t,count,negative=False):
            w=wallets[payer]
            before=scan(w,state)
            cmd=bytes([ord("T") if negative else ord("P"),count])+u64(n)+u64(t)+addresses[payee]
            size=w.sizes.copy()
            packet=w.call(cmd)
            duration=w.times[-1]
            framed=[new-old for new,old in zip(w.sizes,size)]
            if negative:
                need(packet==b"0" or verifier.call(packet)==b"0","inconsistent typed-token equation accepted")
                result["unbalanced_witness"]={"native_balance_unchanged":True,"all_four_typed_openings_consistent":True,
                    "out_token_delta":1,"stage":"prover_refused" if packet==b"0" else "public_verifier_refused",
                    "wallet_request_reply_bytes":framed}
                return
            need(packet[:5]==b"TKN1\x01","TKN1 payment")
            raw=state.produce(packet)
            (out/"blocks"/f"{len(state.logs)}.bin").write_bytes(raw)
            selected=sums(before[:count])
            after=scan(w,state)
            need(sums(after)==[sums(before)[0]-n-3,sums(before)[1]-t],"payer balance")
            result["transfers"].append(dict(payer=payer,payee=payee,real_inputs=count,pay_native=n,pay_token=t,
                  selected_values=selected,change=[selected[0]-n-3,selected[1]-t],wallet_request_reply_bytes=framed,
                  prove_request_wall_s_including_lazy_setup_if_cold=duration,block=state.logs[-1]))
        payment("A","C",0,40,2,True)
        payment("A","C",0,40,2)
        payment("B","C",70,65,2)
        wallet("C","restore")
        c=wallets["C"]
        owned=scan(c,state)
        need(sorted(row[1:] for row in owned)==[(0,40),(70,65)],"two independent seed-only receipts")
        # Wallet-only corruption control. Leave all ordered public CMs and their root unchanged.
        # Copy C's valid first incoming ciphertext beside a different CM; later real output survives.
        mixed=list(state.rows)
        first=owned[0][0]-len(ALLOC)
        other=first^1
        mixed[other]=mixed[other][:32]+mixed[first][32:]
        mixed[first]=mixed[first][:32]+state.rows[first^1][32:]
        recovered=scan(c,state,mixed)
        need([(r[1],r[2]) for r in recovered]==[(70,65)],"skip mismatched opening, retain later owned receipt")
        result["wallet_only_mismatch_control"]={"matched_before":len(owned),"matched_after":len(recovered),"same_public_root":True}
        payment("C","D",41,75,2)
        wallet("D","restore")
        need(sums(scan(wallets["D"],state))==[41,75],"one external note restored")
        payment("D","B",12,14,1)
        wallets_state={name:sums(scan(w,state)) for name,w in wallets.items()}
        need(sum(x[0] for x in wallets_state.values())+state.fees==400 and
             sum(x[1] for x in wallets_state.values())==240,"fixed issuance totals")
        result["final_synthetic_balances"]=wallets_state
        result["final_fee_sink_native"]=state.fees
        for name,w in wallets.items():result["role_meters"][name]=w.close()
        result["role_meters"]["producer_verify"]=verifier.close()
    result["public_replay"]=replay(rt,out,approved)
    dump(out/"RESULT.json",result)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["generate","replay"])
    p.add_argument("runtime",type=Path)
    p.add_argument("evidence",type=Path)
    p.add_argument("--approve-genesis")
    a=p.parse_args()
    need(sha((a.runtime/"registered/token.vk").read_bytes())==VK,"pinned TKN1 key")
    if a.mode=="generate":generate(a.runtime.resolve(),a.evidence.resolve())
    else:
        need(a.approve_genesis is not None,"operator genesis hash required")
        print(json.dumps(replay(a.runtime.resolve(),a.evidence.resolve(),a.approve_genesis),indent=2))
