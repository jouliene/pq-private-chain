"""Conditional witness decoding from test-owned EAR1 oracle cells. No private material leaves this process."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import os
import random
import secrets
import subprocess
import sys

import numpy as np

HERE = Path(__file__).resolve().parent
EX = HERE.parent
sys.path[:0] = [str(EX/"sgm1-admission"), str(EX/"sgm1-security")]
from packets import funded
from wallet import Coin, descriptor, prepare
from relation import FundedTree, Note, h, owner
from early_degree import EarlyDegreeEnvelope
sys.path[:0] = [str(EX/"structured-keccak"/"payment"), str(EX/"structured-keccak"/"funding")]
from monetary import build_payment, ref
from plan import Wiring
from argument import FLATTEN, dimensions
from proof import Transcript, random_fields
from ring_switch import PROFILE, RingCommitment
from commitment import derive_leaf, node
from subfield import F, fencode, feval, fmul, fprod, freduce

P = PROFILE


def funded_case(scratch):
    helper = EX/"hidden-membership"/"paths"/"funding_fixture.py"
    private = json.loads(subprocess.check_output([sys.executable, "-IB", helper, "new", scratch/"prefix"]))
    pin = hashlib.sha256((scratch/"prefix"/"genesis.bin").read_bytes()).digest()
    chain, rows = funded(scratch/"prefix", pin)
    coins = []
    for record in private:
        ask, asset, salt = (bytes.fromhex(record[k]) for k in ("ask", "asset", "salt"))
        cash, qty = (int.from_bytes(bytes.fromhex(record[k]), "little") for k in ("native", "qty"))
        coins.append(Coin(record["index"], Note(owner(ask), cash, asset, qty, salt), ask))
    issued, = [c.note for c in coins if c.note.qty]
    cash = sum(c.note.native for c in coins)
    outputs = [(descriptor(chain,secrets.token_bytes(64)),0,issued.asset,7),
               (descriptor(chain,secrets.token_bytes(64)),cash-1,issued.asset,issued.qty-7)]
    body, st, witness, _, _ = prepare(pin,chain,rows,coins,outputs,1)
    ear = EarlyDegreeEnvelope(body.backend,body.role,body.anchor,body.fee,body.nfs,body.cms,body.receipts)
    intent = ear.intent(chain,FundedTree(rows).root,len(rows))
    statement = replace(st,intent=intent,auth=h("auth",coins[0].ask,intent))
    ref.evaluate(statement,witness)
    return pin,rows,statement,witness


def public_offsets(st):
    # Observe only the public compiler's allocation result IDs. No private encoding is used to
    # choose where to read the decoded bits. Intermediate wires separate these fields.
    fields, active = [], []
    def returned(frame,event,value):
        if event != "return":
            return
        if frame.f_code is Wiring.secret.__code__:
            fields.append(value)
        elif frame.f_code is Wiring.allocate.__code__ and frame.f_back.f_code is build_payment.__code__:
            active.append(value)
    previous = sys.getprofile()
    try:
        sys.setprofile(returned)
        public = build_payment(st, FLATTEN)
    finally:
        sys.setprofile(previous)
    if len(active)!=1 or len(active[0])!=1:
        raise ValueError("changed active-slot layout")
    return public.width,active[0][0],fields


def decode(st, positions, columns, gamma, degree_table):
    d = len(P.points)
    if len(positions) != len(set(positions)) or len(positions) != len(columns):
        raise ValueError("duplicate or missing position")
    retained = []
    for index, col in zip(positions,columns,strict=True):
        if not 0 <= index < P.leaves or len(col) != gamma.shape[1]+P.decs_rows:
            raise ValueError("invalid partial cell")
        mix = col[-P.decs_rows:] ^ freduce(fmul(gamma,col[:-P.decs_rows]),axis=1)
        if np.array_equal(mix,feval(degree_table,P.points,P.evaluation(index))):
            retained.append((P.evaluation(index),col[:-P.decs_rows]))
    if len(retained) < d:
        raise ValueError("insufficient agreeing columns for unique degree decoding")
    basis = tuple(x for x,_ in retained[:d])
    values = np.array([col for _,col in retained[:d]], F).T
    for x,col in retained[d:]:
        if not np.array_equal(feval(values,basis,x),col):
            raise ValueError("inconsistent extra column")
    # Column rows begin with the packed bit assignment. Omit the separate mask rows.
    width,active,ids = public_offsets(st)
    words = (width+15)//16
    witness_rows = (words+P.pack-1)//P.pack
    packed = np.stack([feval(values[:witness_rows],basis,x) for x in P.omega],axis=1).ravel()[:words]
    bits = np.unpackbits(np.frombuffer(fencode(packed), np.uint8),bitorder="little")[:width]
    iterator = iter(ids)
    def take(n):
        positions = next(iterator)
        if len(positions)!=8*n:
            raise ValueError("public allocation width mismatch")
        return np.packbits(bits[positions],bitorder="little").tobytes()
    def uint(n):
        return int.from_bytes(take(n),"little")
    asset = take(64)
    inputs = []
    for _ in range(2):
        ask,occ,native,tag,qty,salt,index = take(64),take(64),uint(8),take(64),uint(8),take(64),uint(5)
        inputs.append(ref.Input(ask,native,tag,qty,salt,occ,index,tuple(take(64) for _ in range(40))))
    outputs = tuple(ref.Note(take(64),uint(8),take(64),uint(8),take(64)) for _ in range(2))
    if next(iterator,None) is not None:
        raise ValueError("additional private field allocations")
    result = ref.Witness(tuple(inputs),outputs,int(bits[active]),asset)
    ref.evaluate(st,result)
    return result


def run(scratch):
    pin,rows,st,witness = funded_case(scratch)
    wiring = build_payment(st,FLATTEN,witness)
    trace_words,_ = dimensions(wiring,wiring.batch())
    context = (b"structured Keccak GKR/C1/v1"+b"SGM1/early-explicit-degree/v1"
               +b"SGM1/complete-FS01/signed-prefix/v1"+pin+st.encode()+bytes([FLATTEN]))
    tr = Transcript(context)
    ring = RingCommitment(tr,wiring.width,trace_words,np.frombuffer(wiring.values,np.uint8),
                          random_fields((trace_words,)),early_degree=True)
    commitment = ring.commitment
    indices = random.Random(pin).sample(range(P.leaves), len(P.points)+1)
    columns = []
    for index in indices:
        pos, col = index, commitment.columns[index]
        digest = derive_leaf(index,fencode(col),commitment.salts[index],P.hash_bytes)
        for level in commitment.tree[:-1]:
            sibling = level[pos^1]
            digest = node(sibling,digest) if pos&1 else node(digest,sibling)
            pos //= 2
        if digest != commitment.root:
            raise ValueError("bad supplied Merkle path")
        columns.append(col)
    try:
        decode(st,indices[:P.opens],columns[:P.opens],commitment.gamma,commitment.rsamples)
    except ValueError as exc:
        if str(exc) != "insufficient agreeing columns for unique degree decoding":
            raise
    else:
        raise ValueError("accepted underspecified unique interpolation")
    result = decode(st,indices,columns,commitment.gamma,commitment.rsamples)
    if result.encode() != witness.encode() or result.active!=1 or result.inputs[0].ask==result.inputs[1].ask:
        raise ValueError("funded decoded witness mismatch")
    for i in result.inputs:
        if (i.occ,i.note().cm(st.chain)) != rows[i.index]:
            raise ValueError("disagrees with selected funded occurrence")
    negatives = []
    for slot in range(2):
        changed = list(result.inputs)
        ask = changed[slot].ask
        changed[slot] = replace(changed[slot],ask=bytes([ask[0]^1])+ask[1:])
        try:
            ref.evaluate(st,replace(result,inputs=tuple(changed)))
        except ValueError:
            negatives.append(slot)
    if negatives != [0,1]:
        raise ValueError("changed owner secret accepted")

    # Dimension obstruction for the degree layer alone. +/- in characteristic two coincide.
    xs = np.array([P.evaluation(i) for i in indices[:P.opens]],F)
    def vanish(x):
        return fprod(xs^x)
    g = commitment.gamma[:,0]
    def shifted(col,x):
        alt = col.copy()
        d = vanish(x)
        alt[0] ^= d
        alt[-P.decs_rows:] ^= fmul(g,d)
        return alt
    if not all(np.array_equal(col,shifted(col,x)) for col,x in zip(columns[:P.opens],xs,strict=True)):
        raise ValueError("sample constraint changed")
    other_x = P.evaluation(indices[-1])
    alternative = shifted(columns[-1],other_x)
    different = not np.array_equal(alternative,columns[-1])
    # Verify the polynomial identity R' = R at a whole unisolvent basis, beyond the 60 examples.
    for j,x in enumerate(P.points):
        alt = shifted(commitment.samples[:,j],x)
        mix = alt[-P.decs_rows:] ^ freduce(fmul(commitment.gamma,alt[:-P.decs_rows]),axis=1)
        if not np.array_equal(mix,commitment.rsamples[:,j]):
            raise ValueError("degree response changed")
    if not different:
        raise ValueError("perturbation is trivial")
    return dict(funded_input_count=2, owner_secrets_distinct=True, witness_exact=True,
                supplied_authenticated_columns=len(indices), reconstruction_positions=len(P.points),
                additional_consistency_checks=1, encoded_witness_B=len(result.encode()),
                changed_ASKs_rejected=negatives, protocol_opening_count=P.opens, insufficient_for_unique_interpolation=True,
                matching_sampled_columns=P.opens, unchanged_R_basis_positions=len(P.points),
                distinct_at_unopened_position=different,
                qualification="Test-owned partial-oracle decoder, without adversarial extraction or a new proof.")


if __name__ == "__main__":
    os.umask(0o077)
    with TemporaryDirectory() as path:
        print(json.dumps(run(Path(path)),indent=2))
