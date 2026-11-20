"""Validate the complete public SWB1 and rejection controls with the deployed node/verifiers."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from struct import pack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure import load_public, read_bundle


def flip(raw, at):
    return raw[:at] + bytes([raw[at]^1]) + raw[at+1:]


def require_rejection(f):
    try:
        f()
    except ValueError as error:
        return str(error)
    raise RuntimeError("invalid case was accepted")


def controls(deployment, blob):
    chain,ledger,wire = load_public(deployment)
    from managed_ledger import ManagedBackend
    from managed_ops import MAGIC
    from runtime import config
    from wire import Role
    data,frames = read_bundle(wire,blob)
    parts = wire.pair(frames)
    a,b = parts
    legs = [p.leg for p in parts]
    sigs = [p.signature for p in parts]
    vis = ledger.public_role()
    effects = []
    cases = {}
    try:
        good = ledger.verify_pair(frames,vis,chain.NETWORK,a.expiry)
        if len(good)!=2 or sum(slot.fee for slot in good)!=3:
            raise ValueError("positive pair missing")
        cases["verified_original"]=True
        for leg in legs:
            effects.append(ledger.read_leg(vis,leg))
        def verify_raw(raw):
            return ledger.verify_pair(wire.split(raw),vis,chain.NETWORK,a.expiry)
        def rebuild(**updates):
            args = dict(network=a.network,terms=a.terms,expiry=a.expiry,payer=a.payer,legs=legs,signatures=sigs)
            return wire.assemble(**(args|updates))
        expired_height = a.expiry+1
        cases["expired"] = require_rejection(lambda: ledger.verify_pair(frames,vis,chain.NETWORK,expired_height))
        cases["missing_frame"] = require_rejection(lambda: verify_raw(wire.BUNDLE+pack("<I",len(frames[0]))+frames[0]))
        cases["duplicated_frame"] = require_rejection(lambda: wire.pair([frames[0],frames[0]]))
        cases["out_of_order"] = require_rejection(lambda: wire.pair(frames[::-1]))
        cases["trailing_bytes"] = require_rejection(lambda: verify_raw(data+b"x"))
        cases["truncated"] = require_rejection(lambda: verify_raw(data[:-1]))
        for i,leg in enumerate(legs):
            cases[f"signature_{i}_changed"] = require_rejection(lambda:
                verify_raw(rebuild(signatures=[flip(s,0) if j==i else s for j,s in enumerate(sigs)])))
            cases[f"proof_{i}_changed"] = require_rejection(lambda:
                verify_raw(rebuild(legs=[flip(l,9) if j==i else l for j,l in enumerate(legs)])))
            ct = wire.CT_PAIR//2
            swapped = leg[:-2*ct]+leg[-ct:]+leg[-2*ct:-ct]
            cases[f"receipts_{i}_exchanged"] = require_rejection(lambda:
                verify_raw(rebuild(legs=[swapped if j==i else l for j,l in enumerate(legs)])))
            if vis.call(swapped) != b"0":
                raise ValueError("native verifier accepted swapped ordered receipts")
        cases["swapped_owner_signatures"] = require_rejection(lambda: verify_raw(rebuild(signatures=sigs[::-1])))
        changed_expiry = a.expiry-1 if a.expiry>1 else 2
        changed_terms = sha256(a.terms+b"control").digest()
        changed_network = sha256(a.network+b"control").digest()
        cases["network"] = require_rejection(lambda: verify_raw(rebuild(network=changed_network)))
        cases["terms"] = require_rejection(lambda: verify_raw(rebuild(terms=changed_terms)))
        cases["fee_payer"] = require_rejection(lambda: verify_raw(rebuild(payer=1-a.payer)))
        # Check both signatures independently. Pair verification of an invalid message can stop at side zero.
        fields = dict(network=a.network,terms=a.terms,expiry=a.expiry,payer=a.payer,legs=legs)
        variants = {"network":{"network":changed_network},"terms":{"terms":changed_terms},
                    "expiry":{"expiry":changed_expiry},"payer":{"payer":1-a.payer},
                    "ordered_legs":{"legs":legs[::-1]},
                    "leg0_digest":{"legs":[flip(legs[0],9),legs[1]]},
                    "leg1_digest":{"legs":[legs[0],flip(legs[1],9)]}}
        signature_checks = {}
        for field, change in variants.items():
            h = wire.digest(**(fields|change))
            rejected = [vis.call(b"V"+e[-1]+h+s)==b"0" for e,s in zip(effects,sigs)]
            if rejected != [True,True]:
                raise ValueError("changed field retained an owner signature")
            signature_checks[field]=rejected
    finally:
        vis.abort()
    conf = config(deployment/"runtime")
    old = Role(conf.binary,conf.binary_sha,["verify","/keys"],conf.keys)
    try:
        ordinary = ManagedBackend(None,old,conf.profile_sha)
        for i,leg in enumerate(legs):
            for tag,changed in [("raw",leg),("AST1",b"AST1"+leg[4:]),("MNG1",b"MNG1"+leg[4:])]:
                if old.call(changed)!=b"0":
                    raise ValueError("standalone proof extraction")
                # Ordinary managed transfer wraps a versioned proof in the genuine transfer envelope.
                packet = MAGIC+b"\x00"+changed if tag=="MNG1" else changed
                cases[f"ordinary_extraction_{i}_{tag}"] = require_rejection(lambda: ordinary.verify(packet))
    finally:
        old.abort()
    return {"bundle_sha256":sha256(data).hexdigest(), "node_and_wire":cases,
            "both_native_signatures_rejected_by_changed_field":signature_checks}


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("deployment",type=Path)
    p.add_argument("public_bundle",type=Path)
    args=p.parse_args()
    print(json.dumps(controls(args.deployment.resolve(),args.public_bundle),indent=2,sort_keys=True))
