"""Check a genuine previous token/token authorization under the installed native-aware wallet and node."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


def check(deployment,packet,terms):
    dev=deployment.resolve()/'devnet'
    sys.path.insert(0,str(dev))
    import chain
    from swap_ledger import public_role, verify_pair
    from swap_wire import split, pair
    from swap_terms import Terms
    raw=packet.read_bytes()
    frames=split(raw); parts=pair(frames)
    assert len(frames)==2 and all(p.payer==0 for p in parts)
    if terms:
        blob=terms.read_bytes()
        assert blob[:8]==b'SWPTER01' and len(blob)==3358
        decoded=Terms.decode(blob)
        assert decoded.encode()==blob and decoded.network==chain.NETWORK and decoded.payer==0
        assert [x.qty for x in decoded.parties]==[7,30] and all(x.give!=bytes(32) for x in decoded.parties)
        prior=sha256(b'SWP1/private-terms/v1\0'+blob).digest()
        assert decoded.commitment()==prior and all(p.terms==prior and p.expiry==decoded.expiry for p in parts)
    verifier=public_role()
    try:
        effects=verify_pair(frames,verifier,chain.NETWORK,parts[0].expiry)
        assert [x.fee for x in effects]==[3,0] and len({v for x in effects for v in x.nfs})==4
        verifier.close()
    finally:
        verifier.abort()
    return dict(old_complete_bundle_sha256=sha256(raw).hexdigest(),complete_B=len(raw),public_proofs_verified=2,
                final_authorizations_verified=2,payer=0,fee_by_leg=[3,0],local_prior_party_amounts=[7,30] if terms else None,
                authenticated_v1_preimage_and_expiry_matched=bool(terms))


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('deployment',type=Path);p.add_argument('old_public_swap',type=Path)
    p.add_argument('--local-old-terms',type=Path)
    a=p.parse_args()
    print(json.dumps(check(a.deployment,a.old_public_swap,a.local_old_terms),indent=2,sort_keys=True))
