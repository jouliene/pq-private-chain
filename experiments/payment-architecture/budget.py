"""Recount fixed framing from the published APV2 PoW capture and project explicit occupancies."""
import hashlib
import json
from pathlib import Path
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[2]
CAPTURE = ROOT/"devnet/wallet-review/evidence/clean/public-capture.tar.gz"
PAYMENTS = 100_000_000
MIXES = {"single":([1,0,0,0],0), "low":([85,10,4,1],1), "busy":([5,10,15,70],1/9), "full":([0,0,0,1],0)}

def parse(raw):
    if raw[:8]!=b"PQDEVBL1" or len(raw)<222:
        raise ValueError("bad base block")
    i=214
    sizes=[]
    for _ in range(raw[213]):
        width,=struct.unpack_from("<I",raw,i)
        packet=raw[i+4:i+4+width]
        n,=struct.unpack_from("<I",packet,5)
        if packet[:5]!=b"APV2\x01" or n+9+3584!=len(packet) or width!=len(packet):
            raise ValueError("invalid published block inventory")
        sizes.append(width)
        i+=4+width
    if i+8!=len(raw):
        raise ValueError("block ending")
    return sizes

def projection(packet):
    result={}
    for mix,(weights,empty) in MIXES.items():
        width=sum((i+1)*w for i,w in enumerate(weights))/sum(weights)
        h=(1+empty)/width
        share=222*h
        poll=PAYMENTS*(3744+305*h)
        result[mix]=dict(mean_paid_width=width,blocks_per_inclusion=h,
            archive_B_per_payment=packet+4+share,
            archive_TB_per_year=PAYMENTS*(packet+4+share)/1e12,
            proof_allowance_1TB=10000-4-share-3584-9,
            proof_allowance_5TB=50000-4-share-3584-9,
            wallet_upload_body_TB=packet*PAYMENTS/1e12,
            one_block_relay_body_TB=PAYMENTS*(packet+4+share)/1e12,
            one_preforward_plus_block_body_TB=PAYMENTS*(packet*2+4+share)/1e12,
            cold_wallet_projection_GB=poll/1e9,
            node_effects_min_GB=PAYMENTS*(128+32*h)/1e9,
            headers_ids_GB=PAYMENTS*164*h/1e9)
    return result

def budget():
    with tarfile.open(CAPTURE) as t:
        w=json.load(t.extractfile("WALLET.json"))
        selected=[parse(t.extractfile("blocks/"+s+".bin").read()) for s in w['selected_chain']]
    packets=[n for row in selected for n in row]
    assert packets and set(packets)=={230206}
    return dict(source_sha256=hashlib.sha256(CAPTURE.read_bytes()).hexdigest(),
        complete_blocks=len(selected),observed_canonical_occupancy={str(k):sum(len(p)==k for p in selected) for k in range(5)},
        complete_packet_B=230206,proof_including_public_inputs_B=226613,ciphertexts_B=3584,
        packet_prefix_B=9,pow_block_B=222,per_packet_block_length_B=4,
        included_per_year=PAYMENTS,baseline=projection(packets[0]))

if __name__=='__main__':
    print(json.dumps(budget(),indent=2,sort_keys=True))
