"""Measure full selected AST1 wallet packets with a fresh verifier-only process for each partial payment."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'advancing-payments'))
from wire import Role


def measure(public, binary, approved, keys):
    run = json.loads((public/'RUN.json').read_bytes())
    vk = (HERE/'native/registry/asset.vk').read_bytes()
    if (keys/'asset.vk').read_bytes()!=vk or sha256(vk).hexdigest()!=run['vk']:
        raise ValueError('shared key mismatch')
    records = {}
    for name in ('spend-a','spend-b'):
        info = run['payments'][name]
        packet = (public/'packets'/(info['tx']+'.bin')).read_bytes()
        proof_b = int.from_bytes(packet[5:9],'little')
        if (sha256(packet).hexdigest()!=info['tx'] or packet[:5]!=b'AST1\x01'
                or len(packet)!=info['packet_B'] or len(packet)!=9+proof_b+3584):
            raise ValueError('incomplete public packet')
        verifier = Role(binary,approved,['verify','/keys'],keys)
        try:
            for _ in range(3):
                reply = verifier.call(packet)
                if (len(reply)!=1+172+3584+40 or reply[:1]!=b'1' or reply[173:-40]!=packet[-3584:]
                        or reply[-40:]!=bytes(40)):
                    raise ValueError('public transfer verification failure')
            meters = verifier.close()
        finally:
            verifier.abort()
        verify = [m for m in meters if m['operation']=='public_verify']
        if len(verify)!=3:
            raise ValueError('missing full native verifier meters')
        records[name] = dict(proof_B=proof_b,receipts_B=3584,frame_B=9,packet_B=len(packet),
                             block_length_prefix_B=4,real_inputs=info['real_inputs'],outputs=info['output_count'],
                             native_sent=info['amount'],token_sent=info['token_amount'],fee=info['fee'],
                             native_change=info['change'],token_change=info['token_change'],
                             wallet_call_cpu_s=info['prover_cpu_s'],wallet_call_wall_s=info['proving_wall_s'],
                             wallet_role_peak_rss_KiB=info['prover_role_peak_rss_KiB'],
                             native_wallet_meters=info.get('wallet_native_meters',[]),
                             public_verify_median_cpu_s=statistics.median(m['cpu_s'] for m in verify),
                             verifier_meters=meters)
    return dict(shared_vk_sha256=sha256(vk).hexdigest(),measurements=records)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('public','binary','keys'):
        p.add_argument('--'+n,type=lambda v:Path(v).resolve(),required=True)
    p.add_argument('--approve-binary',required=True)
    a=p.parse_args()
    print(json.dumps(measure(a.public,a.binary,a.approve_binary,a.keys),indent=2,sort_keys=True))
