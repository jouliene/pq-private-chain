"""Create one fresh typed payment or replay its intact public proof in an isolated verifier."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0,str(ROOT/'experiments/advancing-payments'))
from wire import CT, Role, digest, need, u32, u64

VK='74fa3fb56350de946797b7b68e925ae2193efe6b0257ad62e474225d650cd68c'


def run(runtime,baseline,directory,replay):
    def role(rt,mode,priv=None):
        manifest=json.loads((rt/'BUILD.json').read_bytes())
        keydir=rt/'registered'
        args={'wallet':['wallet','/keys','/private/seed','create'],'hash':['hash'],'verify':['verify','/keys']}[mode]
        obj=Role(rt/'native',manifest['binary_sha256'],args,keydir if mode!='hash' else None,priv)
        stack.callback(obj.abort)
        return obj
    need(sha256((runtime/'registered/token.vk').read_bytes()).hexdigest()==VK,'registered comparison key')
    with ExitStack() as stack:
        if not replay:
            directory.mkdir(exist_ok=False,parents=True)
            temp=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='tkq1-',dir='/dev/shm')))
            for name in ['payer','recipient']:
                (temp/name).mkdir(mode=0o700)
            payer=role(runtime,'wallet',temp/'payer'); payee=role(runtime,'wallet',temp/'recipient')
            a,b=payer.get(),payee.get()
            need(len(a)==len(b)==1601 and a!=b,'fresh independent public addresses')
            hashes=role(runtime,'hash')
            genesis=b''
            for i,(n,t) in enumerate(((30,50),(60,70))):
                context=sha256(b'TKQ1/fixture-origin\0'+bytes.fromhex(VK)+u32(i)).digest()
                row=context+a[1:33]+u64(n)+u64(t)
                genesis+=row+hashes.call(b'C'+row)
            leaves=genesis[80:112]+genesis[192:224]
            header=bytes(36)+digest(b'TKQ1/state',genesis)+digest(b'TKQ1/body',genesis)+hashes.call(b'R'+leaves)
            inventory=payer.call(b'S',header,genesis,b'',b'')
            need(len(inventory)==44 and inventory[:4]==b'SCAN','two owned real inputs')
            packet=payer.call(b'P'+bytes([2])+u64(12)+u64(17)+b)
            need(packet[:5]==b'TKQ1\1','fresh proof')
            (directory/'payment.bin').write_bytes(packet)
        else:
            packet=(directory/'payment.bin').read_bytes()
        public=role(runtime,'verify')
        own=public.call(packet)
        need(len(own)==3757 and own[0:1]==b'1' and own[-2*CT:]==packet[-2*CT:],'native independent verification')
        base_packet=(ROOT/'experiments/token-profile/candidate/evidence/blocks/1.bin').read_bytes()[176:-8]
        need(base_packet[:5]==b'TKN1\1','baseline complete payment')
        need(public.call(b'TKQ1'+base_packet[4:])==b'0','wrong inner relation key')
        base=role(baseline,'verify')
        need(base.call(base_packet)[:1]==b'1' and base.call(b'TKN1'+packet[4:])==b'0','baseline positive and cross-key refusal')
        report={'vk_sha256':VK,'packet_sha256':sha256(packet).hexdigest(),'proof_B':len(packet)-9-2*CT,
                'packet_B':len(packet),'receipts_B':2*CT,'both_public_cross_key_rejections':True,
                'new_verifier_meters':public.close(),'reference_verifier_meters':base.close()}
        if not replay:
            effects=own[1:]; nfs=effects[36:100]; cms=effects[100:164]
            need(effects[:32]==hashes.call(b'H'+header) and effects[32:36]==u32(0) and effects[164:172]==u64(3),'statement at funded root')
            child=effects[:32]+u32(1)+digest(b'TKQ1/state',header,packet)+digest(b'TKQ1/body',packet)+hashes.call(b'R'+leaves+cms)
            rows=cms[:32]+packet[-2*CT:-CT]+cms[32:]+packet[-CT:]
            def received(actor,n,t):
                got=actor.call(b'S',child,genesis,rows,nfs)
                return len(got)==24 and got[:4]==b'SCAN' and got[8:]==u64(n)+u64(t)
            need(received(payee,12,17) and received(payer,75,103),'independent receiver and exact two-lane change')
            report.update(positive_two_lane_receipt_and_change=True,real_inputs=2,
                          proving_call_wall_s=payer.times[1],payer_meters=payer.close())
        return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('runtime',type=Path); p.add_argument('baseline',type=Path); p.add_argument('public',type=Path)
    p.add_argument('--replay',action='store_true'); args=p.parse_args()
    print(json.dumps(run(args.runtime.resolve(),args.baseline.resolve(),args.public.resolve(),args.replay),indent=2,sort_keys=True))
