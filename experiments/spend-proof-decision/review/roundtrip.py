"""Independently check three compact public proof round trips and unchanged signed economics."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from measure_public import K384, check_public, frames
from inspect_public import validate
from wire import Role


def invoke(codec,operation,key,source,dest):
    # Capture per-child RSS for each mode instead of measuring a cumulative maximum across trials.
    metrics=dest.with_suffix('.'+operation+'.time')
    t=time.perf_counter()
    subprocess.run(['/usr/bin/time','-o',metrics,'-f','%U %S %M %x',codec,operation,key,source,dest],
                   check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,timeout=180)
    elapsed=time.perf_counter()-t
    user,system,rss,code=metrics.read_text().split()
    assert int(code)==0
    return dict(wall_s=elapsed,cpu_s=float(user)+float(system),peak_process_KiB=int(rss))


def job(a):
    a.destination.mkdir(exist_ok=False,mode=0o700)
    ordinary=(a.public/'ordinary.bin').read_bytes()
    swap=(a.public/'swap.bin').read_bytes()
    physical=frames(swap,K384)
    proof_frames=[ordinary[6:],physical[0][17195:],physical[1][17195:]]
    registered=json.loads((a.build/'ordinary/BUILD.json').read_bytes()),json.loads((a.build/'leg/BUILD.json').read_bytes())
    files=[a.build/'ordinary/registered/managed.vk',a.build/'leg/registered/swap.vk']
    pins=[a.ordinary_vk_sha,a.swap_vk_sha]
    assert all(sha256(k.read_bytes()).hexdigest()==pin for k,pin in zip(files,pins,strict=True))
    assert sha256(a.codec.read_bytes()).hexdigest()==a.codec_sha
    rows=[]; expanded=[]; compressed=[]
    for label,packet in zip(('ordinary','leg_a','leg_b'),proof_frames,strict=True):
        key=files[0 if label=='ordinary' else 1]
        body=packet[9:-3584]
        assert len(body)==int.from_bytes(packet[5:9],'little')
        initial=a.destination/(label+'.full')
        small=a.destination/(label+'.compact')
        decoded=a.destination/(label+'.decoded')
        initial.write_bytes(body)
        enc=invoke(a.codec,'encode',key,initial,small)
        dec=invoke(a.codec,'decode',key,small,decoded)
        reproduced=decoded.read_bytes()
        assert body==reproduced and 0<small.stat().st_size<=len(body)
        bytes_in_frame=len(ordinary if label=='ordinary' else physical[0 if label=='leg_a' else 1])
        compact_frame=bytes_in_frame-len(body)+small.stat().st_size
        expanded.append(packet[:5]+struct.pack('<I',len(reproduced))+reproduced+packet[-3584:])
        small_body=small.read_bytes()
        compressed.append(b'KC'+packet[2:5]+struct.pack('<I',len(small_body))+small_body+packet[-3584:])
        rows.append(dict(which=label,full_proof_sha256=sha256(body).hexdigest(),compact_sha256=sha256(small.read_bytes()).hexdigest(),
                         full_proof_B=len(body),compact_proof_B=small.stat().st_size,
                         compact_B_with_all_existing_frame_fields=compact_frame,
                         within_live_262144_size=compact_frame<=262144,encode_and_verify=enc,decode_and_verify=dec))
    small_ordinary=b'KC'+ordinary[2:6]+compressed[0]
    small_frames=[b'KC'+physical[i][2:17195]+compressed[i+1] for i in range(2)]
    small_swap=b'KCB1\x01'+b''.join(struct.pack('<I',len(f))+f for f in small_frames)
    assert [len(small_ordinary),*map(len,small_frames)]==[row['compact_B_with_all_existing_frame_fields'] for row in rows]
    (a.destination/'ordinary.compact').write_bytes(small_ordinary)
    (a.destination/'swap.compact').write_bytes(small_swap)
    output=ordinary[:6]+expanded[0]
    rebuilt=[physical[i][:17195]+expanded[i+1] for i in range(2)]
    complete_swap=swap[:5]+b''.join(struct.pack('<I',len(f))+f for f in rebuilt)
    assert (output,complete_swap)==(ordinary,swap)
    for i,(kind,raw) in enumerate((('ordinary',output),('swap',complete_swap))):
        binary=a.build/('ordinary','leg')[i]/'native'
        approved=registered[i]['binary_sha256']
        assert sha256(binary.read_bytes()).hexdigest()==approved
        role=Role(binary,approved,['verify','/keys'],files[i].parent)
        try:
            check_public(role,raw,kind,K384,1)
            role.close()
        finally:
            role.abort()
    confirm=validate(output,complete_swap,'k384',a.roots,a.node)
    return dict(compact_binary_sha256=a.codec_sha,proofs=rows,public_reconstructed_ordinary_sha256=sha256(output).hexdigest(),
                public_reconstructed_swap_sha256=sha256(complete_swap).hexdigest(),reconstructed_bytes_match=True,
                complete_expanded_payments_passed_registered_verifiers=True,independent_signatures_and_receipts=confirm,
                compact_ordinary_all_existing_fields_B=rows[0]['compact_B_with_all_existing_frame_fields'],
                compact_joint_all_existing_fields_B=len(small_swap),actual_compact_sha256=[sha256(x).hexdigest() for x in (small_ordinary,small_swap)])


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('public','build','codec','destination','roots','node'):p.add_argument(n,type=lambda s:Path(s).resolve())
    for n in ('ordinary-vk-sha','swap-vk-sha','codec-sha'):p.add_argument('--'+n,required=True)
    a=p.parse_args();print(json.dumps(job(a),indent=2,sort_keys=True))
