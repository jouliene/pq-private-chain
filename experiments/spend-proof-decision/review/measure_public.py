"""Measure fresh and warmed verification from complete public transfer and swap artifacts."""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from statistics import median
import struct
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location("swp1_accounting",ROOT/"experiments/atomic-swap/measure.py")
accounting=importlib.util.module_from_spec(spec)
spec.loader.exec_module(accounting)
sys.path.insert(0,str(ROOT/'experiments/advancing-payments'))
from wire import Role

NET=bytes.fromhex('7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac')
BASE_KEYS=('1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d','0527447637fa2f34d9585606501c4a55883c0ceaf58adb2d3e9834c66ab19837')
GOLDILOCKS=(1<<64)-(1<<32)+1


@dataclass(frozen=True)
class Collection:
    network: bytes
    ordinary: bytes
    ordinary_inner: bytes
    swap: bytes
    frame: bytes
    swap_inner: bytes
    authorization_domain: bytes


BASELINE=Collection(NET,b'MSP1',b'MNG1',b'SWB1',b'SWF1',b'SLG1',b'SWP1/joint-authorization/v1\0')
K384=Collection(sha256(b'K384/isolated-network/v1').digest(),b'K3P1',b'K3M1',b'K3B1',b'K3F1',b'K3L1',
                b'K384/joint-authorization/v1\0')


def hash_bytes(b):
    return sha256(b).digest()


def effect(role,leg,magic,fee,swap):
    assert leg[:5]==magic+b'\x01' and int.from_bytes(leg[5:9],'little')==len(leg)-3593
    width=34 if swap else 31
    tail=len(leg)-3584
    size,*words=struct.unpack_from('<'+str(width+1)+'Q',leg,tail-8*(width+1))
    assert size==width and all(w<GOLDILOCKS for w in words) and words[4]<1<<32 and words[21]==fee
    pi=leg[tail-width*8:tail]
    key=struct.pack('<8I',*words[26:]) if swap else None
    assert swap or words[26:]==[0]*5
    expected=b'1'+pi[:36]+pi[40:176]+leg[tail:]+(key if swap else bytes(40))
    assert role.call(leg)==expected
    return key,(pi[40:72],pi[72:104]),(pi[104:136],pi[136:168])


def frames(raw,suite):
    assert raw[:5]==suite.swap+b'\x01'
    pos=5
    parts=[]
    for _ in range(2):
        size,=struct.unpack_from('<I',raw,pos)
        pos+=4
        assert 17195<size<=len(raw)-pos
        parts.append(raw[pos:pos+size])
        pos+=size
    assert pos==len(raw)
    return parts


def check_public(role,raw,kind,suite,height):
    if kind=='ordinary':
        assert raw[:6]==suite.ordinary+b'\x01\x00'
        _,nfs,cms=effect(role,raw[6:],suite.ordinary_inner,3,False)
        assert len(set(nfs))==len(set(cms))==2 and bytes(32) not in cms
        return
    a,b=frames(raw,suite)
    assert all(f[:5]==suite.frame+b'\x01' and f[11:43]==suite.network for f in (a,b))
    assert a[5]==0 and b[5]==1 and a[6:75]==b[6:75]
    payer=a[6]
    expiry,=struct.unpack_from('<I',a,7)
    terms=a[43:75]
    assert 0<height<=expiry and terms!=bytes(32) and payer in (0,1)
    legs=a[17195:],b[17195:]
    h=[hash_bytes(l) for l in legs]
    assert a[75:107]==h[1] and b[75:107]==h[0]
    statement=hash_bytes(suite.authorization_domain+suite.network+terms+struct.pack('<IB',expiry,payer)+b''.join(h))
    keys=[]; nfs=[]; cms=[]
    for i,f in enumerate((a,b)):
        key,n,c=effect(role,legs[i],suite.swap_inner,3 if i==payer else 0,True)
        assert role.call(b'V'+key+statement+f[107:17195])==b'1'
        keys.append(key);nfs.extend(n);cms.extend(c)
    assert len(set(keys))==2 and len(set(nfs))==len(set(cms))==4 and bytes(32) not in cms


def session(binary,approve,keys,raw,kind,suite,height,count):
    wall=time.perf_counter(); cpu=time.process_time(); reaped=accounting.children_cpu()
    role=Role(binary,approve,['verify','/keys'],keys)
    helpers_cpu=accounting.children_cpu()-reaped
    start_rows=[]
    try:
        for _ in range(count):
            before=list(role.sizes)
            p=time.process_time();t=time.perf_counter()
            check_public(role,raw,kind,suite,height)
            end=time.perf_counter()
            start_rows.append(dict(check_wall_s=end-t,elapsed_from_launch_s=end-wall,
                                   host_cpu_s=time.process_time()-p,
                                   ipc_input_B=role.sizes[0]-before[0],ipc_reply_B=role.sizes[1]-before[1]))
        parent_to_verdict=time.process_time()-cpu
        tree,hz=accounting.live_cpu(role.proc.pid)
        meters=role.close()
    finally:
        role.abort()
    n=1 if kind=='ordinary' else 4
    assert [m['operation'] for m in meters]==['verifier_setup']+['public_verify']*(n*count)
    for i,row in enumerate(start_rows):
        native=meters[1+i*n:1+(i+1)*n]
        row['native_cpu_s']=sum(x['cpu_s'] for x in native)
        row['host_plus_native_cpu_s']=row['host_cpu_s']+row['native_cpu_s']
        row['native_peak_KiB']=max(x['peak_rss_kib'] for x in native)
        row['native_checks']=native
    return dict(calls=start_rows,setup=meters[0],through_shutdown_wall_s=time.perf_counter()-wall,
                observed_process_cpu_to_last_verdict_s=parent_to_verdict+helpers_cpu+sum(x['cpu_s'] for x in tree),
                observed_cpu_tick_s=1/hz,live_process_cpu_to_last_verdict=tree)


def run(args):
    result={}
    suite=BASELINE if args.profile=='baseline' else K384
    vk_pins=BASE_KEYS if suite==BASELINE else (args.ordinary_vk_sha,args.swap_vk_sha)
    assert all(pin and len(pin)==64 for pin in vk_pins)
    for kind,digest in zip(('ordinary','swap'),vk_pins,strict=True):
        raw=getattr(args,kind).read_bytes()
        binary=getattr(args,kind+'_binary')
        key=getattr(args,kind+'_key')
        approved=getattr(args,kind+'_sha')
        assert sha256(key.read_bytes()).hexdigest()==digest and sha256(binary.read_bytes()).hexdigest()==approved
        assert key.name==('managed.vk' if kind=='ordinary' else 'swap.vk')
        section=(raw[6:],) if kind=='ordinary' else tuple(f[17195:] for f in frames(raw,suite))
        physical=[raw] if kind=='ordinary' else frames(raw,suite)
        live_size=all(len(f)<=262144 for f in physical)
        if suite==BASELINE:
            assert live_size
        else:
            assert all(len(f)<=2**21 for f in physical)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/key.name).write_bytes(key.read_bytes())
            def trial(n):return session(binary,approved,tmp,raw,kind,suite,args.inclusion_height,n)
            cold=[trial(1) for _ in range(3)]
            warm=trial(6)
        samples=warm['calls'][1:]
        summary=dict(cold_processes=len(cold),cold_to_verdict_wall_s=median(s['calls'][0]['elapsed_from_launch_s'] for s in cold),
                     cold_native_process_peak_KiB=max(max(s['calls'][0]['native_peak_KiB'],s['setup']['peak_rss_kib']) for s in cold),
                     cold_observed_cpu_to_verdict_s=median(s['observed_process_cpu_to_last_verdict_s'] for s in cold),
                     warm_checks=len(samples),warm_check_wall_s=median(s['check_wall_s'] for s in samples),
                     warm_check_cpu_s=median(s['host_plus_native_cpu_s'] for s in samples),
                     warm_native_peak_KiB=max(s['native_peak_KiB'] for s in samples))
        result[kind]=dict(packet_sha256=sha256(raw).hexdigest(),binary_sha256=approved,verifier_key_sha256=digest,
                          existing_per_frame_limit_B=262144,within_existing_per_frame_limit=live_size,
                          verifier_profile=args.profile,network=suite.network.hex(),whole_public_submission_B=len(raw),physical_frame_B=list(map(len,physical)),
                          proof_B=[len(l)-3593 for l in section],receipts_B=3584*len(section),
                          final_authorizations_B=(0 if kind=='ordinary' else 2*17088),
                          block_incremental_B=sum(map(len,physical))+4*len(physical),summary=summary,cold=cold,warm=warm)
    return result


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('ordinary','swap'):
        for s in ('','-binary','-key'):p.add_argument('--'+k+s,required=True,type=Path)
        p.add_argument('--'+k+'-sha',required=True)
    p.add_argument('--profile',choices=['baseline','k384'],default='baseline')
    p.add_argument('--ordinary-vk-sha',help='independently approved candidate ordinary registration')
    p.add_argument('--swap-vk-sha',help='independently approved candidate leg registration')
    p.add_argument('--inclusion-height',required=True,type=int)
    print(json.dumps(run(p.parse_args()),sort_keys=True,indent=2))
