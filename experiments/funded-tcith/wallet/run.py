"""Build and sign matched mixed and released proof pairs from disposable local funding."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
EX = HERE.parents[1]
sys.path[:0] = [str(HERE), str(EX/'funded-whir/wallet')]
from fixtures import commitment, exchange, need, swap_policy
import ftl_wire as wire
from subtree import OwnerMeter
from funded_projection import pivot

NAMES = ('alice','bob')


def launch(a, owner, temp, peers):
    output = temp/owner
    output.mkdir(mode=0o700)
    mounts = {a.home/'owner-backups'/owner/'seed':'/owner/seed', peers:'/peers', a.home/'deployment':'/deploy',
              a.home/'public/blocks':'/origin/public/blocks', a.output:'/exchange', a.capture/'leg/native':'/capture/native',
              a.constants:'/constants.rs', a.engine:'/engine', a.shape:'/shape'}
    for rel in ('funded-tcith/wallet', 'funded-whir/wallet', 'funded-whir/relation','spend-proof-decision/whir_port.py',
                'atomic-swap/wallet','atomic-swap/swap_wire.py','packed-tcith/encoding','lattice-spend/pivot'):
        mounts[EX/rel] = '/src/experiments/'+rel
    for system in ('/usr','/lib','/lib64','/bin','/etc/ld.so.cache'):
        mounts[Path(system)] = system
    cmd = ['bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--clearenv',
           '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C','--setenv','RAYON_NUM_THREADS','2',
           '--proc','/proc','--dev','/dev','--tmpfs','/tmp']
    for src,dest in mounts.items():
        cmd += ['--ro-bind', str(src.resolve(strict=True)), dest]
    cmd += ['--bind', str(output), '/own','--remount-ro','/','--chdir','/','--','/usr/bin/python3','-IB',
            '/src/experiments/funded-tcith/wallet/owner.py', owner]
    return subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)


def stop(worker):
    if worker.poll() is None:
        worker.kill()
    worker.wait()
    worker.stdin.close()
    worker.stdout.close()


def write_json(path, data):
    path.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')


def run(a):
    for key, path in vars(a).items():
        setattr(a,key,path.resolve(strict=key != 'output'))
    sys.path.insert(0,str(a.home/'deployment/devnet'))
    import chain
    sw = swap_policy()
    lab = json.loads((a.home/'public/RUN.json').read_text())
    head = lab['tips']['common']
    asset = bytes.fromhex(lab['asset_ids']['managed'])
    tip = bytes.fromhex(head['tip'])
    expiry = head['height'] + 4
    roster = {owner:(a.home/'wallets'/owner/'address').read_bytes() for owner in NAMES}
    salt = secrets.token_bytes(32)
    terms = commitment(chain.NETWORK,asset,expiry,salt,roster)
    need(sha256((a.capture/'leg/native').read_bytes()).hexdigest() ==
         json.loads((a.capture/'leg/BUILD.json').read_text())['binary_sha256'], 'capture installation differs')
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    source = dict(common=head, network=chain.NETWORK.hex(), terms=terms.hex(), expiry=expiry, payer=1, profiles={},
                  disposable_fixture_agreement=dict(token_asset=asset.hex(),token_paid_by='a',token_quantity=20,
                      native_paid_by='b',native_quantity=8,fee_paid_by='b',fee=3),
                  shape_sha256=sha256(a.shape.read_bytes()).hexdigest(),engine_sha256=sha256(a.engine.read_bytes()).hexdigest())
    write_json(a.output/'SOURCE.json', source)
    with ExitStack() as stack:
        temp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='ftl-owners-')))
        peers = temp/'peers'
        peers.mkdir(mode=0o700)
        for name, address in roster.items():
            (peers/name).write_bytes(address)
        (peers/'managed_asset').write_bytes(asset)
        (peers/'funded_tip').write_bytes(tip)
        workers = {}
        meters = {}
        for owner,label in zip(NAMES,('a','b'),strict=True):
            launched = time.monotonic_ns()
            worker = workers[owner] = launch(a,owner,temp,peers)
            stack.callback(stop,worker)
            meters[owner] = OwnerMeter(worker.pid, launched)
            stack.callback(meters[owner].close)
            exchange(worker,salt.hex(),'prepared')
            shutil.copyfile(temp/owner/'released.leg',a.output/('leg-'+label+'.released'))
            if label == 'a':
                shutil.copyfile(temp/owner/'candidate.leg',a.output/'leg-a.candidate')
        for owner in NAMES:
            exchange(workers[owner],'authorize','signed')
            need(workers[owner].wait(timeout=30) == 0,'single-seed owner failed after authorization')
            end_ns = time.monotonic_ns()
            lines = [line.split() for line in (temp/owner/'phases').read_text().splitlines()]
            expected = (['candidate_frontend','candidate_prove','candidate_done'] if owner == 'alice' else [])
            expected += ['waiting','authorization','teardown']
            need([label for label,_ in lines] == expected, 'unexpected owner timing metadata')
            stamps = {label:int(ts) for label,ts in lines}
            source['profiles'][owner] = json.loads((temp/owner/'metrics.json').read_text())
            source['profiles'][owner]['owner_tree'] = meters[owner].result(stamps,end_ns)
        released = [(a.output/('leg-'+label+'.released')).read_bytes() for label in ('a','b')]
        mixed = [(a.output/'leg-a.candidate').read_bytes(),released[1]]
        roots = {m['aux_root'] for m in source['profiles'].values()}
        need(len(roots) == 1 and all(m['leaf_count'] == head['notes'] for m in source['profiles'].values()),
             'independently replayed owner branch views differ')
        source['aux_root'] = roots.pop()
        signed_bundles = {}
        for label, legs in (('released',released),('mixed',mixed)):
            signatures = [(temp/owner/(label+'.signature')).read_bytes() for owner in NAMES]
            encode = wire.sw.assemble if label=='released' else wire.assemble
            signed_bundles[label] = encode(chain.NETWORK,terms,expiry,1,legs,signatures)
        ref_frames = wire.sw.pair(wire.sw.split(signed_bundles['released']))
        params = pivot.f.constants(a.constants)
        with sw.actor('verify') as public:
            frames, effects = wire.validate_pair(signed_bundles['mixed'],a.engine,a.shape,chain.NETWORK,head['height']+1,
                    tip,head['notes'],bytes.fromhex(source['aux_root']),params,public)
            release_digest = wire.sw.digest(chain.NETWORK,terms,expiry,1,released)
            mixed_digest = wire.sw.digest(chain.NETWORK,terms,expiry,1,mixed)
            need(release_digest != mixed_digest, 'released and candidate digest collision')
            for frame,e,m in zip(ref_frames,effects,frames,strict=True):
                need(sw.verify(public,frame.leg) == e and public.call(b'V'+e.public+release_digest+frame.signature)==b'1'
                     and public.call(b'V'+e.public+mixed_digest+frame.signature)==b'0'
                     and public.call(b'V'+e.public+release_digest+m.signature)==b'0', 'baseline proof, effects or signatures differ')
        for label, raw in signed_bundles.items():
            (a.output/(label+'.swap')).write_bytes(raw)
        blocks = a.output/'blocks'
        blocks.mkdir()
        cursor = tip
        while cursor != chain.GENESIS:
            path = a.home/'public/blocks'/(cursor.hex()+'.bin')
            raw = path.read_bytes()
            need(chain.block_id(raw) == cursor, 'public branch archive encoding differs')
            (blocks/path.name).write_bytes(raw)
            cursor = chain.decode_block(raw).parent
        need(len(list(blocks.iterdir())) == head['height'], 'public branch archive incomplete')
        source['complete'] = True
        source['swapped_registration_signatures_rejected'] = True
        write_json(a.output/'SOURCE.json',source)


if __name__ == '__main__':
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('home','capture','constants','engine','shape','output'):
        parser.add_argument(key,type=Path)
    run(parser.parse_args())
