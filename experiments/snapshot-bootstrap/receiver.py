"""A cold local validator with independent operator pin, public download socket and private data directory."""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from peer import serve


def download(port, counts, op, **params):
    from transport import frame, rpc
    meter={}
    try:
        result, body=rpc(port,op,meter=meter,**params)
        counts[op+'_B']+=len(body)
        counts[op+'_responses']+=1
        return result,body
    finally:
        for k,v in meter.items():
            counts[k]+=v


def public_status(db):
    st=db.status()
    mode=st['bootstrap']['mode']
    st['bootstrap']['historical_status']={'provisional':'historical prefix assumed',
        'full':'selected history verified from genesis','quarantined':'historical verification mismatch'}[mode]
    return st


class Receiver:
    def __init__(self, directory, backend, remote, pin):
        import chain, node, node_snapshot
        self.directory,self.backend,self.remote,self.pin=directory,backend,remote,pin
        self.chain=chain.Chain(directory/'live.sqlite',backend)
        self.candidate_count=0
        class Public(node.Node):
            def status(self):
                return public_status(self.db)
        self.wallet=Public.__new__(Public)
        self.wallet.db=self.chain

    def get_block(self,ident):
        import chain
        data=download(self.remote,self.meter,'block',id=ident)[1]
        if chain.block_id(data).hex()!=ident:
            raise ValueError('wrong historical block from peer')
        return data

    def ids(self, start, target):
        result=[]
        endpoint_height=None
        while True:
            meta,raw=download(self.remote,self.meter,'ids',target=target,start=start,limit=64)
            height=meta['height']
            if type(height) is not int or not start<=height<=65536 or len(raw)!=32*min(64,height-start+1):
                raise ValueError('incomplete branch inventory')
            if endpoint_height is not None and endpoint_height!=height:
                raise ValueError('inconsistent branch height')
            endpoint_height=height
            result.extend(raw[i:i+32].hex() for i in range(0,len(raw),32))
            start+=len(raw)//32
            if start>height:
                break
        if result[-1]!=target:
            raise ValueError('inventory endpoint')
        return result

    def replay(self, ids, chain):
        for ident in ids:
            raw=self.get_block(ident)
            chain.accept(raw)

    def dispatch(self, admin, m, body):
        from node_snapshot import (attach_history, finish_replay, import_snapshot, new_replay, pack_work,
                                   recover_fork, state_digest)
        from wire import need
        if not admin:
            if m['op']!='status' and self.chain.status()['bootstrap']['mode']=='quarantined':
                raise ValueError('quarantined snapshot')
            need(m['op'] in ('status','history_head','history_range','history_check','history_info',
                             'submit','tx','page','assets','pending','selected','block'),'unknown wallet RPC')
            return self.wallet.dispatch(m,body,False)
        op=m['op']
        if op=='status':
            return public_status(self.chain),b''
        if op=='readback':
            st=public_status(self.chain)
            entries=self.chain.public_assets(bytes(32),32,st['tip'])
            need(entries['next'] is None,'registry sample exceeded')
            return dict(status=st,registry=entries['entries'],state_sha256=state_digest(self.chain)),b''
        self.meter=Counter()
        try:
            if op=='bootstrap':
                need(self.pin is not None,'independent pin required')
                expected_size=None
                data=bytearray()
                while True:
                    meta,part=download(self.remote,self.meter,'state',offset=len(data))
                    size=meta['size']
                    need(type(size) is int and 0<size<=256*1024*1024 and 0<len(part)<=512*1024
                         and len(data)+len(part)<=size,'invalid snapshot transfer bounds')
                    need(expected_size is None or size==expected_size,'inconsistent state length')
                    expected_size=size
                    data.extend(part)
                    if len(data)==size:
                        break
                need(sha256(data).hexdigest()==self.pin['state_sha256'],'independent snapshot digest mismatch')
                base_ids=self.ids(1,self.pin['tip'])
                need(len(base_ids)==self.pin['height'],'wrong number of work preimages')
                # Download one original template per height. No caller-provided digest replaces that work.
                work=pack_work(self.get_block(ident) for ident in base_ids)
                import_snapshot(self.chain,bytes(data),work,self.pin)
                if m['target']!=self.pin['tip']:
                    self.replay(self.ids(len(base_ids)+1,m['target']),self.chain)
                need(self.chain.status()['tip']==m['target'],'snapshot target not selected')
            elif op=='advance':
                self.replay(self.ids(m['start'],m['target']),self.chain)
                need(self.chain.status()['tip']==m['target'],'target did not win fork choice')
            elif op=='attach':
                for ident in m['ids']:
                    record=download(self.remote,self.meter,'record',id=ident)[1]
                    attach_history(self.chain,bytes.fromhex(ident),record)
            elif op in ('verify','fork'):
                self.candidate_count+=1
                path=self.directory/('replay-'+str(self.candidate_count)+'.sqlite')
                # Each verification begins in an empty local database at genesis. Never accept a remote verdict.
                replica=new_replay(path,self.backend)
                try:
                    self.replay(self.ids(1,m['target']),replica)
                    need(replica.status()['tip']==m['target'],'replay candidate endpoint')
                    if op=='verify':
                        finish_replay(self.chain,replica)
                    else:
                        recover_fork(self.chain,replica)
                finally:
                    replica.close()
                    path.unlink(missing_ok=True)
            else:
                raise ValueError('unknown receiver command')
            return dict(ok=True,traffic=dict(self.meter),status=public_status(self.chain)),b''
        except (ValueError,OSError,RuntimeError) as error:
            return dict(ok=False,reason=str(error),traffic=dict(self.meter),status=public_status(self.chain)),b''


if __name__=='__main__':
    import os
    os.umask(0o077)
    deployment,store,remote,pin,public,control=map(Path,sys.argv[1:7])
    sys.path.insert(0,str(deployment/'devnet'))
    import chain, runtime
    from run import Resources
    services=Resources(runtime.config(deployment/'runtime'))
    try:
        instance=Receiver(store,services.backend,remote,json.loads(pin.read_bytes()) if pin.is_file() else None)
        try:
            serve([(public,False),(control,True)],instance.dispatch)
        finally:
            instance.chain.close()
    finally:
        services.close()
