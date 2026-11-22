"""Bounded read-only public fixture service using the existing local peer framing."""
from collections import Counter
from pathlib import Path
import json
import re
import selectors
import socket


def serve(endpoints, handler):
    from transport import frame, length, unpack
    with selectors.DefaultSelector() as watchers:
        listeners = []
        try:
            for path, admin in endpoints:
                path.unlink(missing_ok=True)
                listener = socket.socket(socket.AF_UNIX)
                listeners.append(listener)
                listener.bind(str(path))
                listener.listen(10)
                watchers.register(listener, selectors.EVENT_READ, admin)
            while True:
                for key, _ in watchers.select():
                    conn, _ = key.fileobj.accept()
                    with conn:
                        conn.settimeout(120)
                        meta = {}
                        with conn.makefile('rb') as stream:
                            header = stream.read(4)
                            if not header:
                                continue
                            try:
                                size = length(header)
                                data = stream.read(size)
                                if len(data) != size:
                                    raise ValueError('short request')
                                meta, payload = unpack(data)
                                if key.data and meta == {'op':'stop'} and not payload:
                                    conn.sendall(frame({'ok': True,'result':{}}))
                                    return
                                result, body = handler(key.data,meta,payload)
                                response = frame({'ok':True,'result':result},body)
                            except (ValueError, KeyError, TypeError, OSError, RuntimeError) as error:
                                response = frame({'ok':False,'error':str(error)[:200]})
                            conn.sendall(response)
        finally:
            for sock in listeners:
                sock.close()
            for path, _ in endpoints:
                path.unlink(missing_ok=True)


class PublicFiles:
    def __init__(self, fixture):
        self.fixture = fixture
        self.fault = {}
        self.counts = Counter()

    def __call__(self,admin,m,body):
        if body:
            raise ValueError('public reader accepts no request body')
        if admin and m['op']=='fault':
            self.fault = m['fault']
            return {},b''
        if admin and m['op']=='status':
            return dict(self.counts),b''
        op = m['op']
        if op=='state' and set(m)=={'op','offset'}:
            start=m['offset']
            if type(start) is not int or not 0<=start<=256*1024*1024:
                raise ValueError('invalid slice')
            file=self.fixture/'state.bin'
            size=file.stat().st_size
            if start>=size:
                raise ValueError('outside state payload')
            with file.open('rb') as stream:
                stream.seek(start)
                data=stream.read(512*1024)
            result={'size':size}
        elif op=='ids' and set(m)=={'op','target','start','limit'}:
            case=json.loads((self.fixture/'case.json').read_bytes())
            start,limit=m['start'],m['limit']
            if type(start) is not int or type(limit) is not int or start<1 or not 1<=limit<=64:
                raise ValueError('bad inventory range')
            for branch in (case['first_main'],case.get('main',[]),case.get('fork',[])):
                if m['target'] in branch:
                    end=branch.index(m['target'])+1
                    result={'height':end}
                    data=b''.join(bytes.fromhex(b) for b in branch[start-1:min(start-1+limit,end)])
                    break
            else:
                raise ValueError('unavailable public branch')
        elif op in ('block','record') and set(m)=={'op','id'} and re.fullmatch('[a-f0-9]{64}',m['id']):
            name='blocks' if op=='block' else 'records'
            path=self.fixture/name/(m['id']+'.bin')
            if not path.is_file() or self.fault=={'op':op,'id':m['id'],'mode':'gap'}:
                raise ValueError('public '+op+' unavailable')
            data=path.read_bytes()
            result={}
        else:
            raise ValueError('unknown public range')
        if self.fault.get('op')==op and self.fault.get('mode')=='corrupt' and self.fault.get('id')==m.get('id'):
            data=data[:-1]+bytes([data[-1]^1])
        self.counts[op+'_B']+=len(data)
        self.counts[op+'_requests']+=1
        return result,data


if __name__=='__main__':
    import sys
    sys.path.insert(0,sys.argv[1]+'/devnet')
    public,control=map(Path,sys.argv[3:5])
    serve([(public,False),(control,True)],PublicFiles(Path(sys.argv[2])))
