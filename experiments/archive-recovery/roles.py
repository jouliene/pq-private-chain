"""Host-side process lifecycle, public transport meters and per-role storage accounting."""
import json
from pathlib import Path
import socket
import sqlite3
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import isolation
sys.path.insert(0, str(HERE.parents[1] / 'devnet'))
import transport

# The server may verify a whole historical branch or perform real CPU mining in
# an administrative request. Public daemon-to-daemon transport keeps its own bound.
def call(addr, op, body=b'', **fields):
    family = socket.AF_INET if type(addr) is int else socket.AF_UNIX
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(900 if family == socket.AF_UNIX else 30)
        s.connect(('127.0.0.1', addr) if family == socket.AF_INET else str(addr))
        s.sendall(transport.frame(dict(op=op, **fields), body))
        with s.makefile('rb') as stream:
            hdr = stream.read(4)
            size = transport.length(hdr)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError('truncated RPC result')
            meta, payload = transport.unpack(data)
        if not meta['ok']:
            raise ValueError(meta['error'])
        return meta['result'], payload


def disk(directory, dbfile=None):
    files = [p for p in directory.rglob('*') if p.is_file()]
    evidence = [p for p in files if p.name in ('peer.jsonl','daemon.log')]
    data = set(files)-set(evidence)
    sizes = dict(logical_B=sum(p.stat().st_size for p in data),
                 allocated_B=sum(p.stat().st_blocks*512 for p in data),
                 observation_logs_B=sum(p.stat().st_size for p in evidence),
                 file_count=len(data))
    if dbfile:
        import contextlib
        with contextlib.closing(sqlite3.connect((directory/dbfile).resolve().as_uri()+'?mode=ro', uri=True)) as db:
            sizes.update(page_B=db.execute('pragma page_size').fetchone()[0],
                         table_and_index_B=dict(db.execute('select name,sum(pgsize) from dbstat group by name')),
                         original_body_B=db.execute('select sum(length(raw)) from blocks').fetchone()[0],
                         original_body_count=db.execute('select count(*) from blocks where length(raw)>0').fetchone()[0],
                         common_history_B=db.execute('select sum(length(record)) from wallet_history_v2').fetchone()[0])
    return sizes


def save(path, obj):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj, sort_keys=True, indent=2)+'\n')
    tmp.replace(path)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Role:
    def __init__(self, deployment, store, archive_ports=()):
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.store, self.port, self.control = store, free_port(), store/'control.sock'
        if archive_ports:
            argv = ['/code/node.py', '--deployment', '/deployment', '--store', '/store/home.sqlite',
                    '--window','3','--port',str(self.port),'--control','/store/control.sock',
                    '--archives',*map(str,archive_ports)]
        else:
            argv = ['/code/archive.py','--deployment','/deployment','--store','/store','--port',str(self.port)]
        self.process = isolation.start(deployment, argv, [(store,'/store',True)],store/'daemon.log',True)
        for _ in range(300):
            if self.process.poll() is not None:
                raise RuntimeError('daemon startup failed: '+str(store/'daemon.log'))
            try:
                self.rpc('status')
                return
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(.1)
        raise TimeoutError('daemon startup: '+str(store))
    def rpc(self, op, **fields):
        return call(self.control,op,**fields)[0]
    def stop(self):
        if self.process.poll() is None:
            try:
                self.rpc('stop')
            finally:
                self.process.wait(timeout=60)
