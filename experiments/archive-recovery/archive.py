"""Full A/B archive using the registered chain and the released peer framing."""
import argparse
import json
from pathlib import Path
import selectors
import socket
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--deployment', type=Path, required=True)
    p.add_argument('--store', type=Path, required=True)
    p.add_argument('--port', type=int, required=True)
    args = p.parse_args()
    sys.path.insert(0, str(args.deployment / 'devnet'))
    import chain
    import runtime
    import node
    from transport import frame, length, rpc, unpack
    from run import Resources
    resources = Resources(runtime.config(args.deployment / 'runtime'))
    db = chain.Chain(args.store / 'archive.sqlite', resources.backend)
    # The public dispatch path is the original daemon's validation/history interface.
    class Archive(node.Node):
        def status(self):
            return self.db.status()
    service = Archive.__new__(Archive)
    service.db = db
    denied = set()
    trace = (args.store / 'peer.jsonl').open('a', buffering=1)
    path = args.store / 'control.sock'
    path.unlink(missing_ok=True)
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(('127.0.0.1', args.port))
    unix = socket.socket(socket.AF_UNIX)
    unix.bind(str(path))
    wallet_path = path.with_name('wallet.sock')
    wallet_path.unlink(missing_ok=True)
    local_public = socket.socket(socket.AF_UNIX)
    local_public.bind(str(wallet_path))
    running = True

    def fetch(port, stop):
        meter = {}
        remote = rpc(port, 'status', meter=meter)[0]
        if remote['network'] != chain.NETWORK.hex():
            raise ValueError('foreign archive')
        height = remote['height'] if stop is None else stop
        if not 0 <= height <= remote['height']:
            raise ValueError('requested height outside selected history')
        counts = {'blocks': 0, 'body_B': 0, 'request_B': meter['request_B'], 'reply_B': meter['reply_B']}
        def read(op, **params):
            meter = {}
            reply = rpc(port, op, meter=meter, **params)
            for k,v in meter.items():
                counts[k] += v
            return reply
        # Pin our traversal and verify every original body locally. Branch selection
        # belongs to Chain.accept; neither an advertised tip nor a height is imported.
        endpoint = read('selected', start=height, limit=1)[0][0]
        for start in range(0, height+1, 64):
            n = min(64, height+1-start)
            ids = read('selected', start=start, limit=n)[0]
            if len(ids) != n:
                raise ValueError('source changed its selected range')
            for offset, name in enumerate(ids):
                bid = node.hexid(name)
                if not start+offset and bid != chain.GENESIS:
                    raise ValueError('genesis mismatch')
                if db.has(bid):
                    continue
                raw = read('block', id=name)[1]
                if chain.block_id(raw) != bid:
                    raise ValueError('block identifier mismatch')
                db.accept(raw)
                counts['blocks'] += 1
                counts['body_B'] += len(raw)
        if db.status()['tip'] != endpoint:
            raise ValueError('source endpoint did not win local selection')
        return counts

    def dispatch(meta, body, admin):
        nonlocal running
        op = meta['op']
        if admin:
            if op == 'sync':
                start = time.monotonic()
                result = fetch(meta['source'], meta.get('height'))
                return dict(result, elapsed_s=time.monotonic()-start), b''
            if op == 'withhold':
                denied.clear()
                denied.update(node.hexid(x) for x in meta['ids'])
                return {'unavailable': len(denied)}, b''
            if op == 'mine':
                pk = node.hexid(meta['pk'])
                for _ in range(node.integer(meta['count'], 1, 128)):
                    db.accept(chain.mine(db.template(pk)))
                return db.status(), b''
            if op == 'stop':
                running = False
                return {}, b''
        if op == 'block' and node.hexid(meta['id']) in denied:
            raise ValueError('original body temporarily unavailable')
        return service.dispatch(meta, body, False)

    try:
        with selectors.DefaultSelector() as sel:
            for sock in (tcp, unix, local_public):
                sock.listen(16)
                sel.register(sock, selectors.EVENT_READ)
            while running:
                for key,_ in sel.select():
                    listener = key.fileobj
                    conn, address = listener.accept()
                    with conn:
                        conn.settimeout(10)
                        with conn.makefile('rb') as stream:
                            hdr = stream.read(4)
                            if len(hdr) != 4:
                                continue
                            meta = {}
                            payload = b''
                            reply_body = b''
                            try:
                                payload = stream.read(length(hdr))
                                meta, body = unpack(payload)
                                result, reply_body = dispatch(meta, body, listener is unix)
                                reply = frame(dict(ok=True, result=result), reply_body)
                                ok = True
                            except (ValueError, OSError, RuntimeError, KeyError, TypeError, IndexError) as exc:
                                reply = frame(dict(ok=False, error=str(exc)[:160]))
                                ok = False
                            if listener is tcp:
                                safe = {k:v for k,v in meta.items() if k in ('op','id','start','limit')}
                                trace.write(json.dumps(dict(request=safe, field_names=sorted(meta),
                                    source_ip=address[0], request_B=4+len(payload), reply_B=len(reply),
                                    body_B=len(reply_body), success=ok))+'\n')
                            conn.sendall(reply)
    finally:
        db.close()
        resources.close()
        trace.close()
        tcp.close()
        unix.close()
        local_public.close()
        wallet_path.unlink(missing_ok=True)
        path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
