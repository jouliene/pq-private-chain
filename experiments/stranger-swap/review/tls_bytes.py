"""Cross-check the maintained transport meter at a second TCP observation point, without decrypting it."""
import argparse
from contextlib import ExitStack
import json
import multiprocessing
from pathlib import Path
import socket
import sys
import tempfile
from threading import Event,Thread
import time

HERE=Path(__file__).resolve().parent
NETWORK='7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac'


def encoded(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def local_service(source,home,ad,inside,ready):
    sys.path.insert(0,str(source))
    from market_transport import serve
    def handler(body):
        assert set(body)=={'probe','padding'}
        return {'probe':body['probe'],'observed_padding':len(body['padding'])}
    serve(home,ad,handler,listen=inside,ready=ready.set)


def hello_from_wire(data):
    # TLS 1.3 sends ServerHello in clear before the certificate and application data are encrypted.
    assert data[:3] == b'\x16\x03\x03' and data[5]==2
    rec=int.from_bytes(data[3:5],'big');size=int.from_bytes(data[6:9],'big')
    assert size+4<=rec and len(data)>=9+size
    hello=data[9:9+size]
    assert hello[:2]==b'\x03\x03'
    offset=35+hello[34]
    suite=int.from_bytes(hello[offset:offset+2],'big')
    assert hello[offset+2]==0
    pos=offset+5
    assert int.from_bytes(hello[offset+3:pos],'big')==len(hello)-pos
    extensions={}
    while pos<len(hello):
        kind=int.from_bytes(hello[pos:pos+2],'big');length=int.from_bytes(hello[pos+2:pos+4],'big')
        assert kind not in extensions and pos+4+length<=len(hello)
        extensions[kind]=hello[pos+4:pos+4+length];pos+=4+length
    version=int.from_bytes(extensions[43],'big');share=extensions[51]
    group=int.from_bytes(share[:2],'big')
    assert int.from_bytes(share[2:4],'big')==len(share)-4
    assert (version,suite,group)==(0x304,0x1302,0x11ec)
    return dict(tls_version=version,cipher_suite=suite,negotiated_group=group,server_key_share_B=len(share)-4)


def proxy(server,target,counters,errors,done,public_prefix):
    def copy(src,dst,direction):
        try:
            while data:=src.recv(65536):
                if direction=='maker_to_taker' and len(public_prefix)<4096:
                    public_prefix.extend(data[:4096-len(public_prefix)])
                dst.sendall(data)
                counters[direction]+=len(data)
            dst.shutdown(socket.SHUT_WR)
        except OSError as error:
            errors.append(str(error))
    try:
        browser,unused=server.accept()
        with browser,socket.create_connection(target,timeout=10) as backend:
            browser.settimeout(12);backend.settimeout(12)
            reverse=Thread(target=copy,args=(backend,browser,'maker_to_taker'))
            reverse.start()
            copy(browser,backend,'taker_to_maker')
            reverse.join(15)
            assert not reverse.is_alive()
    except BaseException as error:
        errors.append(str(error))
    finally:
        done.set()


def check(source):
    sys.path.insert(0,str(source))
    from market_transport import make_advert,request
    with ExitStack() as stack:
        temp=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        outside=stack.enter_context(socket.socket());outside.bind(('127.0.0.1',0));outside.listen(1);outside.settimeout(15)
        with socket.socket() as finder:
            finder.bind(('127.0.0.1',0));inside=finder.getsockname()
        host,port=outside.getsockname()
        now=int(time.time())
        ad=make_advert(temp/'identity',f'{host}:{port}',dict(network=NETWORK,service='token-for-native',version=1,issued=now,expires=now+120))
        ctx=multiprocessing.get_context('fork');ready=ctx.Event()
        # New process group keeps the throwaway TLS fixture independent of wallet data.
        import os,signal
        def launch():
            os.setsid()
            local_service(source,temp/'identity',ad,f'{inside[0]}:{inside[1]}',ready)
        maker=ctx.Process(target=launch);maker.start()
        try:
            assert ready.wait(12)
            counters=dict(taker_to_maker=0,maker_to_taker=0);errors=[];done=Event()
            prefix=bytearray()
            t=Thread(target=proxy,args=(outside,inside,counters,errors,done,prefix),daemon=True);t.start()
            body=dict(probe='raw-socket-byte-check',padding='x'*4096);meter={}
            reply=request(ad,body,meter=meter)
            assert reply=={'probe':body['probe'],'observed_padding':4096}
            assert done.wait(15) and not errors
            assert (counters['taker_to_maker'],counters['maker_to_taker'])==(meter['wire_request_B'],meter['wire_reply_B'])
            assert meter['request_B']==len(encoded(body)) and meter['reply_B']==len(encoded({'ok':True,'result':reply}))
            assert meter['authenticated'] and meter['group']=='X25519MLKEM768' and meter['protocol']=='TLSv1.3'
            assert meter['cipher']=='TLS_AES_256_GCM_SHA384'
            return dict(independent_raw_tcp_payload_B=counters,client_inner_and_outer_meters=meter,
                        directions_byte_identical=True,observed_clear_ServerHello=hello_from_wire(prefix),private_wallet_data_used=False)
        finally:
            if maker.is_alive():
                try:
                    os.killpg(maker.pid,signal.SIGTERM)
                except ProcessLookupError:
                    maker.terminate()
            maker.join(4)


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=lambda x:Path(x).resolve(),default=HERE.parent)
    print(json.dumps(check(p.parse_args().source),indent=2,sort_keys=True))
