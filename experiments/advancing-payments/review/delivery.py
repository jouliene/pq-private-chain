"""Drop a real durable local acknowledgement and verify promotion and deduplication on retransmission."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from ingress import Endpoint,create_pool,recvexact,upload


def check(raw):
    assert raw[:5] == b"APV2\x01"
    payload = struct.pack("<I",len(raw))+raw
    digest = hashlib.sha256(raw).digest()
    with tempfile.TemporaryDirectory() as root, ExitStack() as cleanup:
        root = Path(root)
        pool = root/"queue.sqlite"
        create_pool(pool)
        for label,direct in [("primary",False),("direct",True)]:
            actor = Endpoint(root/label,pool,direct)
            cleanup.callback(actor.stop)
        bus = cleanup.enter_context(socket.socket(socket.AF_UNIX))
        bus.bind(str(root/"lost-ack"))
        bus.listen(1)
        def drop_one_ack():
            with bus.accept()[0] as client, socket.socket(socket.AF_UNIX) as primary:
                assert recvexact(client,len(payload)) == payload
                primary.connect(str(root/"primary"))
                primary.sendall(payload)
                assert recvexact(primary,32) == digest
                # Primary committed. Terminate the complete local application
                # response before relaying that acknowledgement to the sender.
        with ThreadPoolExecutor(max_workers=1) as t:
            forward = t.submit(drop_one_ack)
            result = upload([root/"lost-ack",root/"direct"],raw)
            forward.result()
        c = sqlite3.connect(pool)
        try:
            assert c.execute("SELECT tx,packet,direct FROM pool").fetchall() == [(digest,raw,1)]
            repeat = upload([root/"direct"],raw)
            assert c.execute("SELECT count(*) FROM pool").fetchone()==(1,)
        finally:
            c.close()
        assert [r["out_bytes"] for r in result] == [len(payload)]*2
        assert [r["accepted"] for r in result] == [False,True]
        assert [r["ack_bytes"] for r in result] == [0,32]
        assert repeat[0]["accepted"]
        return dict(public_packet_sha256=digest.hex(),real_durable_ack_lost=True,
                    retry=result,post_retry_repeat=repeat,unique_durable_rows=1,singleton_route=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("public_packet",type=Path)
    print(json.dumps(check(p.parse_args().public_packet.read_bytes()),indent=2,sort_keys=True))
