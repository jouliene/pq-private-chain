"""Check cooperative stop when an awaited peer reply completes during shutdown."""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from node import Node


async def check():
    node=Node.__new__(Node)
    node.shutdown=asyncio.Event()
    node.peers={1,2}
    node.remaining=0
    requests=[]

    async def last_reply(port):
        requests.append(port)
        await asyncio.sleep(0)
        node.shutdown.set()

    node.sync_peer=last_reply
    tasks=[asyncio.create_task(node.miner()),asyncio.create_task(node.sync())]
    try:
        done,_=await asyncio.wait(tasks,timeout=1)
        if len(done)!=2 or requests!=[1]:
            raise AssertionError("workers stayed active after the last peer reply")
        for task in tasks:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)


if __name__=="__main__":
    asyncio.run(check())
