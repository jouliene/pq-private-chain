"""Install the swap upgrade together with the unchanged independently pinned MNG1 suite."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANAGED = HERE.parent/"managed-assets"


def module(name,path):
    s=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


base = module("managed_stage", MANAGED/"stage.py")
replace = base.replace
sha = base.sha


def patch_chain(s):
    s=replace(s,"class Chain(SupplyRegistry):","class ManagedChain(SupplyRegistry):")
    s=replace(s,"from state import Frontier","from state import Frontier\nfrom swap_ledger import SwapSupport, logical, physical_width")
    s=s.replace("packet_width(p) == 1","physical_width(p) == 1")
    s=replace(s,"        self.backend = backend","        self._swap_verifier = None\n        self.backend = backend")
    s=replace(s,"                self.history = history.","                self.setup_swap_tables()\n                self.history = history.")
    start=s.index("            slots = []\n            for packet in b.packets:")
    end=s.index("            ids =",start)
    s=s[:start]+'''            slots = []
            from swap_ledger import groups, verify_pair
            for g in groups(b.packets):
                if len(g)==1:
                    slot, = self.backend.verify(g[0])
                    slots.append(slot)
                else:
                    slots.extend(verify_pair(g,self.swap_verifier(),NETWORK,height))
'''+s[end:]
    s=replace(s,'        need(s.fee == FEE, "invalid fee")','''        need(s.fee == FEE, "invalid fee")
        self.check_funding(s,head)
        return s

    def check_funding(self,s,head):''')
    s=replace(s,'        return s\n\n    def _enqueue','\n    def _enqueue')
    s=replace(s,'        s = self._effects(packet,head)\n        for col', '''        s = self._effects(packet,head)
        self.insert_pool_slot(txid,packet,s)
        return txid,False

    def insert_pool_slot(self,txid,packet,s):
        for col''')
    s=replace(s,'        return txid,False\n\n    def offer','\n    def offer')
    s=replace(s,'slots = [self._effects(p,head) for p in packets]','slots = list(self.group_effects(packets,head))')
    s=replace(s,'offered = [r[0] for r in self.db.execute("SELECT packet FROM pool ORDER BY seq")]',
              'offered = list(logical(r[0] for r in self.db.execute("SELECT packet FROM pool ORDER BY seq")))')
    s=replace(s,'((True,detached),(False,offered))','((True,logical(detached)),(False,offered))')
    s=replace(s,'if txid in seen:', '''if txid in seen or (packet.startswith(b"SWB1") and
                        all(sha256(f).digest() in included for f in split_swap(packet))):''')
    s=replace(s,'INELIGIBLE = {','from swap_wire import split as split_swap\nINELIGIBLE = {"swap expired",')
    s=replace(s,'if __name__ == "__main__":','class Chain(SwapSupport,ManagedChain):\n    pass\n\n\nif __name__ == "__main__":')
    return s


def install(home,managed,managed_sha,swap,swap_sha):
    base.check_build(managed,managed_sha)
    ref=json.loads((HERE/"native/BUILD.json").read_bytes())
    built=json.loads((swap/"BUILD.json").read_bytes())
    if any(built[k]!=ref[k] for k in ("upstream","lock_sha256","generated_sources")) or sha(swap/"native")!=swap_sha or built["binary_sha256"]!=swap_sha:
        raise ValueError("unapproved SLG1 native build")
    vk=HERE/"native/registry/swap.vk"
    if (swap/"registered/swap.vk").read_bytes()!=vk.read_bytes():
        raise ValueError("unapproved SLG1 verifier")
    with tempfile.TemporaryDirectory(dir=home,prefix=".bootstrap-") as tmp:
        dest=Path(tmp)/"network"
        dest.mkdir()
        dev=base.install_sources(dest)
        for name in ("swap_ledger.py","swap_wire.py"):
            shutil.copyfile(HERE/name,dev/name)
        chain=dev/"chain.py"
        chain.write_text(patch_chain(chain.read_text()))
        p=dev/"managed_ledger.py"
        s=replace(p.read_text(),'packet = decode_block(hit["raw"]).packets[hit["idx"]]','''packets = decode_block(hit["raw"]).packets
                index = hit["idx"]
                packet = packets[index]''')
        s=replace(s,'                slot, = self.backend.verify(packet)','''                from swap_wire import FRAME, read_frame
                if packet.startswith(FRAME):
                    from chain import NETWORK
                    from swap_ledger import verify_pair
                    side = read_frame(packet).side
                    base = index-side
                    slot = verify_pair(packets[base:base+2],self.swap_verifier(),NETWORK,hit["h"])[side]
                else:
                    slot, = self.backend.verify(packet)''')
        p.write_text(s)
        p=dev/"history.py"
        s=replace(p.read_text(),'MNGHIS01','SWPHIS01')
        s=replace(s,'bytes([bool(slot.envelope_digest)])','bytes([2 if slot.fee==0 else int(bool(slot.envelope_digest))])')
        s=replace(s,'row[-1] in (0,1)','row[-1] in (0,1,2)')
        s=replace(s,'slots.append(dict(txid=row[:32],','slots.append(dict(txid=row[:32],fee=0 if row[-1]==2 else 3,')
        p.write_text(s)
        p=dev/"wallet_sync.py"
        s=replace(p.read_text(),'sum(FEE for _ in slots)','sum(slot["fee"] for slot in slots)')
        p.write_text(replace(s,'chain.public_transition(nfs,cms,FEE,','chain.public_transition(nfs,cms,slot["fee"],'))
        module("atomic_wallet_stage",HERE/"wallet/stage.py").stage_wallet(dev)
        for build,sub,key,pin,tag in [(managed,"",MANAGED/"native/registry/managed.vk",managed_sha,""),
                                      (swap,"swap-",vk,swap_sha,"swap-")]:
            runtime,keys=dest/(sub+"runtime"),dest/(sub+"keys")
            runtime.mkdir()
            keys.mkdir()
            shutil.copy2(build/"native",runtime/"native")
            for d in (dev,keys):
                shutil.copyfile(key,d/key.name)
            (dev/("approved-"+tag+"native.sha256")).write_text(pin+"\n")
        dest.rename(home/"deployment")


def build(home):
    workspace=Path(tempfile.mkdtemp(dir=home,prefix="source-build-"))/"build"
    managed=base.build_runtime(workspace)
    swap=workspace/"swap"
    subprocess.run([sys.executable,"-IB",HERE/"native/build.py",swap,workspace/"upstream",workspace/"target"],
                   check=True,stdout=sys.stderr)
    subprocess.run([swap/"native","register",swap/"registered"],check=True,stdout=sys.stderr,
                   env=dict(os.environ,RAYON_NUM_THREADS="2"))
    return managed,sha(managed/"native"),swap,sha(swap/"native")
