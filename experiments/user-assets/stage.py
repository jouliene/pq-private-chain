"""Stage the common pinned PoW/node/wallet sources for the AST1 network with an empty genesis."""
from hashlib import sha256
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
DEVNET = ROOT/"devnet"
NATIVE = HERE/"native"
REV = "f04c91307837c0231668383bec76ba98d89d2652"


def sha(path):
    return sha256(path.read_bytes()).hexdigest()


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("unexpected base version near "+repr(old[:70]))
    return text.replace(old,new)


def build_runtime(directory):
    src = directory/"upstream"
    directory.mkdir(parents=True,exist_ok=False)
    subprocess.run(["git","init","-q",src],check=True)
    subprocess.run(["git","-C",src,"fetch","--quiet","--depth=1","https://github.com/DigitalGuards/qnero.git",REV],check=True)
    subprocess.run(["git","-C",src,"checkout","--quiet","--detach",REV],check=True)
    out = directory/"roles"
    subprocess.run([sys.executable,"-IB",NATIVE/"build.py",out,src,directory/"target"],check=True)
    subprocess.run([out/"native","register",out/"registered"],check=True,env=dict(os.environ,RAYON_NUM_THREADS="2"),
                   stdout=sys.stderr)
    return out


def check_build(build, approved):
    registered = NATIVE/"registry/asset.vk"
    reference = json.loads((NATIVE/"BUILD.json").read_bytes())
    manifest = json.loads((build/"BUILD.json").read_bytes())
    for k in ("upstream","lock_sha256","generated_sources"):
        if manifest[k] != reference[k]:
            raise ValueError("source build differs from the approved AST1 construction: "+k)
    if (manifest["upstream"] != REV or sha(build/"native") != approved or manifest["binary_sha256"] != approved
            or (build/"registered/asset.vk").read_bytes() != registered.read_bytes()):
        raise ValueError("unapproved AST1 executable or verifier key")


def chain_source():
    s = (DEVNET/"chain.py").read_text()
    start = s.index("PROFILE = bytes.fromhex")
    stop = s.index("\n\ndef packet_vector(")
    s = s[:start]+'''from runtime import PROFILE as PROFILE_HEX
from asset_ledger import AssetRegistry, public_transition
PROFILE = bytes.fromhex(PROFILE_HEX)
NETWORK = sha256(b"AST1/PoW/network/v1\\0"+PROFILE+struct.pack("<BBBIQ",BITS,WINDOW,MAX_TX,UNDO,SUBSIDY)).digest()
GENESIS = sha256(b"AST1/PoW/genesis/v1\\0"+NETWORK).digest()
GENESIS_HEADER = ZERO+u32(0)+digest(b"dev-genesis-state",NETWORK)+digest(b"dev-genesis-body",NETWORK)+ZERO
MAGIC = b"ASTPOW01"
'''+s[stop:]
    s = replace(s,'class Chain:', 'class Chain(AssetRegistry):')
    s = replace(s,'"approved APV2 profile"','"approved AST1 profile"')
    s = replace(s,'"CREATE INDEX spent_h ON spent(h)",','''"CREATE INDEX spent_h ON spent(h)",
                        "CREATE TABLE assets(id BLOB PRIMARY KEY NOT NULL,supply INTEGER NOT NULL,h INTEGER NOT NULL,tx BLOB NOT NULL) WITHOUT ROWID",
                        "CREATE INDEX assets_h ON assets(h)",''')
    s = replace(s,'cm1 BLOB NOT NULL)",','cm1 BLOB NOT NULL,asset BLOB UNIQUE)",')
    s = replace(s,'    s = slots[0]\n','    s = slots[0]\n        self.check_issuance(s, NETWORK)\n')
    s = replace(s,'self.db.execute("INSERT INTO pool(tx,packet,nf0,nf1,cm0,cm1) VALUES (?,?,?,?,?,?)",\n                        (txid,packet,*s.nfs,*s.cms))','''if s.supply:
            need(not self.db.execute("SELECT 1 FROM pool WHERE asset=?", (s.issue_id,)).fetchone(), "pool conflict")
        self.db.execute("INSERT INTO pool(tx,packet,nf0,nf1,cm0,cm1,asset) VALUES (?,?,?,?,?,?,?)",
                        (txid,packet,*s.nfs,*s.cms,s.issue_id if s.supply else None))''')
    s = replace(s,'        fees = sum(s.fee for s in slots)','''        issuing = [s.issue_id for s in slots if s.supply]
        need(len(issuing) == len(set(issuing)), "asset already issued")
        fees = sum(s.fee for s in slots)''')
    s = replace(s,'b"C"+ctx+pk+u64(reward)','b"C"+ctx+pk+u64(reward)+u64(0)')
    s = replace(s,'        for slot in slots:\n            self.db.executemany("INSERT INTO spent', '''        for tx,slot in zip(txids,slots,strict=True):
            if slot.supply:
                self.db.execute("INSERT INTO assets VALUES(?,?,?,?)",(slot.issue_id,slot.supply,parsed.height,tx))
            self.db.executemany("INSERT INTO spent''')
    s = replace(s,'                self.db.execute("DELETE FROM outs WHERE h>?",(rewind,))','''                self.db.execute("DELETE FROM outs WHERE h>?",(rewind,))
                self.db.execute("DELETE FROM assets WHERE h>?",(rewind,))''')
    return replace(s,'INELIGIBLE = {','INELIGIBLE = {"asset already issued", "issuance identity", ')


def install_sources(dest):
    dev = dest/"devnet"
    dev.mkdir()
    for name in ("node", "cli", "history", "wallet", "wallet_sync", "intents", "transport"):
        shutil.copyfile(DEVNET/(name+".py"),dev/(name+".py"))
    for name in ("asset_ledger","runtime"):
        shutil.copyfile(HERE/(name+".py"),dev/(name+".py"))
    (dev/"chain.py").write_text(chain_source())
    ap = Path("experiments/advancing-payments")
    (dest/ap).mkdir(parents=True)
    for name in ("wire","state","run","ingress"):
        shutil.copyfile(ROOT/ap/(name+".py"),dest/ap/(name+".py"))
    bridge = Path("experiments/wallet-created/wallet/bridge.py")
    (dest/bridge).parent.mkdir(parents=True)
    shutil.copyfile(ROOT/bridge,dest/bridge)
    wire = dest/ap/"wire.py"
    wire.write_text(replace(wire.read_text(),'b"APV2" and 1 <= raw[4] <= 4','b"AST1" and raw[4] == 1'))
    p = dest/ap/"run.py"
    s = p.read_text()
    s = s[:s.index("def verify_keys(")]+'''from asset_ledger import AssetBackend

def verify_keys(keys,approved):
    from runtime import PROFILE, checked_keys
    need(approved == PROFILE, "shared AST1 verifier registration")
    checked_keys(keys)
    return {"suite":"AST1","profile":PROFILE}


'''+s[s.index("def register("):]
    p.write_text(replace(s,'self.backend=PublicBackend(','self.backend=AssetBackend('))
    p = dev/"node.py"
    p.write_text(replace(p.read_text(),'        if op=="selected":','''        if op=="assets":
            return self.db.public_assets(hexid(m["after"]),integer(m["limit"],1,32),hexid(m["tip"]).hex()),b""
        if op=="selected":'''))
    p = dev/"history.py"
    s = replace(p.read_text(),'b"PQHIST01"','b"ASTHIS01"')
    s = replace(s,'SLOT_BYTES = 32+2*32+2*(32+CT_BYTES)','SLOT_BYTES = 32+2*32+2*(32+CT_BYTES)+40')
    s = replace(s,'            body.extend(cm+ct)','            body.extend(cm+ct)\n        body.extend(slot.issue_id+struct.pack("<Q",slot.supply))')
    s = replace(s,'cts=[row[128:cm1],row[cm1+32:]]','cts=[row[128:cm1],row[cm1+32:-40]], issue_id=row[-40:-8],supply=int.from_bytes(row[-8:],"little")')
    p.write_text(s)
    spec = importlib.util.spec_from_file_location("stage_ast_wallet",HERE/"wallet/stage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.stage_wallet(dev)
    return dev


def stage(home, build, approved):
    check_build(build,approved)
    with tempfile.TemporaryDirectory(dir=home,prefix=".bootstrap-") as scratch:
        dest = Path(scratch)/"network"
        dest.mkdir()
        dev = install_sources(dest)
        (dest/"runtime").mkdir()
        shutil.copy2(build/"native",dest/"runtime/native")
        (dest/"keys").mkdir()
        shutil.copyfile(NATIVE/"registry/asset.vk",dev/"asset.vk")
        shutil.copyfile(build/"registered/asset.vk",dest/"keys/asset.vk")
        (dev/"approved-native.sha256").write_text(approved+"\n")
        dest.rename(home/"deployment")
