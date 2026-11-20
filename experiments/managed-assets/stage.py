"""Stage the managed v1 rules, keeping the AST1 installation and its genesis reproducible."""
from pathlib import Path
from hashlib import sha256
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AST = HERE.parent/"user-assets"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module("fixed_asset_stage", AST/"stage.py")
replace = base.replace
sha = base.sha


def build_runtime(directory):
    directory.mkdir(parents=True)
    upstream = directory/"upstream"
    subprocess.run(["git","init","-q",upstream],check=True)
    subprocess.run(["git","-C",upstream,"fetch","--quiet","--depth=1","https://github.com/DigitalGuards/qnero.git",base.REV],check=True)
    subprocess.run(["git","-C",upstream,"checkout","--quiet","--detach",base.REV],check=True)
    out = directory/"roles"
    subprocess.run([sys.executable,"-IB",HERE/"native/build.py",out,upstream,directory/"target"],check=True)
    subprocess.run([out/"native","register",out/"registered"],check=True,stdout=sys.stderr,
                   env=dict(os.environ,RAYON_NUM_THREADS="2"))
    return out


def check_build(build, approved):
    src = json.loads((HERE/"native/BUILD.json").read_bytes())
    dst = json.loads((build/"BUILD.json").read_bytes())
    if (any(src[k]!=dst[k] for k in ("upstream","lock_sha256","generated_sources"))
            or sha(build/"native")!=approved or dst["binary_sha256"]!=approved
            or (build/"registered/managed.vk").read_bytes()!=(HERE/"native/registry/managed.vk").read_bytes()):
        raise ValueError("unapproved managed build or key")


def chain_source(s):
    # The pre-upgrade genesis, reward domains and headers remain valid. The operator
    # separately approves both verifier suites. First MSP1 inclusion requires upgraded peers.
    old_vk=sha(AST/"native/registry/asset.vk")
    s=replace(s,"+PROFILE+struct.pack",f'+bytes.fromhex("{old_vk}")+struct.pack')
    s=replace(s,"from asset_ledger import AssetRegistry, public_transition","from managed_ledger import SupplyRegistry, public_transition")
    s=replace(s,"class Chain(AssetRegistry):","class Chain(SupplyRegistry):")
    old="id BLOB PRIMARY KEY NOT NULL,supply INTEGER NOT NULL,h INTEGER NOT NULL,tx BLOB NOT NULL"
    new=("id BLOB NOT NULL,sequence INTEGER NOT NULL,mode TEXT NOT NULL,authority BLOB NOT NULL,"
         "supply INTEGER NOT NULL,h INTEGER NOT NULL,tx BLOB UNIQUE NOT NULL,PRIMARY KEY(id,sequence)")
    s=replace(s,old,new)
    s=replace(s,'self.db.execute("INSERT INTO assets VALUES(?,?,?,?)",(slot.issue_id,slot.supply,parsed.height,tx))',
              "self.record_event(slot,parsed.height,tx)")
    rejects=('wrong issuer authority','stale issuer state','immutable fixed supply','invalid issuer signature',
             'asset already registered','registration state','unregistered asset','operation mismatch',
             'outstanding supply overflow','outstanding supply underflow')
    return replace(s,'INELIGIBLE = {','INELIGIBLE = {'+', '.join(repr(x) for x in rejects)+', ')


def install_sources(dest):
    dev = base.install_sources(dest)
    for name in ("managed_ops","managed_ledger"):
        shutil.copy2(HERE/(name+".py"),dev/(name+".py"))
    p=dev/"chain.py"
    p.write_text(chain_source(p.read_text()))
    p=dev/"runtime.py"
    p.write_text(p.read_text().replace("asset.vk","managed.vk").replace("AST1","MNG1"))
    p=dev/"history.py"
    s=replace(p.read_text(),"ASTHIS01","MNGHIS01")
    s=replace(s,'+40\n','+41\n')
    s=replace(s,'slot.issue_id+struct.pack("<Q",slot.supply)','slot.issue_id+struct.pack("<Q",slot.supply)+bytes([bool(slot.envelope_digest)])')
    s=replace(s,'slots.append(dict(txid=row[:32],nfs=', 'require(row[-1] in (0,1),"unknown historic suite")\n            slots.append(dict(txid=row[:32],envelope_digest=row[:32] if row[-1] else b"",nfs=')
    s=replace(s,'row[cm1+32:-40]], issue_id=row[-40:-8],supply=int.from_bytes(row[-8:]','row[cm1+32:-41]], issue_id=row[-41:-9],supply=int.from_bytes(row[-9:-1]')
    p.write_text(s)
    p=dev/"node.py"
    p.write_text(replace(p.read_text(),'        if op=="assets":','''        if op=="supply-observation":
            txs = m["txs"]
            if not isinstance(txs,list) or not 1 <= len(txs) <= 8:
                raise ValueError("observation bounds")
            return self.db.supply_observation([hexid(t) for t in txs]),b""
        if op=="assets":'''))
    ap=dest/"experiments/advancing-payments"
    p=ap/"wire.py"
    s=p.read_text()
    p.write_text(s[:s.index("def packet_width(")]+"from managed_ops import packet_width\n\n\n"+s[s.index("def header_parts("):])
    p=ap/"run.py"
    p.write_text(p.read_text().replace("from asset_ledger import AssetBackend","from managed_ledger import ManagedBackend")
                 .replace("self.backend=AssetBackend(","self.backend=ManagedBackend(").replace("AST1","MNG1"))
    module("managed_wallet_stage",HERE/"wallet/stage.py").stage_wallet(dev)
    p=dev/"wallet_sync.py"
    p.write_text(replace(p.read_text(),'require(tx==slot["envelope_digest"]',
                         'require(slot["envelope_digest"] in (b"",tx)'))
    return dev


def stage(home, build, approved):
    check_build(build,approved)
    with tempfile.TemporaryDirectory(dir=home,prefix=".bootstrap-") as tmp:
        dest=Path(tmp)/"network"
        dest.mkdir()
        dev=install_sources(dest)
        (dest/"runtime").mkdir()
        shutil.copy2(build/"native",dest/"runtime/native")
        (dest/"keys").mkdir()
        for d in (dev,dest/"keys"):
            shutil.copyfile(HERE/"native/registry/managed.vk",d/"managed.vk")
        (dev/"approved-native.sha256").write_text(approved+"\n")
        dest.rename(home/"deployment")
