"""Stage an isolated statement-committing PoW network using an approved DLF1 source build."""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "payment-architecture/direct"
sys.path.insert(0, str(BASE))
from stage import stage as stage_direct
from build import replace_once


def create(build, target, approved):
    if target.exists():
        raise ValueError("use a fresh deployment directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as scratch:
        tmp = Path(scratch)
        for name in ("native", "BUILD.json"):
            shutil.copy2(build / name, tmp / name)
        stage_direct(tmp, approved)
        staged = tmp / "network"
        dev = staged / "devnet"
        shutil.copyfile(HERE / "block_format.py", dev / "block_format.py")
        p = dev / "chain.py"
        s = replace_once(p.read_text(), "import history", "import history\nimport block_format")
        s = s.replace('b"PQDEV1/network\\0"', 'b"D8/network/v1\\0"')
        s = replace_once(s,'MAGIC = b"PQDEVBL1"', 'MAGIC = block_format.MAGIC\n\ndef txid_of(packet):\n    return block_format.identity(NETWORK, packet)')
        s = replace_once(s, 'sha256(vector).digest()', 'sha256(block_format.id_vector(NETWORK,vector)).digest()')
        s = replace_once(s, 'b"PQDEV1/template\\0"+template','b"D8/core/v1\\0"+block_format.core(NETWORK,template+bytes(8))[:-8]')
        s = s.replace('sha256(packet).digest()', 'txid_of(packet)').replace('sha256(p).digest()', 'txid_of(p)')
        s = replace_once(s, 'if self.db.execute("SELECT 1 FROM pool WHERE tx=?",(txid,)).fetchone():',
            'existing = self.db.execute("SELECT packet FROM pool WHERE tx=?",(txid,)).fetchone()\n'
            '        if existing:\n            if existing[0] != packet:\n                self.backend.verify(packet)')
        s = replace_once(s, 'need(self.db.execute("SELECT raw FROM blocks WHERE id=?",(bid,)).fetchone()[0] == raw,\n'
            '                     "block identity collision")',
            'stored = self.db.execute("SELECT raw FROM blocks WHERE id=?",(bid,)).fetchone()[0]\n'
            '                if stored != raw:\n'
            '                    need(block_format.core(NETWORK,stored)==block_format.core(NETWORK,raw),"block identity collision")\n'
            '                    for packet in parsed.packets:\n                        self.backend.verify(packet)')
        p.write_text(s)
        p = dev / "node.py"
        p.write_text(replace_once(p.read_text(), 'chain.sha256(b).digest()!=txid', 'chain.txid_of(b)!=txid'))
        p = dev / "intents.py"
        p.write_text(replace_once(p.read_text(), 'tx=hashlib.sha256(raw).hexdigest()', 'from chain import txid_of\n        tx=txid_of(raw).hex()'))
        staged.rename(target)


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("build", type=Path)
    p.add_argument("target", type=Path)
    p.add_argument("--approve-native-sha", required=True)
    a=p.parse_args()
    create(a.build.resolve(),a.target.resolve(),a.approve_native_sha)
