"""Install snapshot service hooks alongside an existing registered profile-C deployment."""
import argparse
from pathlib import Path
import shutil
import tempfile
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from node_deployment import deployment_id


def replace_once(path, before, after):
    old = path.read_text()
    if old.count(before) != 1:
        raise ValueError(f"unexpected funded source in {path.name}")
    path.write_text(old.replace(before, after))


def install(source, destination):
    source, destination = Path(source).absolute(), Path(destination).absolute()
    deployment_id(source)  # Reject links, special files and unrecognized cache contents before staging.
    if destination.exists():
        raise ValueError("snapshot stage needs a new destination")
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        out = Path(tmp)/"deployment"
        shutil.copytree(source, out, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        dev = out/"devnet"
        # Verified A/B/C markers are never assigned to an assumed block. Its distinct
        # imported record is recognized only by this adapter and only while provisional.
        excluded = ("AND NOT EXISTS (SELECT 1 FROM snapshot_prefix sp, snapshot_mode sm "
                    "WHERE sp.bid=b.id AND sm.mode IN ('provisional','quarantined') AND length(b.raw)=0) ")
        replace_once(dev/"upgrade_rules.py","b.h>=? AND NOT EXISTS ", "b.h>=? "+excluded+"AND NOT EXISTS ")
        replace_once(dev/"consensus.py","h>=? AND NOT EXISTS", "b.h>=? "+excluded+"AND NOT EXISTS")
        src = dev/"chain.py"
        replace_once(src,"class Chain(MembershipSupport,SwapSupport,ManagedChain):",
                     "from node_snapshot import SnapshotSupport\n\nclass Chain(SnapshotSupport,MembershipSupport,SwapSupport,ManagedChain):")
        # During a deep reorg wholly above the assumed checkpoint the common prefix is
        # replayed from the retained base. Forks through the base require independent full replay.
        replace_once(src,'prefix = [r[0] for r in self.db.execute(', 'floor = self._snapshot_floor()\n            prefix = [r[0] for r in self.db.execute(')
        replace_once(src,'"SELECT id FROM sel WHERE h BETWEEN 1 AND ? ORDER BY h",(base,)', '"SELECT id FROM sel WHERE h>? AND h<=? ORDER BY h",(floor,base)')
        replace_once(src,'rewind = 0 if deep else base', 'rewind = floor if deep else base')
        shutil.copyfile(HERE/"node_snapshot.py",dev/"node_snapshot.py")
        shutil.copyfile(HERE/"node_deployment.py",dev/"node_deployment.py")
        for name in ("chain.py", "consensus.py", "upgrade_rules.py", "node_snapshot.py"):
            compile((dev/name).read_bytes(),name,"exec")
        deployment_id(out)
        out.rename(destination)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    parser.add_argument("destination",type=Path)
    args = parser.parse_args()
    install(args.source,args.destination)
