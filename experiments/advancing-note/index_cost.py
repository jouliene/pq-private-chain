"""Synthetic storage calibration only, using the node's actual disk index and page settings."""
from hashlib import shake_256
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent/'lab'))
from state import BranchIndex


def main():
    with tempfile.TemporaryDirectory() as tmp, BranchIndex(Path(tmp)/'only-test.sqlite') as idx:
        checkpoints = {1024, 8192, 32768, 65536}
        samples = {}
        for leg in range(1,max(checkpoints)+1):
            # Independently distributed public test bytes approximate the index ordering only.
            vals=shake_256(b'N7P2/public-index-price\0'+leg.to_bytes(8,'little')).digest(224)
            keys=[vals[i:i+56] for i in range(0,len(vals),56)]
            with idx.db:
                idx.change(keys[:2],keys[2:],'00'*16,3)
            if leg in checkpoints:
                samples[leg]=idx.stat()
                assert idx.db.execute('SELECT count(*) FROM spent').fetchone()[0]==leg*2
        size=lambda n:samples[n]['database_file_B']
        per_leg=(size(65536)-size(32768))/32768
        print(json.dumps(dict(kind='Synthetic index occupancy, no proofs or throughput claim',
            sqlite=sqlite3.sqlite_version,legs=sorted(checkpoints),physical=samples,
            marginal_db_B_per_leg=per_leg,projected_database_GB_per_110M_legs=per_leg*110000000/1e9),indent=2))


if __name__=='__main__':
    main()
