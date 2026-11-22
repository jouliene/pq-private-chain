"""Export from an archive, or independently derive the operator pin from a second validating node."""
from contextlib import closing
import json
from pathlib import Path
import sys

def main(deployment, database, dest, mode):
    sys.path.insert(0,str(deployment/'devnet'))
    import chain, runtime
    from node_snapshot import export_snapshot, expected_pin
    from run import Resources
    resources=Resources(runtime.config(deployment/'runtime'))
    try:
        db=chain.Chain(database,resources.backend)
        try:
            if mode=='pin':
                value=expected_pin(db)
                dest.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
            elif mode=='export':
                state,work,value=export_snapshot(db)
                (dest/'state.bin').write_bytes(state)
                (dest/'manifest.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
                for bid,record in db.db.execute('SELECT w.bid,w.record FROM wallet_history_v2 w JOIN sel s ON s.id=w.bid'):
                    (dest/'records'/(bid.hex()+'.bin')).write_bytes(record)
            else:
                raise ValueError('unknown export role')
        finally:
            db.close()
    finally:
        resources.close()

if __name__=='__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
