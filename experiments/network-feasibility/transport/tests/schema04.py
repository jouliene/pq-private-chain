"""Cheap SQL structural invariants only; no proof/admission success is claimed."""
from pathlib import Path
import json,sqlite3
ROOT=Path(__file__).resolve().parents[4]
schema=ROOT/'source/crates/ledger-cp03/src'
checks=[]
def blocked(db,sql):
    try:db.execute(sql)
    except sqlite3.DatabaseError:return True
    return False
for version,mode in ((2,0),(3,0),(3,1)):
    d=sqlite3.connect(':memory:');d.execute('PRAGMA foreign_keys=ON')
    d.executescript((schema/('schema.sql'if version==2 else'schema-network04.sql')).read_text())
    if version==2:d.execute('INSERT INTO body_cache VALUES(1,?,100,0,0,100,0,0)',(bytes(32),))
    else:d.execute('INSERT INTO body_cache VALUES(1,?,100,0,0,100,0,0,?)',(bytes(32),mode))
    header=bytes(216 if version==3 else 208)
    d.execute('INSERT INTO blocks VALUES(1,?,?,?,?,?,0,0,0,?,0,0)',(bytes([1])*64,bytes(64),header,0,bytes(64),bytes(64)))
    ordinal=127 if version==3 else 15
    d.execute('INSERT INTO bodies VALUES(1,?,?,1,?,?)',(ordinal,bytes([2])*64,b'P',b'R'))
    cache=d.execute('SELECT cached_bytes,unexported_bytes FROM body_cache').fetchone()
    pending=d.execute('SELECT COUNT(*) FROM archive_pending').fetchone()[0]
    assert cache==(1,0 if mode else 1)and pending==(0 if mode else 1)
    assert blocked(d,'UPDATE bodies SET full=NULL')
    if mode:
        assert blocked(d,'INSERT INTO archive_segments VALUES(0,0,0)')
        assert blocked(d,'UPDATE body_cache SET retention=0')
    d.execute('DELETE FROM bodies');assert d.execute('SELECT cached_bytes,unexported_bytes FROM body_cache').fetchone()==(0,0)
    assert d.execute('SELECT COUNT(*) FROM archive_pending').fetchone()[0]==0
    checks.append({'schema':version,'retention':mode,'insert_delete_accounting':True,'unacknowledged_or_retain_eviction_rejected':True})
    d.close()
print(json.dumps({'scope':'SQL structural control, not genuine ledger/payment verification','checks':checks,'passed':True},indent=2))
