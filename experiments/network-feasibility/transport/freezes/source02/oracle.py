"""Streaming public SQL/file oracles. Called outside role spans and processes."""
import hashlib,json,sqlite3
from pathlib import Path

def snapshot(path,canonical=False):
 d=sqlite3.connect(f'file:{path}?mode=ro',uri=True);d.execute('BEGIN');out={}
 tables=d.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall()
 expected={'meta','sources','nullifiers','cores','leaves','nodes','anchors','blocks','body_cache','archive_segments','archive_objects','bodies','archive_pending','node_undo'}
 if {r[0]for r in tables}!=expected:raise ValueError('exact14 ledger table set')
 for(name,)in tables:
  cols=[r[1]for r in d.execute('PRAGMA table_info("'+name+'")')]
  if canonical and name=='body_cache':cols.remove('catalog_id')
  h=hashlib.sha256();n=0
  for row in d.execute('SELECT '+','.join('"'+x+'"'for x in cols)+' FROM "'+name+'" ORDER BY '+','.join('"'+x+'"'for x in cols)):
   n+=1
   for x in row:
    if isinstance(x,bytes):tag=b'B';b=x
    elif x is None:tag=b'N';b=b''
    elif isinstance(x,int):tag=b'I';b=str(x).encode()
    else:tag=b'T';b=str(x).encode()
    h.update(tag);h.update(len(b).to_bytes(8,'little'));h.update(b)
  out[name]={'rows':n,'sha256':h.hexdigest()}
 d.rollback();d.close();return out

def retained(path):
 d=sqlite3.connect(f'file:{path}?mode=ro',uri=True)
 usage=d.execute('SELECT cached_bytes,unexported_bytes,archive_committed_bytes,retention FROM body_cache').fetchone()
 bodies=d.execute('SELECT count(*),coalesce(sum(full_length),0),sum(full IS NULL) FROM bodies').fetchone()
 pending=d.execute('SELECT count(*) FROM archive_pending').fetchone()[0];d.close()
 return {'cached_bytes':usage[0],'unexported_bytes':usage[1],'archive_committed_bytes':usage[2],'retention':usage[3],'bodies':bodies[0],'full_bytes':bodies[1],'missing_full':bodies[2]or 0,'pending':pending}

def disk(root):
 logical=allocated=0;files=0
 for p in Path(root).rglob('*'):
  if p.is_file():s=p.stat();logical+=s.st_size;allocated+=s.st_blocks*512;files+=1
 return {'logical_bytes':logical,'allocated_bytes':allocated,'files':files}
