"""Measure actual archive and pruned SQLite objects. Compact into a new file and verify full logical equality."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import time


def inspect(path):
    c=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
    try:
        assert c.execute("PRAGMA integrity_check").fetchone()==("ok",)
        usage=dict(c.execute("SELECT name,sum(pgsize) FROM dbstat GROUP BY name"))
        page=c.execute("PRAGMA page_size").fetchone()[0]
        pages=c.execute("PRAGMA page_count").fetchone()[0]
        free=c.execute("PRAGMA freelist_count").fetchone()[0]
        assert pages*page==path.stat().st_size
        # Includes every logical cell, even headers and archived bytes, with explicit framing for NULL values.
        h=hashlib.sha256()
        for query in ("SELECT * FROM config ORDER BY id","SELECT * FROM blocks ORDER BY h",
                      "SELECT * FROM outs ORDER BY pos","SELECT * FROM spent ORDER BY nf"):
            for row in c.execute(query):
                for field in row:
                    if field is None:
                        h.update(b"N")
                    else:
                        datum=field if isinstance(field,bytes) else str(field).encode()
                        h.update(b"V"+len(datum).to_bytes(8,"little")+datum)
        return dict(file_B=pages*page,allocated_filesystem_B=path.stat().st_blocks*512,
            live_page_B=(pages-free)*page,freelist_B=free*page,page_B=page,physical_objects_B=usage,
            rows=dict(blocks=c.execute("SELECT count(*) FROM blocks").fetchone()[0],funded=c.execute("SELECT count(*) FROM outs").fetchone()[0],spent=c.execute("SELECT count(*) FROM spent").fetchone()[0]),
            body_B=c.execute("SELECT coalesce(sum(length(body)),0) FROM blocks").fetchone()[0],
            material_sha256=h.hexdigest())
    finally: c.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive",type=Path)
    p.add_argument("pruned",type=Path)
    p.add_argument("new_directory",type=Path)
    a=p.parse_args()
    a.new_directory.mkdir(parents=True,exist_ok=False)
    report={}
    for name,path in [("archive",a.archive),("pruned",a.pruned)]:
        before=inspect(path)
        dest=a.new_directory/(name+".sqlite")
        c=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
        start=time.monotonic(); cpu=time.process_time()
        try: c.execute("VACUUM INTO ?",(str(dest),))
        finally:c.close()
        elapsed=time.monotonic()-start; work=time.process_time()-cpu
        after=inspect(dest)
        assert after["material_sha256"]==before["material_sha256"]
        report[name]=dict(before=before,after=after,copy_compaction_wall_s=elapsed,copy_compaction_cpu_s=work)
    assert report["archive"]["before"]["rows"]==report["pruned"]["before"]["rows"]
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
