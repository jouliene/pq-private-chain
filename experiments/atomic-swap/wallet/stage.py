"""Add private swap reservations alongside the ordinary wallet outbox under the same operation lock."""
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def stage_wallet(dev):
    dev = Path(dev)
    shutil.copyfile(HERE/"terms.py",dev/"swap_terms.py")
    shutil.copyfile(HERE/"swap_wallet.py",dev/"swap_wallet.py")
    path = dev/"intents.py"
    source = path.read_text()
    marker = '            self.db.execute("CREATE INDEX IF NOT EXISTS attempts_intent ON attempts(intent)")'
    if source.count(marker) != 1:
        raise ValueError("unexpected base wallet outbox schema")
    source = source.replace(marker, marker + '''
            self.db.execute("""CREATE TABLE IF NOT EXISTS swap_sessions(
                terms BLOB NOT NULL, side INTEGER NOT NULL, state TEXT NOT NULL, nonce BLOB,
                public BLOB NOT NULL, leg BLOB NOT NULL, pins TEXT NOT NULL, changes TEXT NOT NULL,
                metrics TEXT NOT NULL, joint BLOB, signature BLOB, PRIMARY KEY(terms,side))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS swap_reservations(
                cm TEXT PRIMARY KEY, terms BLOB NOT NULL, side INTEGER NOT NULL,
                FOREIGN KEY(terms,side) REFERENCES swap_sessions(terms,side))""")''')
    reserved = 'return self.db.execute("SELECT 1 FROM reservations WHERE cm=? AND intent<>?",(cm,ident)).fetchone() is not None'
    if source.count(reserved) != 1:
        raise ValueError("unexpected base wallet reservation lookup")
    source = source.replace(reserved, '''return self.db.execute("SELECT 1 FROM reservations WHERE cm=? AND intent<>? "
                               "UNION ALL SELECT 1 FROM swap_reservations WHERE cm=? LIMIT 1",
                               (cm,ident,cm)).fetchone() is not None''')
    compile(source,str(path),"exec")
    path.write_text(source)
