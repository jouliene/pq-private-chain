"""Common wallet history on the selected PQDEV1 branch.

A page contains magic, u8 block count and immutable records ordered by height. Each record
has u32le height, 32-byte seal and parent, 132-byte AP header, 104-byte reward, u8 slot
count, then txid, two nullifiers and two ordered commitment/ciphertext pairs per slot.
Only the selected-height index authorizes a record for export. The target may remain valid
under later appends. The validated local node supplies ciphertexts and transaction IDs.

Counters describe SQL statements, returned rows and logical application bytes; indexes,
SQLite page/cache reads and network framing are separate. Metadata integers use protocol
widths (height 4, count/work 8). A range query returns selected h/id and a record BLOB,
so it counts once in sql_queries and once in each of the metadata/payload query counters.
Exact payload_B includes all bytes in those BLOBs. A nonempty page adds nine transport-
payload framing bytes. history_info reports the separate one-time archived-data backfill.
"""

import struct

MAGIC = b"PQHIST01"
CT_BYTES = 1792
MAX_RANGE = 16
MAX_LOCATOR = 64
BLOCK_BYTES = 4+32+32+132+104+1
SLOT_BYTES = 32+2*32+2*(32+CT_BYTES)


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def identifier(value):
    require(type(value) is str and len(value) == 64, "history block identifier")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError("history block identifier") from None
    require(len(raw) == 32 and raw.hex() == value, "history block identifier")
    return raw


def counters():
    return dict(sql_queries=0,metadata_queries=0, metadata_rows=0, metadata_B=0,
                payload_queries=0, payload_rows=0, payload_B=0,
                blocks=0, transactions=0, rewards=0, receipts=0, nullifiers=0)


def record(height, bid, parent, header, reward, txids, slots):
    body = bytearray(struct.pack("<I",height)+bid+parent+header+reward+bytes([len(txids)]))
    require(len(body) == BLOCK_BYTES and len(txids) <= 4, "history block fields")
    for txid,slot in zip(txids,slots,strict=True):
        body.extend(txid+b"".join(slot.nfs))
        for cm,ct in zip(slot.cms,slot.cts,strict=True):
            body.extend(cm+ct)
    require(len(body) == BLOCK_BYTES+len(txids)*SLOT_BYTES, "history slot fields")
    return bytes(body)


def decode_range(raw):
    """Decode the bounded binary reply into ordered public wallet records."""
    if raw == b"":
        return []
    require(isinstance(raw,bytes) and 9 <= len(raw) <= 9+MAX_RANGE*(BLOCK_BYTES+4*SLOT_BYTES)
            and raw[:8] == MAGIC and 1 <= raw[8] <= MAX_RANGE, "history range framing")
    offset = 9
    blocks = []
    for _ in range(raw[8]):
        require(offset+BLOCK_BYTES <= len(raw), "truncated history header")
        prefix = raw[offset:offset+BLOCK_BYTES]
        h, = struct.unpack_from("<I",prefix)
        bid, parent, header = prefix[4:36],prefix[36:68],prefix[68:200]
        require(0 < h and h == int.from_bytes(header[32:36],"little") and prefix[-1] <= 4, "history height or width")
        if blocks:
            require(h == blocks[-1]["height"]+1 and parent == blocks[-1]["id"], "history page ancestry")
        slots = []
        offset += BLOCK_BYTES
        for _ in range(prefix[-1]):
            require(offset+SLOT_BYTES <= len(raw), "truncated history slot")
            row = raw[offset:offset+SLOT_BYTES]
            cm1 = 128+CT_BYTES
            slots.append(dict(txid=row[:32],nfs=[row[32:64],row[64:96]],
                              cms=[row[96:128],row[cm1:cm1+32]],
                              cts=[row[128:cm1],row[cm1+32:]]))
            offset += SLOT_BYTES
        blocks.append(dict(height=h,id=bid,parent=parent,header=header,reward=prefix[200:304],slots=slots))
    require(offset == len(raw), "trailing history bytes")
    return blocks


class PublicHistory:
    """Call within the owning Chain transaction, so target, base and returned rows share one branch view."""

    def __init__(self,db,network,profile,genesis,genesis_header):
        self.db = db
        self.network = network
        self.profile = profile
        self.genesis = genesis
        self.genesis_header = genesis_header
        # blocks is WITHOUT ROWID with complete proofs in its primary tree. Force a
        # narrow covering index: SQLite otherwise chooses the primary, even for header-only queries.
        db.execute("CREATE INDEX IF NOT EXISTS wallet_header_lookup ON blocks(id,header,ap,n,work)")
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name IN ('wallet_history_v1','wallet_history_v2')")}
        self.new = not tables
        self.startup = dict(schema_version=2,index_created="wallet_history_v2" not in tables,
                            archive_blocks=0,archive_metadata_B=0,archive_bytes=0,
                            verified_packets=0,written_payload_B=0,projection_rows_copied=0,
                            projection_bytes_copied=0)
        if "wallet_history_v2" not in tables:
            # The narrow UNIQUE index maps a block ID to a rowid. Neighboring receipt
            # bodies never enter interior lookup keys. Only the selected rowid is fetched.
            db.execute("CREATE TABLE wallet_history_v2 (bid BLOB PRIMARY KEY NOT NULL REFERENCES blocks(id), record BLOB NOT NULL)")
            if "wallet_history_v1" in tables:
                rows,length = db.execute("SELECT count(*),coalesce(sum(length(record)),0) FROM wallet_history_v1").fetchone()
                db.execute("INSERT INTO wallet_history_v2 SELECT bid,record FROM wallet_history_v1")
                db.execute("DROP TABLE wallet_history_v1")
                self.startup.update(projection_rows_copied=rows,projection_bytes_copied=length)

    HEAD_SQL = "SELECT header,ap,n,work FROM blocks INDEXED BY wallet_header_lookup WHERE id=?"

    def put(self,bid,blob):
        self.db.execute("INSERT INTO wallet_history_v2 VALUES (?,?)",(bid,blob))

    def _metadata(self,reads,query,params,widths):
        row = self.db.execute(query,params).fetchone()
        reads["metadata_queries"] += 1
        reads["sql_queries"] += 1
        if row is not None:
            reads["metadata_rows"] += 1
            reads["metadata_B"] += sum(widths)
        return row

    def head(self,locator):
        require(type(locator) is list and len(locator) <= MAX_LOCATOR, "history locator length")
        entries = []
        previous = 2**32
        for pair in locator:
            require(isinstance(pair,(list,tuple)) and len(pair) == 2 and type(pair[0]) is int
                    and 0 <= pair[0] < previous, "history locator heights")
            previous = pair[0]
            entries.append((pair[0],identifier(pair[1])))
        if entries:
            require(entries[-1] == (0,self.genesis), "history genesis locator")
        reads = counters()
        height,tip = self._metadata(reads,"SELECT h,id FROM sel ORDER BY h DESC LIMIT 1",(),(4,32))
        header,anchor,notes,work = self._metadata(reads,
            self.HEAD_SQL,(tip,),(132,32,8,8))
        common, common_id = 0,self.genesis
        for h,bid in entries:
            if h > height:
                continue
            if h == height:
                chosen = tip
            elif h == 0:
                chosen = self.genesis
            else:
                chosen, = self._metadata(reads,"SELECT id FROM sel WHERE h=?",(h,),(32,))
            if bid == chosen:
                common,common_id = h,bid
                break
        return dict(network=self.network.hex(),profile=self.profile.hex(),genesis=self.genesis.hex(),
                    genesis_header=self.genesis_header.hex(),height=height,tip=tip.hex(),header=header.hex(),
                    anchor=anchor.hex(),notes=notes,work=work,common_height=common,common=common_id.hex(),reads=reads)

    def _target(self,target,reads):
        row = self._metadata(reads,"SELECT h FROM sel WHERE id=?",(identifier(target),),(4,))
        require(row is not None, "history branch changed")
        return row[0]

    def check(self,target):
        reads = counters()
        return dict(height=self._target(target,reads),tip=target,reads=reads)

    RANGE_SQL = """SELECT s.h,s.id,w.record FROM sel AS s CROSS JOIN wallet_history_v2 AS w
                   WHERE s.h BETWEEN ? AND ? AND w.bid=s.id ORDER BY s.h"""

    def page(self,target,start,base,limit):
        require(type(start) is int and 1 <= start <= 2**32 and type(limit) is int and 1 <= limit <= MAX_RANGE,
                "history range bounds")
        base_id = identifier(base)
        reads = counters()
        height = self._target(target,reads)
        require(start <= height+1, "history range starts after target")
        prior = self._metadata(reads,"SELECT id FROM sel WHERE h=?",(start-1,),(32,))
        require(prior and prior[0] == base_id, "history branch changed")
        end = min(height,start+limit-1)
        blobs = []
        if start <= end:
            reads["payload_queries"] = 1
            reads["sql_queries"] += 1
            reads["metadata_queries"] += 1
            expected_parent = base_id
            for h,bid,blob in self.db.execute(self.RANGE_SQL,(start,end)):
                reads["metadata_rows"] += 1
                reads["metadata_B"] += 4+32
                require(h == start+len(blobs) and len(blob) >= BLOCK_BYTES
                        and blob[:68] == struct.pack("<I",h)+bid+expected_parent, "invalid indexed history")
                expected_parent = bid
                width = blob[BLOCK_BYTES-1]
                require(width <= 4 and len(blob) == BLOCK_BYTES+width*SLOT_BYTES, "invalid indexed history width")
                reads["payload_B"] += len(blob)
                reads["transactions"] += width
                blobs.append(blob)
            require(len(blobs) == end-start+1, "missing indexed history")
            require(end != height or expected_parent.hex() == target, "invalid indexed target")
        reads["payload_rows"] = reads["blocks"] = reads["rewards"] = len(blobs)
        reads["receipts"] = reads["nullifiers"] = 2*reads["transactions"]
        body = MAGIC+bytes([len(blobs)])+b"".join(blobs) if blobs else b""
        return dict(target=target,base=base,start=start,end=end,next=end+1 if end < height else None,reads=reads),body
