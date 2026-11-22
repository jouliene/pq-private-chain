"""Registered snapshot state for the funded chain. Only local genesis replay can promote an import."""
from hashlib import sha256
import json
import os
from pathlib import Path

import history
from node_deployment import deployment_id
from state import Frontier
from wire import ZERO, canonical, digest, need, u32

STATE = b"SNPSTAT1"
WORK = b"SNPWORK1"
MAX_STATE = 256 << 20
MAX_WORK = 512 << 20
_REPLAY = object()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _num(v, lo=0, hi=2**63-1):
    need(type(v) is int and lo <= v <= hi, "invalid snapshot integer")
    return v


def _hex(v, length=None):
    need(type(v) is str and (length is None or len(v) == 2*length), "invalid snapshot field width")
    raw = bytes.fromhex(v)
    need(raw.hex() == v, "invalid snapshot field encoding")
    return raw


def rules_id():
    return deployment_id(Path(__file__).absolute().parents[1])


def _tip(chain, height=None):
    row = chain._head() if height is None else chain.db.execute(
        "SELECT b.* FROM blocks b JOIN sel s ON s.id=b.id WHERE s.h=?", (_num(height),)).fetchone()
    need(row is not None,"snapshot height outside selected branch")
    return row


def _make_state(chain, height=None):
    import chain as c
    db = chain.db
    tip = _tip(chain,height)
    h = tip["h"]
    anchors = []
    for row in db.execute("""SELECT b.*,p.record_sha,w.record FROM sel s JOIN blocks b ON s.id=b.id
            LEFT JOIN snapshot_prefix p ON p.bid=b.id LEFT JOIN wallet_history_v2 w ON w.bid=b.id
            WHERE s.h BETWEEN 1 AND ? ORDER BY s.h""",(h,)):
        committed = row["record_sha"]
        if row["record"] is not None:
            actual = sha256(row["record"]).digest()
            need(committed is None or actual == committed, "mismatched local wallet history")
            committed = actual
        need(committed is not None,"missing snapshot history commitment")
        anchors.append([row["id"].hex(),row["ap"].hex(),row["header"].hex(),row["fees"],row["n"],
                        row["front"].hex(),committed.hex()])
    leaves = [[cm.hex(),at] for cm,at in db.execute("SELECT cm,h FROM outs WHERE h<=? ORDER BY pos",(h,))]
    spent = [[nf.hex(),at] for nf,at in db.execute("SELECT nf,h FROM spent WHERE h<=? ORDER BY nf",(h,))]
    assets = [[aid.hex(),seq,mode,pk.hex(),supply,at,tx.hex()] for aid,seq,mode,pk,supply,at,tx
              in db.execute("SELECT * FROM assets WHERE h<=? ORDER BY id,sequence",(h,))]
    raw = STATE + _json(dict(version=1, network=c.NETWORK.hex(),genesis=c.GENESIS.hex(),rules=rules_id(),
                             height=h,tip=tip["id"].hex(),work=tip["work"],anchors=anchors,
                             leaves=leaves,spent=spent,assets=assets))
    need(len(raw) <= MAX_STATE,"snapshot state size limit")
    return raw


def _pin(raw, tip):
    import chain as c
    return dict(version=1, network=c.NETWORK.hex(),genesis=c.GENESIS.hex(),rules=rules_id(),height=tip["h"],
                tip=tip["id"].hex(),work=tip["work"],state_sha256=sha256(raw).hexdigest())


def state_digest(chain, height=None):
    with chain._transaction():
        return sha256(_make_state(chain,height)).hexdigest()


def expected_pin(chain):
    with chain._transaction():
        need(chain._mode()["mode"] == "full","independent registration requires fully verified state")
        return _pin(_make_state(chain),chain._head())


def pack_work(raw_blocks):
    import chain as c
    out = bytearray(WORK + bytes(4))
    n = 0
    for raw in raw_blocks:
        need(type(raw) is bytes and 222 <= len(raw) <= c.MAX_BLOCK and len(out)+4+len(raw)<=MAX_WORK,
             "invalid snapshot work frame")
        out.extend(u32(len(raw)))
        out.extend(raw)
        n += 1
    out[8:12] = u32(n)
    return bytes(out)


def export_snapshot(chain):
    with chain._transaction():
        need(chain._mode()["mode"] == "full","cannot attest an assumed state")
        state = _make_state(chain)
        pin = _pin(state,chain._head())
        work = pack_work(row[0] for row in chain.db.execute(
            "SELECT b.raw FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h>0 ORDER BY s.h"))
        return state,work,pin


def _work_rows(work, height):
    import chain as c
    need(type(work) is bytes and 12 <= len(work) <= MAX_WORK and work[:8]==WORK and
         int.from_bytes(work[8:12],"little")==height, "incorrect snapshot work framing")
    off = 12
    for _ in range(height):
        need(off+4<=len(work),"truncated snapshot work size")
        size = int.from_bytes(work[off:off+4],"little")
        off += 4
        need(222 <= size <= c.MAX_BLOCK and off+size<=len(work),"truncated snapshot work body")
        yield work[off:off+size]
        off += size
    need(off == len(work),"trailing snapshot work bytes")


def _import(chain, state, work, pin):
    import chain as c
    from swap_wire import bundle,groups
    from managed_ops import LIMIT

    need(type(state) is bytes and len(state)<=MAX_STATE and state.startswith(STATE), "snapshot state framing")
    need(isinstance(pin,dict) and set(pin)=={"version","network","genesis","rules","height","tip","work","state_sha256"}
         and _num(pin["version"],1,1)==1 and pin["network"]==c.NETWORK.hex() and pin["genesis"]==c.GENESIS.hex()
         and pin["rules"]==rules_id() and sha256(state).hexdigest()==pin["state_sha256"],"independent snapshot registration mismatch")
    base = _num(pin["height"],1,2**32-1)
    need(_num(pin["work"])==base*c.WORK,"incorrect registered cumulative work")
    doc = json.loads(state[len(STATE):])
    need(isinstance(doc,dict) and set(doc)==(set(pin)-{"state_sha256"})|{"anchors","leaves","spent","assets"}
         and all(doc[k]==v for k,v in pin.items() if k!="state_sha256") and STATE+_json(doc)==state,
         "noncanonical snapshot or manifest mismatch")
    anchors,leaves,spent,assets=(doc[k] for k in ("anchors","leaves","spent","assets"))
    need(all(isinstance(x,list) for x in (anchors,leaves,spent,assets)) and len(anchors)==base,"snapshot row counts")
    db = chain.db
    need(chain._head()["h"]==0 and db.execute("SELECT count(*) FROM blocks").fetchone()[0]==1 and
         not db.execute("SELECT 1 FROM pool LIMIT 1").fetchone() and chain._mode()["mode"]=="full" and
         getattr(chain,"_fresh_replay",None) is not _REPLAY,"import requires a fresh non-replay database")
    parent = c.GENESIS
    ap = chain._head()["ap"]
    front = Frontier(0,b"",chain.backend.hashes)
    fees = 0
    expected_nfs = [0] * (base+1)
    for h,raw in enumerate(_work_rows(work,base),1):
        b = c.decode_block(raw)
        bid = c.block_id(raw)
        need(int.from_bytes(bid,"big")<=c.TARGET and b.parent==parent and b.height==h, "invalid original PoW or ancestry")
        ident,anchor,header,total_fees,n,tree,hist=anchors[h-1]
        need(_hex(ident,32)==bid and _hex(header,132)==ap+u32(h)+b.state+digest(b"dev-seal",c.NETWORK,bid)+b.root,
             "funded header does not match original work preimage")
        ap = chain.backend.header_id(bytes.fromhex(header))
        need(_hex(anchor,32)==ap,"invalid funded anchor")
        widths = list(groups(b.packets))
        expected_nfs[h] = 2*len(b.packets)
        reward = c.SUBSIDY+c.FEE*len(widths)
        fees += reward-c.SUBSIDY
        need(b.amount==reward and _num(total_fees)==fees and _num(n)==front.count+expected_nfs[h]+1
             and n<=len(leaves),"snapshot count, fee or issuance inconsistency")
        while front.count<n:
            pos = front.count
            cm,at = leaves[pos]
            cm = _hex(cm,32)
            need(_num(at)==h and (pos!=n-1 or cm==b.reward_cm),"snapshot leaf height or reward")
            front.append(cm)
            db.execute("INSERT INTO outs VALUES(?,?,?,NULL,NULL)",(pos,cm,h))
        need(_hex(tree)==front.encode() and front.root()==b.root,"snapshot funded frontier mismatch")
        db.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (bid,parent,h,h*c.WORK,ap,bytes.fromhex(header),fees,n,front.encode(),b""))
        db.execute("INSERT INTO sel VALUES(?,?)",(h,bid))
        db.execute("INSERT INTO snapshot_prefix VALUES(?,?)",(bid,_hex(hist,32)))
        db.executemany("INSERT INTO txloc VALUES(?,?,?)",((sha256(p).digest(),bid,i) for i,p in enumerate(b.packets)))
        pos = 0
        for g in widths:
            if len(g)==2:
                db.execute("INSERT INTO swap_archive VALUES(?,?,?)",(sha256(bundle(g)).digest(),bid,pos))
            pos += len(g)
        parent = bid
    need(parent==_hex(pin["tip"],32) and len(leaves)==front.count,"wrong selected checkpoint")
    prev = None
    for nf,h in spent:
        nf = _hex(nf,32)
        _num(h,1,base)
        need(canonical(nf) and (prev is None or prev<nf),"noncanonical spent set")
        prev = nf
        expected_nfs[h] -= 1
        db.execute("INSERT INTO spent VALUES(?,?)",(nf,h))
    need(not any(expected_nfs),"snapshot spent count by height")
    prev_id,prev_seq,prev_height = None,0,0
    for aid,seq,mode,authority,supply,h,tx in assets:
        aid,authority,tx = _hex(aid,32),_hex(authority),_hex(tx,32)
        _num(seq,1); _num(supply,0,LIMIT); _num(h,1,base)
        need(canonical(aid) and aid!=ZERO and mode in ("fixed","managed") and len(authority)==(0 if mode=="fixed" else 32)
             and ((aid==prev_id and seq==prev_seq+1 and h>prev_height) or
                  ((prev_id is None or aid>prev_id) and seq==1)) and db.execute(
                 "SELECT 1 FROM txloc JOIN sel ON sel.id=bid WHERE tx=? AND sel.h=?",(tx,h)).fetchone(),
             "invalid snapshot asset history")
        db.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?)",(aid,seq,mode,authority,supply,h,tx))
        prev_id,prev_seq,prev_height = aid,seq,h
    db.execute("UPDATE snapshot_mode SET mode='provisional',base_height=?,base=?,state_sha256=?,rules=?,reason=NULL",
               (base,parent,pin["state_sha256"],pin["rules"]))
    need(_make_state(chain)==state,"installed monetary state differs from registered bytes")


def import_snapshot(chain,state,work,pin):
    with chain._transaction(True):
        _import(chain,state,work,pin)
    return chain.status()["bootstrap"]


def attach_history(chain,bid,record):
    need(type(bid) is bytes and len(bid)==32 and type(record) is bytes and
         history.BLOCK_BYTES<=len(record)<=history.BLOCK_BYTES+4*history.SLOT_BYTES,"wallet history size")
    with chain._transaction(True):
        chain._usable()
        db = chain.db
        row = db.execute("""SELECT b.h,b.parent,b.header,b.n,p.record_sha,w.record FROM blocks b
             JOIN sel s ON s.id=b.id LEFT JOIN snapshot_prefix p ON p.bid=b.id
             LEFT JOIN wallet_history_v2 w ON w.bid=b.id WHERE b.id=?""",(bid,)).fetchone()
        need(row is not None,"wallet history branch changed")
        if row["record"] is not None:
            need(row["record"]==record,"different existing wallet history")
            return False
        need(row["record_sha"] is not None and sha256(record).digest()==row["record_sha"],
             "wallet history commitment mismatch")
        need(record[:200]==u32(row["h"])+bid+row["parent"]+row["header"],"wallet history header mismatch")
        block, = history.decode_range(history.MAGIC+b"\x01"+record)
        slots = block["slots"]
        pos = row["n"]-1-2*len(slots)
        for i,slot in enumerate(slots):
            need(db.execute("SELECT 1 FROM txloc WHERE bid=? AND idx=? AND tx=?",(bid,i,slot["txid"])).fetchone(),
                 "wallet history transaction identity")
            for cm,ct in zip(slot["cms"],slot["cts"],strict=True):
                need(db.execute("UPDATE outs SET ct=? WHERE pos=? AND cm=? AND h=?",(ct,pos,cm,row["h"])).rowcount==1,
                     "wallet history leaf mismatch")
                pos += 1
        reward=block["reward"]
        need(db.execute("UPDATE outs SET reward=? WHERE pos=? AND cm=? AND h=?",
                        (reward,pos,reward[-32:],row["h"])).rowcount==1,"wallet history reward mismatch")
        chain.history.put(bid,record)
        return True


class SnapshotSupport:
    def setup_swap_tables(self):
        self.db.execute("""CREATE TABLE IF NOT EXISTS snapshot_mode(id INTEGER PRIMARY KEY CHECK(id=1),
                mode TEXT NOT NULL,base_height INTEGER,base BLOB,state_sha256 TEXT,rules TEXT,reason TEXT)""")
        self.db.execute("INSERT OR IGNORE INTO snapshot_mode(id,mode) VALUES(1,'full')")
        self.db.execute("""CREATE TABLE IF NOT EXISTS snapshot_prefix(bid BLOB PRIMARY KEY REFERENCES blocks(id),
                           record_sha BLOB NOT NULL) WITHOUT ROWID""")
        m=self._mode()
        need(m["rules"] in (None,rules_id()),"registered snapshot rules changed")
        super().setup_swap_tables()

    def _mode(self):
        return self.db.execute("SELECT * FROM snapshot_mode WHERE id=1").fetchone()

    def _usable(self):
        need(self._mode()["mode"]!="quarantined","snapshot verification failed; node quarantined")

    def _snapshot_floor(self):
        m=self._mode()
        return m["base_height"] if m["mode"]=="provisional" else 0

    def _fork_path(self,parent):
        base,path=super()._fork_path(parent)
        need(base>=self._snapshot_floor(),"below snapshot base: full genesis fork replay required")
        return base,path

    def _status(self):
        m=self._mode()
        if m["mode"]=="quarantined":
            import chain as c
            head=self._head()
            res=dict(network=c.NETWORK.hex(),genesis=c.GENESIS.hex(),tip=head["id"].hex(),
                     height=head["h"],work=head["work"])
        else:
            res=super()._status()
        total,attached=self.db.execute("""SELECT count(*),count(w.record) FROM snapshot_prefix p
                       LEFT JOIN wallet_history_v2 w ON w.bid=p.bid""").fetchone()
        res["bootstrap"] = dict(mode=m["mode"],base_height=m["base_height"],base=m["base"].hex() if m["base"] else None,
                                state_sha256=m["state_sha256"],rules=m["rules"],reason=m["reason"],
                                history_attached=attached,history_expected=total)
        return res

    def accept(self, raw):
        import chain as c
        with self.lock:
            self._usable()
            bid=c.block_id(raw)
            if self.db.execute("SELECT 1 FROM snapshot_prefix p JOIN blocks b ON p.bid=b.id WHERE p.bid=? "
                               "AND length(b.raw)=0",(bid,)).fetchone():
                # Same authenticated work preimage. Nothing is promoted by re-supplying it.
                b=c.decode_block(raw)
                old=self._head()
                need(b.height<=self._snapshot_floor() and self._row(bid)["parent"]==b.parent,"imported archive identity")
                return dict(id=bid.hex(),selected=True,changed=False,tip=old["id"].hex(),height=old["h"],
                            detached=[],attached=[],deep_replay=False,requeued=[],rejected=[])
            return super().accept(raw)

    def offer(self,packet):
        with self.lock:
            self._usable()
            return super().offer(packet)

    def template(self,pk,packets=None):
        with self.lock:
            self._usable()
            return super().template(pk,packets)

    def block(self,bid):
        import chain as c
        with self.lock:
            self._usable()
            raw=super().block(bid)
            need(raw or bid==c.GENESIS,"snapshot block body unavailable")
            return raw

    def pending(self):
        with self.lock:
            self._usable()
            return super().pending()

    def public_assets(self,after,limit,tip):
        with self.lock:
            self._usable()
            return super().public_assets(after,limit,tip)

    def supply_observation(self,txids):
        with self.lock:
            self._usable()
            for tx in txids:
                row=self.db.execute("""SELECT length(b.raw) FROM txloc l JOIN sel s ON s.id=l.bid
                                     JOIN blocks b ON b.id=l.bid WHERE l.tx=?""",(tx,)).fetchone()
                need(row is None or row[0],"snapshot block body unavailable")
            return super().supply_observation(txids)

    def selected(self,start,limit):
        with self.lock:
            self._usable()
            return super().selected(start,limit)

    def locator(self):
        with self.lock:
            self._usable()
            return super().locator()

    def after(self,locator,limit):
        with self.lock:
            self._usable()
            return super().after(locator,limit)

    def has(self,bid):
        with self.lock:
            self._usable()
            return super().has(bid)

    def tx(self,txid):
        with self.lock:
            self._usable()
            missing=self.db.execute("""SELECT 1 FROM blocks b JOIN sel s ON s.id=b.id
                      WHERE length(b.raw)=0 AND b.id IN (SELECT bid FROM txloc WHERE tx=?
                      UNION ALL SELECT bid FROM swap_archive WHERE id=?) LIMIT 1""",(txid,txid)).fetchone()
            need(not missing,"snapshot block body unavailable")
            return super().tx(txid)

    def history_range(self,target,start,base,limit):
        with self.lock:
            self._usable()
            try:
                return super().history_range(target,start,base,limit)
            except ValueError as exc:
                if str(exc) in ("missing indexed history","invalid indexed history") and self.db.execute("""
                      SELECT 1 FROM sel s JOIN snapshot_prefix p ON p.bid=s.id LEFT JOIN wallet_history_v2 w ON w.bid=s.id
                      WHERE w.bid IS NULL AND s.h BETWEEN ? AND min(?,(SELECT h FROM sel WHERE id=?)) LIMIT 1""",
                      (start,start+limit-1,bytes.fromhex(target))).fetchone():
                    raise ValueError("snapshot wallet history unavailable") from None
                raise

    def history_head(self,locator):
        with self.lock:
            self._usable()
            return super().history_head(locator)

    def history_check(self,target):
        with self.lock:
            self._usable()
            return super().history_check(target)

    def page(self,kind,start,limit,tip_hex):
        with self.lock:
            self._usable()
            if kind in ("receipts","rewards"):
                need(not self.db.execute("""SELECT 1 FROM snapshot_prefix p LEFT JOIN wallet_history_v2 w
                    ON w.bid=p.bid WHERE w.bid IS NULL LIMIT 1""").fetchone(),"snapshot wallet history unavailable")
            return super().page(kind,start,limit,tip_hex)


def new_replay(path,backend):
    """Only a fresh, local, genesis-initialized verifier handle can provide validation provenance."""
    from chain import Chain
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
    os.close(fd)
    replay=Chain(path,backend)
    replay._fresh_replay=_REPLAY
    return replay


def _local(live,replay):
    need(live is not replay and getattr(replay,"_fresh_replay",None) is _REPLAY and
         replay._mode()["mode"]=="full" and not replay.db.execute("SELECT 1 FROM snapshot_prefix LIMIT 1").fetchone(),
         "fresh local genesis replay required")


def _install_full(live,replay,reason):
    """Install the independently validated archive and monetary rows in the live SQLite transaction."""
    from chain import decode_block
    from swap_ledger import logical
    db=live.db
    pend = list(logical(row[0] for row in db.execute("SELECT packet FROM pool ORDER BY seq")))
    # Only original bodies actually available can supply detached transactions for the pool.
    detached = []
    if reason=="fully verified competing branch":
        for bid,raw in db.execute("SELECT s.id,b.raw FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h>0 ORDER BY s.h"):
            if raw and not replay.db.execute("SELECT 1 FROM sel WHERE id=?",(bid,)).fetchone():
                detached.extend(decode_block(raw).packets)
    tables = ("blocks","sel","outs","spent","assets","txloc","swap_archive","wallet_history_v2",
              "funded_upgrade_blocks","funded_c_blocks")
    db.execute("DELETE FROM pool")
    db.execute("DELETE FROM snapshot_prefix")
    for table in reversed(tables):
        db.execute(f"DELETE FROM {table}")
    for table in tables:
        rows=replay.db.execute(f"SELECT * FROM {table}")
        marks=",".join("?" for _ in rows.description)
        db.executemany(f"INSERT INTO {table} VALUES({marks})", rows)
    db.execute("UPDATE snapshot_mode SET mode='full',reason=?",(reason,))
    live._spent_summary=None
    # Refresh uses the original funded rules and drops confirmed/conflicting offers.
    for packet in pend:
        from chain import INELIGIBLE
        try:
            live._enqueue(packet,live._head())
        except ValueError as exc:
            if str(exc) not in INELIGIBLE:
                raise
    live._refresh(detached,set())


def finish_replay(live,replay):
    """Compare the pinned base and the current suffix, including every wallet record commitment."""
    failed=None
    with live.lock, replay.lock, live._transaction(True):
        _local(live,replay)
        m=live._mode()
        need(m["mode"]=="provisional","expected provisional checkpoint")
        base=m["base_height"]
        head=live._head()
        h=replay._head()["h"]
        need(base<=h<=head["h"] and _tip(live,h)["id"]==replay._head()["id"] and _tip(replay,base)["id"]==m["base"],
             "genesis replay has not reached the selected checkpoint branch")
        import chain as c
        registered=m["state_sha256"]
        try:
            local_base=sha256(_make_state(live,base)).hexdigest()
            real_base=sha256(_make_state(replay,base)).hexdigest()
            if local_base!=registered or real_base!=registered:
                failed="registered base differs from full monetary or history replay"
            else:
                for row in live.db.execute("""SELECT b.id,b.raw FROM blocks b JOIN sel s ON s.id=b.id
                                             WHERE s.h>? ORDER BY s.h""",(h,)):
                    bid,raw=row
                    need(raw,"snapshot suffix body unavailable")
                    if c.block_id(raw)!=bid:
                        failed="local suffix differs from its original work identity"
                        break
                    try:
                        replay.accept(raw)
                    except ValueError as exc:
                        # Operational failures (unavailable executable, key configuration, OS,
                        # worker output protocol) have no bearing on the monetary comparison.
                        invalid=c.INELIGIBLE|{"invalid reward or state commitment","invalid C proof or depth",
                                              "verified funded depth mismatch","missing valid swap authorization",
                                              "incorrect managed proof","duplicate swap authority","invalid swap leg proof"}
                        if str(exc) not in invalid:
                            raise
                        failed="registered suffix rejected by full genesis verifier: "+str(exc)
                        break
                if failed is None and _make_state(live)!=_make_state(replay):
                    failed="selected suffix differs from independently verified replay"
        except ValueError as exc:
            if str(exc) not in ("mismatched local wallet history","missing snapshot history commitment"):
                raise
            failed=str(exc)
        if failed:
            live.db.execute("UPDATE snapshot_mode SET mode='quarantined',reason=?",(failed,))
        else:
            _install_full(live,replay,"registered base and live suffix fully replayed")
    need(not failed,failed)
    return live.status()["bootstrap"]


def recover_fork(live,replay):
    """Adopt a fully replayed preferred chain crossing the registered base, atomically."""
    with live.lock,replay.lock,live._transaction(True):
        _local(live,replay)
        m=live._mode()
        need(m["base_height"] is not None and m["base"] is not None,"no snapshot origin to recover")
        old,new=live._head(),replay._head()
        need(new["work"]>old["work"] or (new["work"]==old["work"] and new["id"]<old["id"]),
             "competing replay lacks preferred work")
        need(_tip(replay,m["base_height"])["id"]!=m["base"],"candidate did not cross snapshot base")
        _install_full(live,replay,"fully verified competing branch")
    return live.status()["bootstrap"]
