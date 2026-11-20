"""Private two-party SWP1 wallet negotiation, verification and durable authorization."""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import tempfile
import time

from terms import LIMIT, SIZE_V2, ZERO, Party, Terms, asset_id, need, side_num

CT = 1792
SIGNATURE = 17088
MAX_LEG = 262144
MAGIC = b"SLG1\x01"


def read_file(path, limit, *, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "incorrect exchange file size or type")
        if private:
            need(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "terms require a private file")
        raw = stream.read(limit+1)
        need(len(raw) == info.st_size, "exchange file changed during read")
        return raw


def emit(path, data):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                need(read_file(path, len(data), private=True) == data, "output file already contains different bytes")
        finally:
            temporary.unlink(missing_ok=True)


def role(mode, private=None):
    from wallet import _wire
    import wallet as installed_wallet
    deploy = Path(installed_wallet.__file__).resolve().parent.parent
    key = deploy/"swap-keys/swap.vk"
    need(not key.is_symlink() and not key.parent.is_symlink() and {p.name for p in key.parent.iterdir()} == {"swap.vk"}
         and key.read_bytes() == (deploy/"devnet/swap.vk").read_bytes(), "unapproved swap verifier")
    pin = (deploy/"devnet/approved-swap-native.sha256").read_text().strip()
    args = ["wallet","/keys","/private/seed","restore"] if mode == "wallet" else ["verify","/keys"]
    return _wire.Role(deploy/"swap-runtime/native", pin, args, keys=key.parent, private=private)


@contextmanager
def actor(mode, directory=None):
    worker = role(mode, directory)
    try:
        yield worker
        worker.close()
    finally:
        worker.abort()


def wallet_address(worker, owner):
    need(worker.get() == owner.address, "swap and ordinary wallet do not control the same receiving address")


def choose(state, book, participant, fee):
    rows = state.db.execute("SELECT cm,amount,asset,token,origin,path,nf FROM owned "
                            "WHERE spent IS NULL AND (amount>0 OR token>0) AND asset IN (?,?) ORDER BY pos",
                            (ZERO, participant.give))
    eligible = [r for r in rows if not book.reserved(r["cm"].hex(), "")]
    for width in (1, 2):
        for sources in combinations(eligible, width):
            native = sum(r["amount"] for r in sources) - participant.native - fee
            token = sum(r["token"] for r in sources) - participant.token
            if 0 <= native <= LIMIT and 0 <= token <= LIMIT:
                return sources, native, token
    raise ValueError("insufficient compatible unreserved swap funding within two inputs")


def prove(worker, nonce, fee, hdr, me, other, sources):
    from wallet_sync import path_rows
    data = bytearray(b"P"+nonce+bytes([fee])+hdr+struct.pack("<QQ",me.native,me.token)+me.give+other.address+bytes([len(sources)]))
    for r in sources:
        levels = path_rows(r["path"])
        origin = r["origin"]
        need(len(origin) in (112, 1824) and 1 <= len(levels) <= 20, "invalid private funding path")
        data.extend(struct.pack("<HB",len(origin),len(levels))+origin)
        for siblings in levels:
            need(len(siblings) == 3 and all(len(s) == 32 for s in siblings), "invalid private funding siblings")
            data.extend(b"".join(siblings))
    out = worker.call(bytes(data))
    frame(out)
    return out


def frame(raw):
    n = int.from_bytes(raw[5:9],"little")
    need(raw.startswith(MAGIC) and n > 0 and len(raw) == 9+n+2*CT and len(raw) <= MAX_LEG,
         "swap leg framing or native proving failure")


@dataclass(frozen=True)
class Effect:
    anchor: bytes
    height: int
    nfs: tuple
    cms: tuple
    fee: int
    cts: tuple
    public: bytes


def verify(worker, leg):
    from wallet import _wire
    frame(leg)
    raw = worker.call(leg)
    need(len(raw) == 1+172+2*CT+32 and raw[:1] == b"1", "swap leg proof rejected")
    row = raw[1:]
    result = Effect(row[:32], int.from_bytes(row[32:36],"little"), (row[36:68],row[68:100]),
                    (row[100:132],row[132:164]), int.from_bytes(row[164:172],"little"),
                    (row[172:172+CT],row[172+CT:172+2*CT]), row[-32:])
    need(b"".join(result.cts) == leg[-2*CT:] and all(_wire.canonical(w) for w in (result.anchor,*result.nfs,*result.cms))
         and ZERO not in result.cms and len(set(result.cms)) == len(set(result.nfs)) == 2,
         "invalid verified swap effects or ordered receipts")
    return result


def check_pair(effects, terms):
    need(tuple(e.fee for e in effects) == (terms.fee(0), terms.fee(1)) and len({e.public for e in effects}) == 2
         and len({w for e in effects for w in e.nfs}) == len({w for e in effects for w in e.cms}) == 4,
         "swap roles, fees, commitments or nullifiers disagree")


def eligible(state, terms, effects):
    from chain import WINDOW
    need(state.height+1 <= terms.expiry, "swap deadline passed")
    for effect in effects:
        row = state.db.execute("SELECT header FROM heads WHERE h=?", (effect.height,)).fetchone()
        need(1 <= state.height+1-effect.height <= WINDOW and row is not None
             and state.hashes.call(b"H"+row["header"]) == effect.anchor, "swap funding anchor expired or detached")


def opened(worker, effect, index, native, asset, amount):
    need((amount == 0) == (asset == ZERO), "expected receipt currency and token value disagree")
    raw = worker.call(b"D"+effect.cms[index]+effect.cts[index])
    need(len(raw) == 84 and raw[:3] == b"HIT" and raw[3:35] != ZERO and raw[-1] == (2 if index == 0 else 3) and
         struct.unpack_from("<QQ32s", raw, 35) == (native, amount, asset),
         "wallet cannot open the committed output under its spending keys for the agreed amounts")
    # This native D operation recomputes cm using the local spend pk and derives nf with the local nk.
    return True


def get_session(book, key, side):
    return book.db.execute("SELECT * FROM swap_sessions WHERE terms=? AND side=?", (key, side)).fetchone()


def term_file(path):
    from chain import NETWORK
    terms = Terms.decode(read_file(path, SIZE_V2, private=True))
    need(terms.network == NETWORK, "wrong network in swap agreement")
    return terms


def make_leg(lab, args):
    from intents import Outbox
    from wallet_sync import synced_wallet, role_sample
    terms = term_file(args.terms)
    side = side_num(args.side)
    me, other = terms.parties[side], terms.parties[1-side]
    fee = terms.fee(side)
    terms.confirm(side, lab.address(args.wallet), asset_id(args.give_id), args.give_qty, asset_id(args.take_id), args.take_qty)
    need(args.counterparty.startswith("@") and lab.destination(args.counterparty) == other.address and
         args.expiry == terms.expiry and args.fee == fee, "counterparty, expiry or local fee differs from instructions")
    key = terms.commitment()
    with lab.locked_wallet(args.wallet) as directory, Outbox(directory) as book:
        old = get_session(book,key,side)
        if old:
            need(old["state"] != "aborted", "negotiation was aborted")
            packet = old["leg"]
            metrics = json.loads(old["metrics"])
        else:
            with lab.wallet(args.wallet) as normal, synced_wallet(lab,args.node,normal,directory) as (state,_), actor("wallet",directory) as worker:
                wallet_address(worker,normal)
                need(state.height+1 <= terms.expiry, "swap deadline passed")
                sources, native_change, token_change = choose(state,book,me,fee)
                nonce = secrets.token_bytes(32)
                public = worker.call(b"E"+nonce)
                need(len(public) == 32 and public != ZERO, "native swap key generation failed")
                before = role_sample(worker)
                start = time.perf_counter()
                packet = prove(worker,nonce,fee,state.header,me,other,sources)
                after = role_sample(worker)
                metrics = dict(proving_wall_s=time.perf_counter()-start, prover_cpu_s=after[0]-before[0],
                               prover_role_peak_rss_KiB=after[1], real_inputs=len(sources), fee=fee,
                               native_change=native_change, token_change=token_change, packet_B=len(packet))
                with actor("verify") as verifier:
                    effect = verify(verifier,packet)
                need(effect.public == public and effect.fee == fee and
                     tuple(r["nf"] for r in sources) == effect.nfs[:len(sources)], "own proof differs from pinned inputs, fee or swap key")
                opened(worker,effect,1,native_change,me.give if token_change else ZERO,token_change)
                pins = [r["cm"].hex() for r in sources]
                with book.db:
                    book.db.execute("INSERT INTO swap_sessions VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL)",
                                    (key,side,"offered",nonce,public,packet,json.dumps(pins),
                                     json.dumps([native_change,token_change]),json.dumps(metrics)))
                    book.db.executemany("INSERT INTO swap_reservations VALUES(?,?,?)", ((p,key,side) for p in pins))
    emit(args.output,packet)
    return dict(state=(old["state"] if old else "offered"),side=args.side,leg_sha256=sha256(packet).hexdigest(),**metrics)


def permit(lab, args):
    from intents import Outbox
    from swap_wire import digest
    from wallet_sync import synced_wallet
    terms, side = term_file(args.terms), side_num(args.side)
    key = terms.commitment()
    legs = read_file(args.leg_a,MAX_LEG), read_file(args.leg_b,MAX_LEG)
    joint = digest(terms.network,key,terms.expiry,terms.payer,legs)
    me, other = terms.parties[side], terms.parties[1-side]
    with lab.locked_wallet(args.wallet) as directory, Outbox(directory) as book:
        saved = get_session(book,key,side)
        need(saved is not None and saved["state"] != "aborted" and saved["leg"] == legs[side],
             "proposal differs from the locally offered leg or negotiation was aborted")
        need(lab.address(args.wallet) == me.address, "signer differs from the agreed wallet")
        if saved["signature"] is not None:
            need(saved["joint"] == joint, "wallet already released a different proposal")
            signature = saved["signature"]
        else:
            with lab.wallet(args.wallet) as normal, synced_wallet(lab,args.node,normal,directory) as (state,_), actor("wallet",directory) as w, actor("verify") as verifier:
                wallet_address(w,normal)
                effects = tuple(verify(verifier,leg) for leg in legs)
                check_pair(effects,terms)
                need(effects[side].public == saved["public"] == w.call(b"E"+saved["nonce"]),
                     "own verified swap key differs from reserved negotiation")
                native_change, token_change = json.loads(saved["changes"])
                opened(w,effects[side],1,native_change,me.give if token_change else ZERO,token_change)
                opened(w,effects[1-side],0,other.native,other.give,other.token)
                state.synchronize(lab,args.node)
                eligible(state,terms,effects)
                need(all(v == "unspent" for v in state.input_status(json.loads(saved["pins"])).values()),
                     "own real funding no longer unspent")
                signature = w.call(b"S"+saved["nonce"]+joint)
                need(len(signature) == SIGNATURE and verifier.call(b"V"+saved["public"]+joint+signature) == b"1",
                     "final swap authorization failed verification")
                with book.db:
                    book.db.execute("UPDATE swap_sessions SET state='released',joint=?,signature=? WHERE terms=? AND side=?",
                                    (joint,signature,key,side))
    emit(args.output,signature)
    return dict(state="released",side=args.side,digest=joint.hex(),signature_B=len(signature))


def abort(lab, args):
    from intents import Outbox
    terms, side = term_file(args.terms), side_num(args.side)
    key = terms.commitment()
    need(lab.address(args.wallet) == terms.parties[side].address, "swap role differs from local wallet")
    with lab.locked_wallet(args.wallet) as directory, Outbox(directory) as book:
        row = get_session(book,key,side)
        need(row is not None, "no saved offer for this negotiation")
        released = row["signature"] is not None
        if released:
            need(args.release_after_expiry, "final authorization already released and cannot be revoked")
            from wallet_sync import synced_wallet
            with lab.wallet(args.wallet) as normal, synced_wallet(lab,args.node,normal,directory) as (state,_):
                need(state.height >= terms.expiry, "released reservation remains live before expiry")
            status = "released-unlocked"
        else:
            status = "aborted"
        with book.db:
            book.db.execute("UPDATE swap_sessions SET state=?,nonce=NULL WHERE terms=? AND side=?", (status,key,side))
            book.db.execute("DELETE FROM swap_reservations WHERE terms=? AND side=?", (key,side))
    return dict(state=status, side=args.side, original_signature_still_valid_on_eligible_fork=released)


def combine(args):
    from swap_wire import digest, assemble, split
    terms = term_file(args.terms)
    legs = read_file(args.leg_a,MAX_LEG), read_file(args.leg_b,MAX_LEG)
    signatures = read_file(args.sig_a,SIGNATURE), read_file(args.sig_b,SIGNATURE)
    joint = digest(terms.network,terms.commitment(),terms.expiry,terms.payer,legs)
    with actor("verify") as public:
        effects = tuple(verify(public,leg) for leg in legs)
        check_pair(effects,terms)
        for effect,sig in zip(effects,signatures,strict=True):
            need(len(sig) == SIGNATURE and public.call(b"V"+effect.public+joint+sig) == b"1",
                 "proposal lacks the correct final signature from both owners")
    raw = assemble(terms.network,terms.commitment(),terms.expiry,terms.payer,legs,signatures)
    emit(args.output,raw)
    return dict(digest=joint.hex(),bundle_sha256=sha256(raw).hexdigest(),
                frame_ids=[sha256(f).hexdigest() for f in split(raw)],packet_B=len(raw))


def main(home, command, args):
    from chain import NETWORK
    from cli import Lab
    os.umask(0o077)
    p = argparse.ArgumentParser(prog="pqd swap "+command)
    if command in ("terms","leg","authorize","abort"):
        p.add_argument("wallet")
    if command == "terms":
        p.add_argument("counterparty")
    elif command in ("leg","authorize","abort"):
        p.add_argument("side",choices=("a","b"))
    if command != "terms":
        p.add_argument("terms",type=Path)
    if command in ("terms","leg"):
        p.add_argument("give_id"); p.add_argument("give_qty",type=int)
        p.add_argument("take_id"); p.add_argument("take_qty",type=int)
    if command == "terms":
        p.add_argument("expiry",type=int)
        p.add_argument("--payer",choices=("a","b"),help="fee-paying side, default native sender or a for token/token")
    if command == "leg":
        p.add_argument("--counterparty",required=True); p.add_argument("--expiry",required=True,type=int)
        p.add_argument("--fee",required=True,type=int)
    if command in ("authorize","combine"):
        p.add_argument("leg_a",type=Path); p.add_argument("leg_b",type=Path)
    if command == "combine":
        p.add_argument("sig_a",type=Path); p.add_argument("sig_b",type=Path)
    if command == "abort":
        p.add_argument("--release-after-expiry",action="store_true")
    if command in ("leg","authorize","abort"):
        p.add_argument("--node",choices=list("abcd"),default="c")
    if command != "abort":
        p.add_argument("output",type=Path)
    parsed = p.parse_args(args)
    home = Path(home).resolve()
    lab = Lab(home,home/"deployment/runtime")
    if command == "terms":
        need(parsed.counterparty.startswith("@"), "supply the independently exported public address")
        mine = Party(lab.address(parsed.wallet),asset_id(parsed.give_id),parsed.give_qty)
        other = Party(lab.destination(parsed.counterparty),asset_id(parsed.take_id),parsed.take_qty)
        payer = None if parsed.payer is None else side_num(parsed.payer)
        terms = Terms.fresh(NETWORK,parsed.expiry,(mine,other),payer)
        emit(parsed.output,terms.encode())
        result = dict(terms_commitment=terms.commitment().hex(),expiry=terms.expiry,payer=("a","b")[terms.payer])
    elif command == "leg":
        result = make_leg(lab,parsed)
    elif command == "authorize":
        result = permit(lab,parsed)
    elif command == "abort":
        result = abort(lab,parsed)
    elif command == "combine":
        result = combine(parsed)
    else:
        p.error("unsupported negotiation command")
    print(json.dumps(result,sort_keys=True))
    return result
