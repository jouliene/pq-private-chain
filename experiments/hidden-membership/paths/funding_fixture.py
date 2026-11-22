"""Create or publicly replay the bounded signed FS01 prefix for the path experiment."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

BINDING = Path(__file__).resolve().parents[2] / "fresh-spend" / "binding"
sys.path.insert(0, str(BINDING))
from issuer import Funding, Issue
from relation import (Note, ZERO, credit_occ, funding_asset, h, le, need, new_note,
                      owner, spend_key)

GRANTS = 11
NOTE = 208
RECEIPT = 1792
SIGNATURE = 29792
GENESIS = 4 + 64 + 64 + 4 + GRANTS*NOTE
ISSUE_CORE = 4 + 64 + 64 + 8 + NOTE + RECEIPT
POLICY = hashlib.shake_256(b"hidden-membership/fs01/signed-prefix/v1").digest(64)
ISSUE_FILES = ("issue0.bin", "issue1.bin")


def native_helper(tool, mode, payload):
    proc = subprocess.run((os.environ.get("FS_RECEIPT_NODE", "node"), BINDING/tool, mode),
                          input=payload, stdout=subprocess.PIPE, check=True)
    return proc.stdout


def issue_record(issue):
    return (b"FSI1" + issue.issuer_pk + issue.nonce + le(issue.cap, 8)
            + issue.note.encode() + issue.receipt)


def parse_note(raw):
    need(len(raw) == NOTE, "note framing")
    return Note(raw[:64], int.from_bytes(raw[64:72], "little"), raw[72:136],
                int.from_bytes(raw[136:144], "little"), raw[144:])


def read_fixed(path, length):
    with path.open("rb") as src:
        data = src.read(length+1)
    need(len(data) == length, "funding record length")
    return data


def signed_issue(chain, cap):
    keys = native_helper("approval.mjs", "key", b"")
    pk, nonce = keys[:64], secrets.token_bytes(64)
    aid = funding_asset(chain, pk, nonce, cap)
    seed = secrets.token_bytes(64)
    ask = spend_key(chain, seed)
    note = new_note(owner(ask), 0, aid, cap)
    fid = h("funding_id", chain, b"\x01", aid)
    context = chain + credit_occ(chain, fid, 0) + bytes(1) + note.cm(chain)
    descriptor = native_helper("receipt.mjs", "descriptor", chain+seed)
    receipt = native_helper("receipt.mjs", "seal", context+descriptor+note.encode())
    need(native_helper("receipt.mjs", "open", context+seed+receipt) == note.encode(),
         "unrecoverable issued receipt")
    issue = Issue(pk, nonce, cap, note, receipt)
    _, message, _, _ = issue.public_fields(chain)
    sig = native_helper("approval.mjs", "sign", message+keys[64:])
    need(len(sig) == SIGNATURE and len(receipt) == RECEIPT, "provider framing")
    return ask, issue, sig


def opening(index, ask, note, state):
    occ, cm = state.entries[index]
    need(owner(ask) == note.owner and note.cm(state.chain) == cm, "opening mismatch")
    fields = dict(ask=ask, native=le(note.native, 8), asset=note.asset, qty=le(note.qty, 8),
                  salt=note.salt, occ=occ, cm=cm)
    return dict(index=index, **{key: value.hex() for key, value in fields.items()})


def new(directory):
    # Never send ASK to a terminal or file. The private caller consumes this one pipe.
    need(stat.S_ISFIFO(os.fstat(1).st_mode) or stat.S_ISSOCK(os.fstat(1).st_mode),
         "private stdout pipe required")
    directory.mkdir(mode=0o700)
    nonce = secrets.token_bytes(64)
    chain = h("chain", nonce, POLICY)
    keys = [spend_key(chain, secrets.token_bytes(64)) for _ in range(GRANTS)]
    grants = [new_note(owner(ask), i+1, ZERO, 0) for i, ask in enumerate(keys)]
    genesis = b"FSG1" + nonce + POLICY + le(GRANTS, 4) + b"".join(n.encode() for n in grants)
    state = Funding(chain, grants)
    issues = [signed_issue(chain, cap) for cap in (99, 173)]
    for _, issue, sig in issues:
        state.register(issue, sig)
    need(len(state.supplies) == 2, "two distinct issued assets required")
    # All three records are public. Only the private return value selects two rows.
    (directory/"genesis.bin").write_bytes(genesis)
    for filename, (_, issue, sig) in zip(ISSUE_FILES, issues, strict=True):
        (directory/filename).write_bytes(issue_record(issue)+sig)
    g, j = secrets.randbelow(GRANTS), secrets.randbelow(2)
    values = [opening(g, keys[g], grants[g], state),
              opening(GRANTS+j, issues[j][0], issues[j][1].note, state)]
    secrets.SystemRandom().shuffle(values)
    sys.stdout.write(json.dumps(values))


def ledger(directory, expected_genesis_sha256, reverse=False):
    need(len(expected_genesis_sha256) == 64 and
         all(ch in "0123456789abcdef" for ch in expected_genesis_sha256), "invalid genesis pin")
    raw = read_fixed(directory/"genesis.bin", GENESIS)
    need(hashlib.sha256(raw).hexdigest() == expected_genesis_sha256, "wrong pinned genesis")
    need(raw[:4] == b"FSG1" and raw[68:132] == POLICY and raw[132:136] == le(GRANTS, 4),
         "genesis policy or grant count")
    chain = h("chain", raw[4:68], POLICY)
    grants = [parse_note(raw[pos:pos+NOTE]) for pos in range(136, len(raw), NOTE)]
    state = Funding(chain, grants)
    for filename in reversed(ISSUE_FILES) if reverse else ISSUE_FILES:
        record = read_fixed(directory/filename, ISSUE_CORE+SIGNATURE)
        need(record[:4] == b"FSI1", "issue magic")
        issue = Issue(record[4:68], record[68:132], int.from_bytes(record[132:140], "little"),
                      parse_note(record[140:140+NOTE]), record[140+NOTE:ISSUE_CORE])
        state.register(issue, record[ISSUE_CORE:])
    count = len(state.entries)
    need(count == GRANTS+2 and len(state.supplies) == 2 and
         len({occ for occ, _ in state.entries}) == count, "funding cardinality")
    return b"HMF1"+chain+le(count, 4)+b"".join(occ+cm for occ, cm in state.entries)


def main(args):
    if len(args) == 2 and args[0] == "new":
        new(Path(args[1]))
    elif len(args) in (3, 4) and args[0] == "ledger" and (len(args) == 3 or args[3] == "reverse"):
        sys.stdout.buffer.write(ledger(Path(args[1]), args[2], len(args) == 4))
    else:
        raise ValueError("expected new DIRECTORY or ledger DIRECTORY EXPECTED_GENESIS_SHA256 [reverse]")


if __name__ == "__main__":
    main(sys.argv[1:])
