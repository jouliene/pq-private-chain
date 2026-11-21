"""Exercise activation, retirement and continuing issuance using only public funded blocks."""
import argparse
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def need(condition, message):
    if not condition:
        raise ValueError(message)


def rejected(operation, reason):
    try:
        operation()
    except ValueError as e:
        need(str(e) == reason, "unexpected refusal: " + str(e))
        return str(e)
    raise ValueError("unexpected acceptance: " + reason)


def capture(public):
    from chain import block_id, decode_block
    rows = []
    for f in sorted((public / "blocks").glob("*.bin")):
        raw = f.read_bytes()
        need(f.stem == block_id(raw).hex(), "public block identity")
        rows.append((decode_block(raw), raw))
    prefix = {}
    race = {}
    for block, raw in rows:
        if block.height <= 12:
            need(block.height not in prefix, "ambiguous funding prefix")
            prefix[block.height] = raw
        if block.height == 13 and len(block.packets) == 1:
            suite = block.packets[0][:4]
            if suite in (b"MSP1", b"MSP2"):
                need(suite not in race, "ambiguous activation race")
                race[suite] = block.packets[0]
    need(set(prefix) == set(range(1, 13)) and b"MSP1" in race, "incomplete funded control")
    return prefix, race


def replay(ledger, prefix, first, last):
    for height in range(first, last + 1):
        need(ledger.accept(prefix[height])["selected"], "public branch did not advance")


def extend(ledger, miner, packets):
    from chain import mine
    block = mine(ledger.template(miner, packets))
    need(ledger.accept(block)["selected"], "newly mined branch did not advance")
    return block


def run_a(args):
    # The released pre-upgrade decoder cannot parse B. Read only the unique
    # prefix and the A race block with that decoder; B blocks remain opaque.
    from chain import Chain, block_id, decode_block
    import runtime
    from run import Resources
    prefix = {}
    race = []
    for f in (args.public / "blocks").glob("*.bin"):
        raw = f.read_bytes()
        need(block_id(raw).hex() == f.stem, "A block name")
        height = int.from_bytes(raw[73:77], "little")
        if height <= 12:
            need(height not in prefix, "ambiguous A prefix")
            prefix[height] = raw
        elif height == 13 and raw[218:223] == b"MSP1\x01":
            race.append(decode_block(raw).packets[0])
    packet, = race
    with closing(Resources(runtime.config(args.a / "runtime"))) as roles:
        with closing(Chain(args.work / "legacy.sqlite", roles.backend)) as ledger:
            replay(ledger, prefix, 1, 12)
            pk = decode_block(prefix[12]).pk
            for height in range(13, 16):
                raw = extend(ledger, pk, [packet] if height == 15 else [])
                (args.work / f"alt-{height}.bin").write_bytes(raw)


def test(args):
    from chain import Chain, block_id, decode_block, mine, packet_vector
    import runtime
    from run import Resources
    from managed_ops import B_MAGIC
    prefix, race = capture(args.public)
    legacy, successor = race[b"MSP1"], race[b"MSP2"]
    registration, = [p for p in decode_block(prefix[8]).packets if p.startswith(b"MSP1\x01\x02")]
    miner = decode_block(prefix[12]).pk
    with closing(Resources(runtime.config(args.b / "runtime"))) as roles:
        # Use the independently mined complete block as the sole public input
        # for this control. An A-funded input at H11 is live for H12 and H13.
        early = (args.public / "early/BLOCK.bin").read_bytes()
        early_block = decode_block(early)
        early_payment, = early_block.packets
        need(early_payment.startswith(B_MAGIC) and early_block.height == 13
             and early_block.parent == block_id(prefix[12]), "wrong early fixture")
        with closing(Chain(args.work / "early.sqlite", roles.backend)) as node:
            replay(node, prefix, 1, 11)
            old = node.status()
            rejected(lambda: node.offer(early_payment), "inactive proof suite")
            need(node.status() == old and not node.pending(), "early admission mutated state")
            # Verify the genuine proof under its eligible profile and check
            # funding separately against this actual H11 parent/current spent set.
            with node._transaction():
                slot, = node.verify_single(early_payment, 13)
                need(slot.height == 11 and slot.fee == 3 and slot.supply == 0, "early public effects")
                node.check_funding(slot, node._head())
            replay(node, prefix, 12, 12)
            old = node.status()
            need(node.offer(early_payment)["id"] == sha256(early_payment).hexdigest(), "eligible public offer")
            need(node.accept(early)["selected"], "eligible H13 block failed")
            settled = node.status()
            need(settled["height"] == 13 and settled["tip"] == block_id(early).hex() and not node.pending()
                 and settled["spent"] == old["spent"] + 2 and settled["fees"] == old["fees"] + 3
                 and early_block.amount == 103, "eligible early branch accounting")
        with closing(Chain(args.work / "boundary.sqlite", roles.backend)) as node:
            replay(node, prefix, 1, 11)
            # Retain the genuine B proof, and obtain valid work for the precise
            # candidate bytes. Its anchor is H12, so this H12 negative also has
            # a premature anchor. The node must stop at the version rule first.
            premature = mine(prefix[12][:213] + packet_vector([successor]))
            before = node.status()
            rejected(lambda: node.accept(premature), "inactive proof suite")
            need(node.status() == before, "premature proposal changed state")
            replay(node, prefix, 12, 12)
            b_slot, = node.verify_single(successor, 13)
            a_slot, = node.verify_single(legacy, 13)
            need(set(a_slot.nfs) & set(b_slot.nfs), "race misses common funded input")
            issuance, = roles.backend.verify(registration)
            need(issuance.operation == "register" and issuance.supply > 0, "missing positive issuance")
            # Changing outer/inner versions never carries authority to the new key.
            from managed_ops import parse
            old_inner = parse(registration).inner
            rejected(lambda: node.verify_single(B_MAGIC + b"\0" + b"MNG2" + old_inner[4:], 13),
                     "cryptographic payment rejection")
            rejected(lambda: node.verify_single(B_MAGIC + b"\x02" + successor[6:], 13), "B is transfer only")
            # The last five public field words are the asset ID and delta. Give
            # this actual B transfer the original nonzero issuer statement,
            # keeping its complete proof openings and both receipts intact.
            end = len(successor) - 3584
            need(successor[end-40:end] == bytes(40), "expected pure B transfer")
            changed = successor[:end-40] + issuance.issue_id + issuance.supply.to_bytes(8, "little") + successor[end:]
            rejected(lambda: node.verify_single(changed, 13), "cryptographic payment rejection")
            rejected(lambda: node.verify_single(b"MSP1\x01\x01" + legacy[6:], 15), "operation mismatch")
            for h in (13, 14):
                need(node.accept((args.work / f"alt-{h}.bin").read_bytes())["selected"], "alternate branch")
            before = node.status()
            stale = (args.work / "alt-15.bin").read_bytes()
            need(decode_block(stale).packets == (legacy,), "wrong H15 test packet")
            # The original rules just admitted this same block at H15. Its
            # nullifiers, anchor, funding, fee, reward, roots and work were valid.
            rejected(lambda: node.offer(legacy), "inactive proof suite")
            rejected(lambda: node.accept(stale), "inactive proof suite")
            need(node.status() == before and not node.pending(), "retirement mutated state")
        # A non-upgraded process really persisted the now-invalid public H15.
        rejected(lambda: Chain(args.work / "legacy.sqlite", roles.backend), "inactive proof suite")
        with closing(Chain(args.work / "issuance.sqlite", roles.backend)) as node:
            replay(node, prefix, 1, 7)
            need(issuance.height == 7, "captured signed registration must use the H7 anchor")
            for _ in range(8, 15):
                extend(node, miner, [])
            before = node.status()
            event = extend(node, miner, [registration])
            after = node.status()
            asset = node.latest_asset(issuance.issue_id)
            need(asset["supply"] == issuance.supply and asset["authority"] == issuance.public_key
                 and after["spent"] == before["spent"] + 2 and after["fees"] == before["fees"] + 3
                 and decode_block(event).amount == 103, "H15 issuance accounting")
        return dict(early_funded_transfer=dict(anchor=slot.height, fee=slot.fee,
                    tx=sha256(early_payment).hexdigest(), refused_candidate=12, accepted_height=13,
                    accepted_block=block_id(early).hex(), spent_increase=2),
                    premature_block=block_id(premature).hex(), premature_height=12,
                    premature_B_anchor=b_slot.height, premature_reason="inactive proof suite",
                    retired_block=block_id(stale).hex(), retired_height=15, retired_A_anchor=a_slot.height,
                    retired_reason="inactive proof suite", same_block_accepted_by_original_A=True,
                    stale_A_database_reopen="inactive proof suite",
                    rejected_version_relabel=True, rejected_transfer_as_issue=True,
                    rejected_nonzero_B_public_delta_mutation=True,
                    retained_issuance=dict(block=block_id(event).hex(), height=15, anchor=issuance.height,
                    tx=sha256(registration).hexdigest(), asset=issuance.issue_id.hex(), supply=issuance.supply,
                    fee=3, subsidy=100))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("a", "b", "public"):
        p.add_argument(arg, type=lambda name: Path(name).resolve(strict=True))
    p.add_argument("--legacy", dest="work", type=Path, help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.work:
        sys.path.insert(0, str(args.a / "devnet"))
        run_a(args)
        return
    sys.path.insert(0, str(args.b / "devnet"))
    with tempfile.TemporaryDirectory(prefix="funded-fork-check-") as tmp:
        args.work = Path(tmp)
        subprocess.run([sys.executable, "-IB", __file__, args.a, args.b, args.public, "--legacy", tmp], check=True)
        print(json.dumps(test(args), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
