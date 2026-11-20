"""Exercise a fee-free token seller, native recovery and conflicting live PoW branches."""
from contextlib import closing
import fcntl
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys

# Isolated Python omits the script directory. Reuse the established operator harness.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from walkthrough import (
    BACKUPS, HOME, N, PUBLIC, GENESIS, NETWORK, agree, assemble, cmd, decode_block,
    expect, isolate, lab, link, ordinary, pair, r, reject, snapshot, split, state, wait,
)
from chain import SUBSIDY
from transport import rpc


def balance(native, assets=None):
    return dict(native=native, assets=assets or {})


def agreement(label, managed, delivery, quantity, expiry):
    path = N / (label + ".terms")
    result = cmd("terms", "alice", "@" + str(N / "bob.addr"), managed, 20,
                 delivery, quantity, expiry, path, "--payer", "b")
    expect(result["payer"] == "b", "counterparty must pay the native fee")
    return path, bytes.fromhex(result["terms_commitment"])


def offer(label, wallet, side, terms, managed, delivery, quantity, expiry):
    path = N / (label + ".leg")
    give, take = (managed, 20), (delivery, quantity)
    if side == "b":
        give, take = take, give
    other = "bob" if side == "a" else "alice"
    metrics = cmd("leg", wallet, side, terms, *give, *take, path, "--counterparty",
                  "@" + str(N / (other + ".addr")), "--expiry", expiry,
                  "--fee", 0 if side == "a" else 3)
    return path, metrics


def reject_delivery(label, managed, delivery, quantity, expiry, accepted, commitment, seller_leg):
    alternate, _ = agreement(label, managed, delivery, quantity, expiry)
    candidate, metrics = offer(label, "bob-rival", "b", alternate, managed, delivery, quantity, expiry)
    output = N / (label + ".sig")
    before = state("c")
    pending = lab.request("c", "pending")[0]
    error = cmd("authorize", "alice", "a", accepted, seller_leg, candidate, output,
                error="wallet cannot open the committed output under its spending keys for the agreed amounts")
    expect(not output.exists() and state("c") == before and lab.request("c", "pending")[0] == pending,
           "bad delivery changed the wallet signature file or public state")
    path = lab.walletdir("alice") / "mng1-intents.sqlite"
    with closing(sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT state,joint,signature FROM swap_sessions WHERE terms=? AND side=0",
                         (commitment,)).fetchone()
    expect(row == ("offered", None, None), "seller released an authorization for a wrong receipt")
    expect(cmd("abort", "bob-rival", "b", alternate)["state"] == "aborted", "control input release")
    r["checks"][label] = dict(error=error, genuine_proved_offer=True, final_signature_released=False,
                             submitted=False, fee=metrics["fee"], real_inputs=metrics["real_inputs"],
                             offer_B=candidate.stat().st_size)


def enrolled():
    for owner in ("alice", "bob", "rival", "forward"):
        cmd("create", owner)
    for owner in ("alice", "bob"):
        cmd("export-address", owner, N / (owner + ".addr"))
        dest = BACKUPS / owner
        dest.mkdir(mode=0o700, parents=True)
        cmd("backup", owner, dest / "seed")
        expect((dest / "seed").stat().st_size == 32, "backup size")
    for node in "ab":
        lab.mine(node, 3)
        agree("abc")
    managed = ordinary("managed", ("register", "miner-b", 100), "b")["asset_id"]
    fixed = ordinary("fixed", ("issue", "miner-a", 8))["asset_id"]
    ordinary("usd-funding", ("send", "miner-b", "alice", 0, managed, 100), "b")
    ordinary("native-funding", ("send", "miner-a", "bob", 25, "native", 0))
    ordinary("substitute-funding", ("send", "miner-a", "bob", 0, fixed, 8))
    r["asset_ids"] = dict(managed=managed, substitute=fixed)
    initial = snapshot("funded", "c")
    expect(r["balances"]["funded"] == {"alice": balance(0, {managed: 100}), "bob": balance(25, {fixed: 8})},
           "seller or counterparty funding mismatch")
    expect(r["registries"]["funded"][managed]["supply"] == 100 and
           r["registries"]["funded"][fixed]["supply"] == 8 and initial["fees"] == 15, "funding supply or fees")
    cmd("restore", "bob-rival", BACKUPS / "bob" / "seed")
    return managed, fixed, initial


def negotiate(managed, fixed, initial):
    expiry = initial["height"] + 5
    terms, commitment = agreement("accepted", managed, "native", 8, expiry)
    a, ma = offer("a", "alice", "a", terms, managed, "native", 8, expiry)
    lab.mining("b", 1)
    b, mb = offer("b", "bob", "b", terms, managed, "native", 8, expiry)
    wait(lambda: lab.status("b"), lambda s: s["remaining"] == 0, "independent negotiation block")
    moving = agree("abc")
    expect(moving["height"] > initial["height"], "no block between the two offers")
    expect((ma["real_inputs"], ma["fee"], ma["native_change"], ma["token_change"]) == (1, 0, 0, 80)
           and (mb["real_inputs"], mb["fee"], mb["native_change"], mb["token_change"]) == (1, 3, 14, 0),
           "real funding, change or payer differs from negotiated amounts")
    reject_delivery("short", managed, "native", 7, expiry, terms, commitment, a)
    reject_delivery("substitute", managed, fixed, 8, expiry, terms, commitment, a)
    sig_a, sig_b = N / "a.sig", N / "b.sig"
    d1 = cmd("authorize", "alice", "a", terms, a, b, sig_a)
    r["checks"]["missing_counter_authority"] = cmd("combine", terms, a, b, sig_a, sig_a,
                                                   N / "half.bin", error="proposal lacks")
    d2 = cmd("authorize", "bob", "b", terms, a, b, sig_b)
    expect(d1["digest"] == d2["digest"], "owners signed different joint messages")
    target = PUBLIC / "SWAP.bin"
    joined = cmd("combine", terms, a, b, sig_a, sig_b, target)
    raw = target.read_bytes()
    frames = split(raw)
    left, right = pair(frames)
    expect(left.payer == right.payer == 1, "signed header assigns fee to wrong participant")
    r["swap"] = dict(joined, expiry=expiry, payer="b", leg_B=[a.stat().st_size, b.stat().st_size],
                     frame_B=list(map(len, frames)), wallet_A=ma, wallet_B=mb, physical_block_slots=2)
    r["negotiation_B"] = {key: path.stat().st_size for key, path in
                          dict(terms=terms, offer_A=a, offer_B=b, auth_A=sig_a, auth_B=sig_b).items()}
    reject("incomplete", "c", frames[0], "incomplete atomic swap")
    reject("missing-first", "c", frames[1], "incomplete atomic swap")
    changed = bytes([left.terms[0] ^ 1]) + left.terms[1:]
    legs, signatures = (left.leg, right.leg), (left.signature, right.signature)
    reject("changed-terms", "c", assemble(NETWORK, changed, expiry, 1, legs, signatures),
           "invalid swap authorization")
    reject("changed-payer", "c", assemble(NETWORK, left.terms, expiry, 0, legs, signatures), "swap fee payer")
    return target, moving, expiry


def submit_and_spend(target, managed, fixed, common):
    raw = target.read_bytes()
    upload = cmd("submit", target, "--node", "a")
    advert, fetch = {}, {}
    ids, _ = rpc(lab.cfg["ports"]["a"], "pending", meter=advert)
    expect(ids == [sha256(raw).hexdigest()], "incomplete relay inventory")
    _, relayed = rpc(lab.cfg["ports"]["a"], "tx", id=ids[0], meter=fetch)
    expect(relayed == raw and cmd("submit", target, "--node", "a")["duplicate"], "relay or duplicate admission")
    r["swap"].update(upload=upload, relay_readback=dict(public_inventory=advert, whole_bundle_fetch=fetch))
    lab.mine("a", 1)
    included = state("a")
    block = decode_block(lab.request("a", "block", id=included["tip"])[1])
    expect(tuple(block.packets) == tuple(split(raw)) and block.amount == SUBSIDY + 3 and
           included["fees"] == common["fees"] + 3 and included["spent"] == common["spent"] + 4,
           "inclusion must settle and credit both legs together")
    observed = lab.request("a", "supply-observation", txs=r["swap"]["frame_ids"])[0]["events"]
    expect(all(e and e["op"] == "swap" and e["quantity"] == 0 for e in observed), "swap changed public supply")

    # No seller process runs between final authorization and inclusion. Only the pre-negotiation seed
    # is passed to a new alias, which scans selected public history before the next ordinary transfer.
    restored = "alice-restored"
    expect(not lab.walletdir(restored).exists(), "recovery destination must be empty")
    recovered = cmd("restore", restored, BACKUPS / "alice" / "seed", "--node", "a")
    expect((recovered["assets"], recovered["balance"]) == ({managed: 80}, 8), "seed-only incoming receipt recovery")
    r["checks"]["restore"] = dict(empty_destination=True, seed_B=32, native=8, dollars=80)
    snapshot("swap_included", "a", (restored, "bob"))
    expect(r["balances"]["swap_included"]["bob"] == balance(14, {managed: 20, fixed: 8}), "buyer receipt or change")
    transfer = ordinary("respend-a", ("send", restored, "forward", 5, "native", 0), "a", "a")
    expect(transfer["real_inputs"] == 1 and transfer["fee"] == 3, "ordinary spend must use the recovered 8")
    spent = snapshot("native_respent", "a", (restored, "forward"))
    expect(r["balances"]["native_respent"] == {restored: balance(0, {managed: 80}), "forward": balance(5)}
           and spent["fees"] == included["fees"] + 3 and spent["spent"] == included["spent"] + 2,
           "native output, ordinary fee or restored seller balance")
    return included


def competing_branches(target, managed, fixed, expiry, common):
    ordinary("competing-ordinary", ("send", "bob-rival", "rival", 2, "native", 0), "b", "b")
    reject("ordinary-conflict", "b", target.read_bytes(), "spent nullifier")
    lab.mine("c", expiry - state("c")["height"])
    expired = snapshot("expiry_branch", "c", ("bob",))
    expect(expired["spent"] == common["spent"] and expired["fees"] == common["fees"], "empty branch took fees")
    reject("expired", "c", target.read_bytes(), "swap expired")
    lab.mine("a", expiry + 1 - state("a")["height"])
    link("ac")
    agree("ac")
    owners = ("alice-restored", "bob", "forward", "rival")
    active = snapshot("before_reorg", "c", owners)
    isolate()
    lab.mine("b", expiry + 3 - state("b")["height"])
    link("bc")
    agree("bc")
    detached = snapshot("swap_detached", "c", owners)
    expect(r["balances"]["swap_detached"] == {"alice-restored": balance(0, {managed: 100}),
           "bob": balance(20, {fixed: 8}), "rival": balance(2), "forward": balance(0)}
           and detached["spent"] == common["spent"] + 2 and detached["fees"] == common["fees"] + 3,
           "detached swap or dependent native payment retained effects")
    lab.mine("a", expiry + 5 - state("a")["height"])
    link("abc")
    agree("abc")
    restored = snapshot("swap_restored", "c", owners)
    expect(r["balances"]["before_reorg"] == r["balances"]["swap_restored"]
           and restored["spent"] == active["spent"] == common["spent"] + 6
           and restored["fees"] == active["fees"] == common["fees"] + 6, "reorg restored partial or repeated effects")


def run():
    start = lab.start(manual=True)
    r["scenario"] = "native-currency"
    r["miner_keys"] = {("miner-" + n): (HOME / "nodes" / n / "miner.pk").read_text().strip() for n in "abc"}
    managed, fixed, initial = enrolled()
    target, moving, expiry = negotiate(managed, fixed, initial)
    common = snapshot("common", "c", ("bob",))
    isolate()
    included = submit_and_spend(target, managed, fixed, common)
    competing_branches(target, managed, fixed, expiry, common)
    final = agree("abc")
    expect(not (HOME / "nodes/d/chain.sqlite").exists(), "fresh node database exists")
    origin = lab.launch("d")
    expect(origin["height"] == 0 and origin["tip"] == GENESIS.hex(), "fourth node did not start at genesis")
    lab.links("d", ["c"])
    expect(agree("cd") == final, "fresh public node replay diverged")
    names = ("alice-restored", "bob", "forward", "rival", "miner-a", "miner-b")
    snapshot("final", "d", names)
    h = r["balances"]["final"]
    expect(h["alice-restored"] == balance(0, {managed: 80}) and h["forward"] == balance(5)
           and h["bob"] == balance(14, {fixed: 8, managed: 20}) and h["rival"] == balance(0),
           "selected ledger wallet totals")
    expect(all(sum(row["assets"].get(tag, 0) for row in h.values()) == total == r["registries"]["final"][tag]["supply"]
               for tag, total in ((managed, 100), (fixed, 8))), "outstanding token discrepancy")
    expect(sum(row["native"] for row in h.values()) == final["issued"] and final["fees"] == 21,
           "native issuance or fee reconciliation")
    r["fresh_node"] = dict(initial_height=0, final_height=final["height"], winning_tip=final["tip"])
    r["peer_pids_preserved"] = all(lab.status(n)["pid"] == start[n]["pid"] for n in "abc")
    expect(r["peer_pids_preserved"], "original peer process replaced during walkthrough")
    r["moving"] = dict(before_first_leg=initial["height"], after_second_leg=moving["height"],
                       inclusion_height=included["height"])
    r["gross_miner_credits"] = final["issued"] + final["fees"]
    (PUBLIC / "RUN.json").write_text(json.dumps(r, sort_keys=True, indent=2) + "\n")
    return dict(height=final["height"], fees=final["fees"], swap_fee=3, seller_native=0,
                seller_dollars=80, payment_native=5, packet_B=target.stat().st_size, public=str(PUBLIC))


if __name__ == "__main__":
    with (HOME / ".walkthrough.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        expect(not any((HOME / k).exists() for k in ("nodes", "wallets", "network.json", "public", "negotiation",
                                                      "owner-backups")), "walkthrough needs unused node and wallet stores")
        N.mkdir(mode=0o700)
        for name in ("blocks", "packets", "controls"):
            (PUBLIC / name).mkdir(parents=True)
        try:
            print(json.dumps(run(), indent=2))
        finally:
            if (HOME / "network.json").exists():
                lab.stop()
