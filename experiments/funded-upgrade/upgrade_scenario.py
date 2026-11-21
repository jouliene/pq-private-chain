"""Run signed transfers, atomic swaps and competing, independently mined activation histories."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import time


def need(condition, message):
    if not condition:
        raise ValueError(message)


def client(w, node, command, *args, suite="auto"):
    p = subprocess.run([w.ROOT / "pqd", "upgrade",
                        "--home", w.HOME, "--node", node, "--suite", suite, command, *map(str, args)],
                       capture_output=True, timeout=240)
    if p.returncode:
        raise ValueError(f"{command} wallet command failed: {p.stderr.decode()[-560:]}")
    return json.loads(p.stdout)


def included(w, node, raw):
    w.lab.mine(node, 1)
    head = w.state(node)
    block = w.decode_block(w.lab.request(node, "block", id=head["tip"])[1])
    packets = tuple(w.split(raw)) if raw.startswith(b"SWB2") else (raw,)
    need(tuple(block.packets) == packets and block.amount == 103, "unexpected mined packet or fee credit")
    w.retain(node, head["tip"])
    return head


def transfer(w, node, label, sender, receiver, native, asset, quantity, *, suite="auto"):
    res = client(w, node, "send", sender, receiver, native, asset, quantity, "--intent", label, suite=suite)
    raw = w.lab.request(node, "tx", id=res["tx"])[1]
    need(res["tx"] == sha256(raw).hexdigest() and raw[:4] == (b"MSP1" if suite == "A" else b"MSP2"),
         "node returned a different packet or suite")
    keys = ("tx", "packet_B", "real_inputs", "fee", "asset_id", "operation", "anchor_height", "change",
            "token_change", "proving_wall_s", "prover_cpu_s", "prover_role_peak_rss_KiB", "submission_frame")
    w.r["ordinary"][label] = {key: res[key] for key in keys}
    return raw


def swap(w, node, fixed, managed):
    path = w.N / "trade.terms"
    addresses = {who: "@" + str(w.N / (who + ".addr")) for who in ("alice", "bob")}
    expiry = w.state(node)["height"] + 8
    client(w, node, "terms", "alice", addresses["bob"], fixed, 7, managed, 9, expiry, path)
    offers, signatures = [w.N / (n + ".leg") for n in ("a", "b")], [w.N / (n + ".sig") for n in ("a", "b")]
    metrics = []
    for i, (side, owner, other, give, take, fee) in enumerate((
            ("a", "alice", "bob", (fixed, 7), (managed, 9), 3),
            ("b", "bob", "alice", (managed, 9), (fixed, 7), 0))):
        row = client(w, node, "leg", owner, side, path, *give, *take, offers[i],
                     "--counterparty", addresses[other], "--expiry", expiry, "--fee", fee)
        metrics.append({k: row[k] for k in ("packet_B", "fee", "real_inputs", "proving_wall_s", "prover_cpu_s",
                                               "prover_role_peak_rss_KiB")})
    for i, owner in enumerate(("alice", "bob")):
        client(w, node, "authorize", owner, "ab"[i], path, *offers, signatures[i])
    output = w.PUBLIC / "SWAP.bin"
    result = client(w, node, "combine", path, *offers, *signatures, output)
    raw = output.read_bytes()
    need(raw.startswith(b"SWB2") and len(w.split(raw)) == 2, "incorrect B swap envelope")
    meter = {}
    reply, _ = w.lab.request(node, "submit", raw, meter=meter)
    need(reply["id"] == sha256(raw).hexdigest(), "swap admission identity")
    w.r["swap"] = dict(result, legs=metrics, expiry=expiry, upload=meter, frame_B=list(map(len, w.split(raw))),
                       negotiation_B=sum(f.stat().st_size for f in (path, *offers, *signatures)))
    return raw


def measure_restore(w, node, owner, managed):
    alias = "offline-restored"
    need(not w.lab.walletdir(alias).exists() and {p.name for p in w.lab.walletdir(owner).iterdir()} == {"address", "seed"},
         "offline receiver has already scanned")
    restore = client(w, node, "restore", alias, w.BACKUPS / owner)
    need((restore["balance"], restore["assets"], restore["notes"]) == (20, {managed: 12}, 1),
         "seed-only recovery of sole A note failed")
    sync = restore["sync"]
    need(sync["complete"] and sync["start_height"] == 0 and sync["end_height"] == w.state(node)["height"],
         "restore missed selected public history")
    w.r["recovery"] = dict(backup_B=32, start_height=0, empty_destination=True, notes=1, native=20,
                            asset=managed, quantity=12, sync={k: sync[k] for k in (
                                "blocks", "end_height", "request_B", "reply_B", "public_body_B", "wall_s",
                                "wallet_db_B", "controller_cpu_s", "controller_peak_rss_KiB",
                                "native_wallet", "native_hash")})


def fresh(w, winner, final):
    """A separate node home contains only public network settings and its own new database."""
    from cli import Lab
    public_home = w.HOME / "replay-home"
    public_home.mkdir(mode=0o700)
    dest = public_home / "nodes/d"
    dest.mkdir(parents=True)
    shutil.copyfile(w.HOME / "network.json", public_home / "network.json")
    shutil.copyfile(w.HOME / "nodes/d/miner.pk", dest / "miner.pk")
    (dest / "peers.json").write_text("[]")
    replay = Lab(public_home, w.HOME / "deployment/runtime")
    need(not (dest / "chain.sqlite").exists() and not (public_home / "wallets").exists(), "nonempty public replay")
    try:
        start = time.monotonic()
        initial = replay.launch("d")
        need(initial["height"] == 0 and initial["tip"] == w.GENESIS.hex(), "public replay did not start at original genesis")
        replay.links("d", [winner])
        w.wait(lambda: replay.status("d"), lambda s: {k: s[k] for k in w.FIELDS} == final, "public-only replay")
        w.r["fresh_node"] = dict(initial_height=0, final_height=final["height"], winning_tip=final["tip"],
                                  own_wallets=0, seconds=time.monotonic()-start,
                                  sqlite_B=(dest / "chain.sqlite").stat().st_size)
    finally:
        # The other peers are managed by the original lab and use separate control sockets.
        try:
            replay.admin("d", "stop")
        except (FileNotFoundError, ConnectionRefusedError):
            pass


def activate(w):
    w.r.update(json.loads((w.PUBLIC / "PREFIX.json").read_bytes()))
    baseline = w.r["tips"]["common"]
    fixed, managed = (w.r["asset_ids"][k] for k in ("fixed", "managed"))
    w.lab.start(manual=True)
    need(w.agree("abc") == baseline, "upgraded peers diverged from the original funded prefix")
    w.isolate()
    # Both branches share the same sole real input, same height and same eligible anchor.
    client(w, "b", "restore", "conflict-b", w.BACKUPS / "conflict")
    legacy = transfer(w, "a", "a-conflict", "conflict", "rival", 8, "native", 0, suite="A")
    new = transfer(w, "b", "b-conflict", "conflict-b", "recipient", 9, "native", 0)
    # Duplicate, competing proposals see the same local mempool spent set.
    w.reject("a-pool-then-b", "a", new, "pool conflict")
    w.reject("b-pool-then-a", "b", legacy, "pool conflict")
    a13, b13 = included(w, "a", legacy), included(w, "b", new)
    w.r["tips"].update(a_overlap=a13, b_overlap=b13)
    need(a13["height"] == b13["height"] == 13 and a13["tip"] != b13["tip"], "wrong fork height")
    w.reject("a-spent-then-b", "a", new, "spent nullifier")
    w.reject("b-spent-then-a", "b", legacy, "spent nullifier")
    # C first selects A, then switches across activation onto B, including the different spend.
    w.link("ac")
    w.agree("ac")
    w.snapshot("a_selected", "c", ("conflict", "rival", "recipient"))
    w.isolate()
    w.lab.mine("b", 2)
    w.link("bc")
    w.agree("bc")
    w.snapshot("b_selected", "c", ("conflict", "rival", "recipient"))
    need(w.r["balances"]["a_selected"]["rival"]["native"] == 8 and
         w.r["balances"]["b_selected"]["rival"]["native"] == 0 and
         w.r["balances"]["b_selected"]["recipient"]["native"] == 9, "wrong conflict after reorg")
    w.reject("retired-a", "c", legacy, "inactive proof suite")
    measure_restore(w, "b", "offline", managed)
    pay = transfer(w, "b", "restored-a-to-b", "offline-restored", "forward", 12, managed, 8)
    included(w, "b", pay)
    w.agree("bc")
    need(w.holdings("forward", "c") == dict(native=12, assets={managed: 8}), "wrong recovered transfer")
    further = transfer(w, "b", "b-to-b", "forward", "recipient", 5, managed, 6)
    included(w, "b", further)
    w.agree("bc")
    signed = swap(w, "b", fixed, managed)
    settled = included(w, "b", signed)
    w.agree("bc")
    users = ("alice", "bob", "offline-restored", "forward", "recipient", "rival", "conflict")
    w.snapshot("b_settled", "c", users)
    want = {"alice": (37, {fixed: 23, managed: 9}), "bob": (24, {fixed: 7, managed: 41}),
            "offline-restored": (5, {managed: 4}), "forward": (4, {managed: 2}),
            "recipient": (14, {managed: 6}), "rival": (0, {}), "conflict": (8, {})}
    need(w.r["balances"]["b_settled"] == {k: dict(native=n, assets=t) for k, (n,t) in want.items()},
         "post-upgrade holdings differ from independently calculated amounts")
    need(settled["fees"] == 30 and settled["spent"] == baseline["spent"] + 10, "B branch accounting")
    # Reorganize away all B effects and then reselect those exact original funded blocks.
    w.isolate()
    w.lab.mine("a", settled["height"] + 1 - w.state("a")["height"])
    w.link("ac")
    w.agree("ac")
    detached = w.snapshot("b_detached", "c", users)
    bal = w.r["balances"]["b_detached"]
    need((detached["fees"], detached["spent"]) == (21, baseline["spent"]+2) and
         bal["offline-restored"] == dict(native=20, assets={managed: 12}) and
         bal["forward"] == dict(native=0, assets={}) and bal["recipient"] == dict(native=0, assets={})
         and bal["alice"] == w.r["balances"]["common"]["alice"] and bal["bob"] == w.r["balances"]["common"]["bob"],
         "incomplete rollback across activation")
    w.isolate()
    w.lab.mine("b", detached["height"] + 1 - w.state("b")["height"])
    w.link("abc")
    final = w.agree("abc")
    full = (*users, "miner-a", "miner-b")
    w.snapshot("final", "c", full)
    rows = w.r["balances"]["final"]
    need(all(rows[k] == w.r["balances"]["b_settled"][k] for k in users)
         and final["fees"] == settled["fees"] and final["spent_set_sha256"] == settled["spent_set_sha256"]
         and w.r["registries"]["final"] == w.r["registries"]["common"], "reapplication changed a prior effect")
    need(sum(v["native"] for v in rows.values()) == final["issued"] and
         all(sum(v["assets"].get(asset, 0) for v in rows.values()) == w.r["registries"]["final"][asset]["supply"]
             for asset in (fixed, managed)), "native or token supply failed reconciliation")
    fresh(w, "c", final)
    (w.PUBLIC / "RUN.json").write_text(json.dumps(w.r, indent=2, sort_keys=True)+"\n")
    print(json.dumps(dict(height=final["height"], fees=final["fees"], replay=final["tip"])))
