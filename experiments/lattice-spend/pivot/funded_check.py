"""Memory-only migration diagnostics for the four released one-seed workers."""
import copy
from hashlib import sha256
import json
from pathlib import Path
import struct

import check as released
import pivot


SHAPES = {
    "MNG1": "b60397b80e6bd46da58648ea3ecfebef7cb4d8b153795c41a4c5b0e0f86697f2",
    "SLG1": "77533cc1c383bec78358ae8b304a1151aab834c34656d2edcc167dccdaf1c339",
}


def encoded(words):
    return struct.pack("<4Q", *words)


def checked(condition, label):
    if not condition:
        raise ValueError(label)


def selected_history(params, head):
    # The calling worker has already run the deployed validator on this branch.
    from chain import GENESIS, block_id, decode_block

    tip = bytes.fromhex(head["tip"])
    blocks = []
    while tip != GENESIS:
        raw = (Path("/source/public/blocks") / (tip.hex() + ".bin")).read_bytes()
        checked(block_id(raw) == tip, "different block id during pivot replay")
        block = decode_block(raw)
        blocks.append(block)
        tip = block.parent
    leaves = []
    spent = set()
    for height, block in enumerate(reversed(blocks), 1):
        checked(block.height == height, "noncontiguous pivot history")
        for packet in block.packets:
            public, receipts = released.inner(packet)
            checked(released.receipt_digest(params, receipts) == public[22:26],
                    "selected history receipt projection differs")
            spent.update(encoded(public[i:i+4]) for i in (5, 9))
            leaves.extend(encoded(public[i:i+4]) for i in (13, 17))
        leaves.append(block.reward_cm)
        checked(released.tree(params, leaves, 0)[0] == block.root, "wrong legacy branch root")
    checked(len(blocks) == head["height"] and len(leaves) == head["notes"] and
            blocks[0].root == bytes.fromhex(head["header"])[-32:], "wrong funded snapshot")
    return leaves, spent


def input_identity(params, witness, note):
    f = pivot.f

    def tag(domain, *parts):
        return released.sponge(params, [domain, *(x for part in parts for x in part)])

    asset = witness["asset_id"] if note["token"] else [0]*4
    opening = tag(f.OPEN, asset, [note["token"]], note["raw"])
    pk = tag(f.PK, tag(f.AK, note["ask"]), note["nk"])
    cm = tag(f.CM, tag(f.NOTE, pk, note["rho"], opening), [note["value"]])
    nf = tag(f.NF_DUMMY if note["dummy"] else f.NF, note["nk"], note["rho"], opening)
    return encoded(cm), encoded(nf)


def shared_nullifier_policy(spent, registered_effects):
    """Local proposed dual-registration admission rule, without a chain mutation."""
    def admit(registration, ledger):
        nfs = registered_effects[registration]
        if len(set(nfs)) != len(nfs) or ledger.intersection(nfs):
            return False
        ledger.update(nfs)
        return True

    for first, second in (("legacy", "fixed-parent"), ("fixed-parent", "legacy")):
        fresh = set(spent)
        checked(admit(first, fresh), "initial funded candidate conflicts")
        after_first = fresh.copy()
        checked(not admit(second, fresh) and fresh == after_first,
                "shared spent set accepted a second registration")


def check(role, suite, params, w):
    """Called after the released proof, both old circuits and actual receipts pass."""
    checked((role in ("ordinary", "onward") and suite == "MNG1") or
            (role in ("leg-a", "leg-b") and suite == "SLG1"), "unexpected funded role")
    tips = json.loads(Path("/peers/ledger.json").read_text())["tips"]
    head = tips["swap_included" if role == "onward" else "common"]
    public = w["public"]
    checked(encoded(public[:4]).hex() == head["anchor"] and public[4] == head["height"],
            "wrong released anchor or height")
    leaves, spent = selected_history(params, head)
    branch_root = pivot.tree(params, leaves, 0)[0]
    private = copy.deepcopy(w)
    private["public"] = [*public, *struct.unpack("<4Q", branch_root)]
    active_cms = []
    real_nfs = []
    for i, note in enumerate(private["inputs"]):
        cm, nf = input_identity(params, w, note)
        checked(nf == encoded(public[5+4*i:9+4*i]), "nullifier differs on migration")
        if note["dummy"]:
            checked(note["value"] == note["token"] == 0, "nonzero dummy on migration")
            continue
        checked(leaves.count(cm) == 1, "owned commitment absent or nonunique")
        pos = leaves.index(cm)
        legacy_root = released.tree(params, leaves, pos)[0]
        checked(legacy_root == encoded(w["header"][13:17]), "funded leaf has wrong old root")
        root, neighbors, directions = pivot.tree(params, leaves, pos)
        checked(root == branch_root and len(directions) == w["depth"], "funded leaf has wrong new root")
        note.update(siblings=neighbors, positions=directions)
        active_cms.append(cm)
        real_nfs.append(nf)
    checked(bool(real_nfs) and len(set(real_nfs)) == len(real_nfs), "no distinct real spend")
    if role == "onward":
        import swap_wire
        frames = swap_wire.pair(swap_wire.split(Path("/source/swap.bin").read_bytes()))
        peer_effects, _ = released.inner(frames[1].leg)
        checked(active_cms == [encoded(peer_effects[13:17])],
                "restored spend did not use counterparty output zero")
    c, program = pivot.compile_full(suite, params, private, register=True)
    checked(sha256(program).hexdigest() == SHAPES[suite], "pivot funded shape changed")
    checked(not c.failures and released.e.evaluate(program, c.z, private["public"]),
            "pivot funded relation refused")
    # The wrapper's preceding released.full checked the actual ordered 3584
    # receipt bytes against these very same words; the pivot changes no ciphertext.
    projected = [c.val(word) for word in c.public]
    checked(projected[:-4] == public and projected[22:26] == w["ct_digest"]
            and encoded(projected[-4:]) == branch_root, "pivot changed released effects")
    same_nfs = {
        "legacy": tuple(encoded(public[j:j+4]) for j in (5, 9)),
        "fixed-parent": tuple(encoded(projected[j:j+4]) for j in (5, 9)),
    }
    checked(same_nfs["legacy"] == same_nfs["fixed-parent"], "different spent identities")
    shared_nullifier_policy(spent, same_nfs)
    return True
