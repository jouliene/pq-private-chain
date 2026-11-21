"""Run synthetic monetary conformance vectors; use --write only to regenerate the public answers."""
from dataclasses import replace
from hashlib import sha256
import argparse
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reference as r


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def schedule(i):
    return struct.pack("<4Q", *(731*i+j+1 for j in range(4)))


def build():
    # Small consecutive public integers identify synthetic test data. They are
    # unrelated to keys, outputs, proofs or openings from a funded network.
    alice = r.Authority(schedule(101), schedule(102))
    bob = r.Authority(schedule(201), schedule(202))
    asset = schedule(401)
    native = r.reward(bytes(range(32)), alice.pk, 22)
    managed = r.Note(alice.pk, 12, 28, asset, r.tagged(r.RHO, schedule(20), schedule(21), 0), schedule(405))
    swapped = r.Note(bob.pk, 0, 3, asset, r.tagged(r.RHO, schedule(30), schedule(31), 1),
                     r.swap_output_raw(bytes(range(32)), schedule(407)))
    leaves = [schedule(i) for i in range(14)]
    leaves[0], leaves[4], leaves[13] = native.commitment, managed.commitment, swapped.commitment
    canonical = r.Tree(leaves)

    def spend(note, key, index, tree=canonical):
        return r.Input(key, note, note.nullifier(key.nk, index is None), index,
                       () if index is None else tree.path(index))

    n, m, s = spend(native, alice, 0), spend(managed, alice, 4), spend(swapped, bob, 13)
    empty = r.Note(alice.pk, 0, 0, r.ZERO, schedule(408), schedule(409))
    dummy = spend(empty, alice, None)
    spent = frozenset()
    accepted = r.accept_inputs(canonical, [n,m], spent)
    require(accepted == {n.nullifier, m.nullifier} and not spent, "atomic input-set result")
    r.accept_inputs(canonical, [dummy,s], spent)
    r.accept_inputs(canonical, [s,dummy], spent, swap_leg=True)
    branch_a = r.Anchor(schedule(501), 20, canonical)
    branch_b = r.Anchor(schedule(502), 20, r.Tree(leaves[:-1]))
    selected = r.selected_inputs({20:branch_a}, 27, branch_a.identifier, 20, [n,m], spent)
    require(selected == accepted, "last valid old anchor")
    r.selected_inputs({20:branch_b}, 20, branch_b.identifier, 20,
                      [spend(native,alice,0,branch_b.tree), dummy], spent)

    controls = {}
    def reject(name, function):
        try:
            function()
        except ValueError as error:
            controls[name] = str(error)
        else:
            raise ValueError("reference accepted invalid case: " + name)

    reject("absent_funding", lambda: r.check_input(canonical, replace(s, index=5), spent))
    reject("other_owner", lambda: r.check_input(canonical, replace(m, authority=bob), spent))
    reject("other_key_opening", lambda: r.check_input(canonical, replace(m, authority=r.Authority(alice.ask,bob.nk)), spent))
    reject("different_amount", lambda: r.check_input(canonical, replace(m, note=replace(managed, native=13)), spent))
    reject("different_asset", lambda: r.check_input(canonical, replace(m, note=replace(managed, asset=schedule(402))), spent))
    reject("different_rho", lambda: r.check_input(canonical, spend(replace(managed,rho=schedule(410)),alice,4), spent))
    reject("different_opening", lambda: r.check_input(canonical, spend(replace(managed,raw=schedule(411)),alice,4), spent))
    reject("different_nullifier", lambda: r.check_input(canonical, replace(m,nullifier=s.nullifier), spent))
    reject("missing_path_level", lambda: r.check_input(canonical, replace(n,path=n.path[:-1]), spent))
    reject("padded_leaf", lambda: r.check_input(canonical, replace(s,index=14), spent))
    reject("noncanonical_digest", lambda: r.Tree([struct.pack("<4Q",r.P,0,0,0)]))
    reject("funding_zero", lambda: r.Tree([r.ZERO]))
    reject("duplicate_funding", lambda: r.Tree([native.commitment]*2))
    reject("negative_amount", lambda: replace(native,native=-1).commitment)
    reject("oversize_token", lambda: replace(managed,token=2**62).commitment)
    reject("asset_without_quantity", lambda: replace(managed,token=0).commitment)
    reject("quantity_without_asset", lambda: replace(managed,asset=r.ZERO).commitment)
    reject("oversize_asset_limb", lambda: replace(managed,asset=struct.pack("<4Q",2**63,0,0,0)).commitment)
    reject("rank_out_of_range", lambda: r.path_root(native.commitment,(replace(n.path[0],sorted_position=4),*n.path[1:]),14))
    reject("wrong_depth", lambda: r.path_root(native.commitment,n.path[:1],14))
    reject("tree_capacity", lambda: r.tree_depth(4**20+1))
    reject("same_input_twice", lambda: r.accept_inputs(canonical,[n,n],spent))
    reject("already_spent", lambda: r.accept_inputs(canonical,[n,m],accepted))
    reject("dummy_has_value", lambda: r.accept_inputs(canonical,[spend(managed,alice,None),n],spent))
    reject("two_dummies", lambda: r.accept_inputs(canonical,[dummy,dummy],spent))
    reject("dummy_first_swap", lambda: r.accept_inputs(canonical,[dummy,s],spent,swap_leg=True))
    reject("orphan_anchor", lambda: r.selected_inputs({20:branch_b},20,branch_a.identifier,20,[n,dummy],spent))
    reject("spent_after_anchor", lambda: r.selected_inputs({20:branch_a},23,branch_a.identifier,20,[n,m],accepted))
    reject("expired_anchor", lambda: r.selected_inputs({20:branch_a},28,branch_a.identifier,20,[n,m],spent))
    require(spent == frozenset() and selected == accepted, "input rejection changed caller state")

    # Independent known answers are the released upstream full tree, including
    # all observed depth changes through 260 leaves (no program from a proof).
    released = json.loads((HERE.parent / "advancing-payments/review/REFERENCE_ROOTS.json").read_bytes())
    for key, expected in released["prefix_roots"].items():
        require(r.Tree(schedule(i) for i in range(int(key))).root.hex() == expected, "upstream root "+key)
    permuted = list(leaves)
    permuted[0], permuted[1] = permuted[1], permuted[0]
    require(r.Tree(permuted).root == canonical.root, "sibling permutation")
    permuted = list(leaves)
    permuted[0], permuted[4] = permuted[4], permuted[0]
    require(r.Tree(permuted).root != canonical.root, "cross-quartet regrouping")
    require(r.Tree([]).root == r.ZERO and r.tree_depth(4**20) == 20 and r.tree_depth(1) == 1, "tree boundaries")
    return dict(profile="funded-membership-oracle-v1", upstream_prefix_roots_checked=len(released["prefix_roots"]),
                depth_boundaries={str(n):r.tree_depth(n) for n in (0,1,3,4,5,16,17,4**20-1,4**20)},
                selected_count=canonical.count, selected_root=canonical.root.hex(),
                schedule="test-only digest(i) = concatenate u64LE(731*i+j+1) for j=0,1,2,3",
                public_effects={label:dict(pk=w.note.pk.hex(), commitment=w.note.commitment.hex(),
                                          nullifier=w.nullifier.hex(), occurrence=w.index,
                                          sorted_positions=[level.sorted_position for level in w.path])
                                for label,w in (("reward",n),("managed",m),("swap",s),("dummy",dummy))},
                negative_controls=controls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    encoded = (json.dumps(build(), sort_keys=True, indent=2) + "\n").encode()
    path = HERE / "vectors.json"
    if args.write:
        path.write_bytes(encoded)
    else:
        require(path.read_bytes() == encoded, "published vector mismatch")
    print(json.dumps(dict(conformant=True, vectors_sha256=sha256(encoded).hexdigest())))
