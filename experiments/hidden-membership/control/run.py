"""Independent statement generator and process-isolated linked-parent controls."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fresh-spend" / "binding"))
from relation import (FundedTree, ZERO, credit_occ, funding_asset, leaf, new_note,
                      owner, spend_key)


def parent(level, left, right):
    return hashlib.shake_256(bytes((0xf1, 7, level)) + left + right).digest(64)


def run(binary, directory):
    directory.mkdir(mode=0o700)
    chain = secrets.token_bytes(64)
    asset = funding_asset(chain, secrets.token_bytes(64), secrets.token_bytes(64), 60)
    # An isolated reference prefix holds three native grants and one 60-token issue.
    # Independent opening randomness. Authorizing the grants is outside this gadget.
    entries = []
    for slot in range(4):
        account = owner(spend_key(chain, secrets.token_bytes(64)))
        note = new_note(account, 0, asset, 60) if slot == 2 else new_note(account, 7, ZERO, 0)
        entries.append((credit_occ(chain, secrets.token_bytes(64), 0), note.cm(chain)))
    tree = FundedTree(entries)
    leaves = [leaf(*row) for row in entries]
    expected = tree.layers[2][0]
    root_path = directory / "eligible-two-level-root.bin"
    root_path.write_bytes(expected)
    rows = []
    for position in (0, 1):
        a, b = leaves[2*position:2*position+2]
        sibling = tree.layers[1][position ^ 1]
        digest = parent(0, a, b)

        def root_from(mid):
            return parent(1, sibling, mid) if position else parent(1, mid, sibling)

        if root_from(digest) != expected:
            raise RuntimeError("wallet paths disagree with the preselected subtree")
        # This is a clear cross-check of both full FS01 paths, separate from the two-level proof.
        index = 2 * position
        candidate = leaves[index]
        path = tree.path(index)
        for level, adjacent in enumerate(path):
            pairs = (adjacent, candidate) if (index >> level) & 1 else (candidate, adjacent)
            candidate = parent(level, *pairs)
        if len(path) != 40 or index >= tree.count or candidate != tree.root:
            raise RuntimeError("invalid full reference path")
        fields = a + b + sibling

        def role(action, data, expected, timed=False):
            cmd = [str(binary), action, str(expected)]
            stamp = directory / f"{position}-{action}.time"
            if timed:
                cmd = ["/usr/bin/time", "-o", str(stamp), "-f", "%e %U %S %M", *cmd]
            out = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                                 check=True, env={"LANG": "C"}).stdout
            return out

        proof = role("prove", fields + digest + bytes([position]), root_path, timed=True)
        (directory / f"proof-{position}.bin").write_bytes(proof)
        role("verify", proof, root_path, timed=True)
        role("reject", proof[:-1] + bytes([proof[-1] ^ 1]), root_path)
        # Both permutations have correct independent preimages. Only the copy is false.
        detached_mid = bytes([digest[0] ^ 1]) + digest[1:]
        detached = directory / f"unlinked-root-{position}.bin"
        detached.write_bytes(root_from(detached_mid))
        if detached.read_bytes() == root_path.read_bytes():
            raise RuntimeError("new root unexpectedly matches")
        role("inconsistent", fields + detached_mid + bytes([position]), detached)
        role("reject", proof, detached)
        def timing(action):
            wall, user, system, rss = (directory / f"{position}-{action}.time").read_text().split()
            return dict(wall_s=float(wall), user_s=float(user), sys_s=float(system),
                        peak_KiB=int(rss))
        rows.append(dict(position=position, root_bytes=64, proof_bytes=len(proof),
                         prover=timing("prove"), verifier=timing("verify"),
                         changed_proof_rejected=True, changed_root_rejected=True,
                         inconsistent_witness_rejected=True))
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]))
