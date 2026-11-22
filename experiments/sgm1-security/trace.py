"""Replay a public funded proof and census the exact registered transcript and degree openings."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
EX = HERE.parent
sys.path.insert(0, str(EX / "structured-keccak" / "harness"))
from payment_role import FLATTEN, build_payment, parse_head, replay, run
from payment_codec import Ordinary
from early_degree import EarlyDegreeEnvelope
import backend
import numpy as np
import proof
from ring_switch import PROFILE as P
from subfield import F, feval, fmul, freduce
from transcript import Transcript


def census(directory, pin, early, all_events):
    chain, root, count = replay.public_state(str(directory / "prefix"), pin, False)
    wire = (directory / "payment.bin").read_bytes()
    envelope = EarlyDegreeEnvelope if early else Ordinary
    if len(wire) > 262144 or int.from_bytes(wire[3982:3990], "little") != len(wire) - 3990:
        raise ValueError("invalid outer proof extent")
    st = parse_head(wire[:3982], pin, chain, root, count, envelope=envelope)
    schedule, columns, indices = [], [], []
    groups = defaultdict(Counter)
    recorded = {}

    def event(kind, label, size):
        name = label.decode("ascii") if label.isascii() and label.decode("ascii").isprintable() else "registered ring id, parameters and dimensions"
        schedule.append((kind, name, size))
        groups[name][kind + "_calls"] += 1
        groups[name][kind + "_bytes"] += size

    class Observed(Transcript):
        def message(self, label, length, value=None):
            v = super().message(label, length, value)
            event("message", label, length)
            if label == b"mixed open column":
                columns.append(np.frombuffer(v, F))
            elif label == b"explicit degree table v1":
                recorded["table"] = bytes(v)
            return v

        def challenge(self, label, n):
            values = super().challenge(label, n)
            event("coin", label, n * 32)
            if label in (b"mixed opening indices", b"mixed degree matrix"):
                symbols = np.frombuffer(b"".join(x.to_bytes(32, "little") for x in values), F)
                if label == b"mixed degree matrix":
                    recorded["gamma"] = symbols
                else:
                    for symbol in symbols[:P.opens]:
                        i = int(symbol) % P.leaves
                        if len(indices) < P.opens and i not in indices:
                            indices.append(i)
            return values

    original_hash, original_transcript = backend.hash_bytes, proof.Transcript

    def observe_hash(label, *chunks):
        if label == b"mixed R":
            recorded["table"], = chunks
        return original_hash(label, *chunks)

    proof.Transcript, backend.hash_bytes = Observed, observe_hash
    try:
        domain = b"SGM1/complete-FS01/signed-prefix/v1" + bytes.fromhex(pin) + st.encode()
        run(build_payment(st, FLATTEN), domain, wire[3990:], early_degree=early)
    finally:
        proof.Transcript, backend.hash_bytes = original_transcript, original_hash

    table = np.frombuffer(recorded["table"], F).reshape(P.decs_rows, len(P.points))
    width = len(columns[0]) - P.decs_rows
    gamma = recorded["gamma"][:P.decs_rows*width].reshape(P.decs_rows, width)
    changed = table.copy()
    changed[0] ^= 1  # add the constant one to a single polynomial, before looking at any x
    comparisons = [0, 0]
    for idx, col in zip(sorted(indices), columns, strict=True):
        wanted = col[width:] ^ freduce(fmul(gamma, col[:width]), axis=1)
        for j, checked in enumerate((table, changed)):
            comparisons[j] += int(np.array_equal(wanted, feval(checked, P.points, P.evaluation(idx))))
    if comparisons != [P.opens, 0]:
        raise ValueError("honest or constant-offset degree control failed")
    sums = Counter()
    for g in groups.values():
        sums.update(g)
    if sums["message_bytes"] != len(wire) - 3990:
        raise ValueError("incomplete census")
    # DFM rounds alternate prover replies with fresh coins. Consecutive coin calls,
    # deterministic bindings and final retries do not each add a prover message.
    blocks = []
    for kind, _, size in schedule:
        if kind == "coin" and size == 0:
            continue
        if not blocks or blocks[-1] != kind:
            blocks.append(kind)
    result = dict(suite=envelope.tag.decode(), funded_count=count, pin=pin, wire_B=len(wire),
                  proof_B=len(wire)-3990, packet_sha256=hashlib.sha256(wire).hexdigest(),
                  schedule_sha256=hashlib.sha256(json.dumps(schedule,separators=(",",":")).encode()).hexdigest(),
                  totals=dict(sums), interacting_coin_blocks=blocks.count("coin"),
                  degree_basis_B=table.nbytes, columns_B=columns[0].nbytes, authenticated_columns=len(columns),
                  original_matches=comparisons[0], constant_offset_matches=comparisons[1],
                  events_by_label=dict(groups))
    if all_events:
        result["ordered_events"] = schedule
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("pin", help="independently expected SHA-256 of the funding genesis")
    parser.add_argument("--early", action="store_true")
    parser.add_argument("--events", action="store_true")
    args = parser.parse_args()
    print(json.dumps(census(args.directory, args.pin, args.early, args.events), indent=2))
