"""Run deterministic structural controls on public, synthetic descriptions."""
from dataclasses import replace
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from selector import (Atom, InvalidLayout, Leg, ORDINARY, SWAP, TOKEN, ZERO, digest,
                      replace_suffix, schedule, swap_id, ticket, validate_block)


def fixture(kind, label):
    count = 2 if kind == SWAP else 1
    es = [digest(b"example/effect", label, bytes([i])) for i in range(count)]
    session = digest(b"example/terms", label) if kind == SWAP else ZERO
    agreement = swap_id(session, es) if kind == SWAP else ZERO
    legs = []
    for i, e in enumerate(es):
        nfs = tuple(digest(b"example/nf", e, bytes([n])) for n in range(2))
        legs.append(Leg(kind, i, e, nfs, ticket(kind, i, agreement, e, nfs)))
    return Atom(kind, session, tuple(legs))


def run():
    a, b = (fixture(ORDINARY, x) for x in (b"a", b"b"))
    token, swap, other = fixture(TOKEN, b"t"), fixture(SWAP, b"s"), fixture(SWAP, b"o")
    left, right = swap.legs
    split = tuple(replace(swap, legs=(leg,)) for leg in swap.legs)
    queue = (a, token, b, swap)
    chain = schedule(queue)
    assert chain == ((a, token, b), (swap,))  # One free slot cannot split the next swap.
    assert replace_suffix(chain, 1, ((other,),)) == ((a, token, b), (other,))
    assert replace_suffix(chain, 0, ((),(swap,))) == ((),(swap,))
    assert validate_block((token, swap))
    failures = {}

    def reject(label, fn):
        try:
            fn()
        except InvalidLayout as e:
            failures[label] = str(e)
        else:
            raise AssertionError(label)

    reject("left only", lambda: validate_block((split[0],)))
    reject("right only", lambda: validate_block((split[1],)))
    reject("one leg per block", lambda: replace_suffix(chain, 1, ((split[0],),(split[1],))))
    reject("unmatched agreement", lambda: validate_block((replace(swap, legs=(left, other.legs[1])),)))
    reject("repeated role", lambda: validate_block((replace(swap, legs=(left, left)),)))
    reject("wrong role order", lambda: validate_block((replace(swap, legs=(right, left)),)))
    reject("changed terms", lambda: validate_block((replace(swap, session=other.session),)))
    reject("ordinary envelope on token", lambda: validate_block((replace(token, kind=ORDINARY),)))
    recast = replace(token.legs[0], kind=ORDINARY)
    reject("relabel token statement", lambda: validate_block((Atom(ORDINARY, ZERO, (recast,)),)))
    recast = replace(left, kind=ORDINARY)
    reject("relabel one swap leg", lambda: validate_block((Atom(ORDINARY, ZERO, (recast,)),)))
    reject("duplicate whole agreement", lambda: validate_block((swap, swap)))
    reject("pre-spent counterparty", lambda: validate_block((swap,), {right.nullifiers[0]}))
    reject("cross-block double-spend", lambda: replace_suffix(chain, 1, ((b,),)))
    reject("scheduler given orphan", lambda: schedule((a, split[1])))
    reject("oversized candidate", lambda: validate_block((*queue,)))
    assert chain == ((a, token, b), (swap,))
    return dict(scope="synthetic structural layouts only", slots=[3,2],
                successful_replacements=2, rejected=failures,
                original_layout_preserved=True, proof_or_value_authorization=False)


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
