"""Public candidate-layout model. It has no proof-verification or ledger-write API."""

from dataclasses import dataclass
from hashlib import sha3_256

ORDINARY = b"APV2"
TOKEN = b"APT1"
SWAP = b"APS1"
ZERO = bytes(32)


class InvalidLayout(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise InvalidLayout(why)


def digest(domain, *fields):
    h = sha3_256()
    for field in (domain, *fields):
        h.update(len(field).to_bytes(4, "little"))
        h.update(field)
    return h.digest()


@dataclass(frozen=True)
class Leg:
    kind: bytes
    role: int
    effect: bytes       # Commitment to the canonical anchor, effects and receipts.
    nullifiers: tuple
    ticket: bytes      # Proposed proof statement digest, structurally checked only.


@dataclass(frozen=True)
class Atom:
    kind: bytes
    session: bytes    # Zero for a transfer, blinded agreement commitment for a swap.
    legs: tuple


def swap_id(session, effects):
    return digest(b"candidate/swap/ordered-offers/v1", session, *effects)


def ticket(kind, role, agreement, effect, nullifiers):
    return digest(b"candidate/statement/v1", kind, bytes([role]), agreement,
                  effect, *nullifiers)


def validate_atom(atom):
    need(atom.kind in (ORDINARY, TOKEN, SWAP), "unknown version")
    is_swap = atom.kind == SWAP
    need(len(atom.legs) == (2 if is_swap else 1), "incomplete atom")
    need(len(atom.session) == 32 and ((atom.session != ZERO) == is_swap),
         "agreement commitment")
    agreement = (swap_id(atom.session, [leg.effect for leg in atom.legs])
                 if is_swap else ZERO)
    for role, leg in enumerate(atom.legs):
        need(leg.kind == atom.kind, "cross-version role")
        need(leg.role == role, "duplicate or reordered role")
        need(len(leg.effect) == 32 and leg.effect != ZERO, "effect digest")
        need(len(leg.nullifiers) == 2 and all(len(n) == 32 and n != ZERO for n in leg.nullifiers),
             "nullifier encoding")
        need(leg.ticket == ticket(atom.kind, role, agreement, leg.effect, leg.nullifiers),
             "role/statement mismatch")
    return agreement


def validate_block(atoms, spent=frozenset(), agreements=frozenset()):
    """Return proposed indexes only; a caller must separately verify proof and branch."""
    need(isinstance(atoms, tuple), "block boundaries")
    count = sum(len(atom.legs) for atom in atoms)
    need(count <= 4, "batch capacity")
    nfs = set(spent)
    swaps = set(agreements)
    for atom in atoms:
        agreement = validate_atom(atom)
        if atom.kind == SWAP:
            need(agreement not in swaps, "duplicate agreement")
            swaps.add(agreement)
        for leg in atom.legs:
            for nf in leg.nullifiers:
                need(nf not in nfs, "nullifier conflict")
                nfs.add(nf)
    return frozenset(nfs), frozenset(swaps)


def schedule(queue):
    """Model FIFO block construction with complete atoms and at most four effect slots."""
    blocks = []
    current = ()
    previous = (frozenset(), frozenset())
    for atom in queue:
        validate_atom(atom)
        if sum(len(a.legs) for a in (*current, atom)) > 4:
            previous = validate_block(current, *previous)
            blocks.append(current)
            current = ()
        current += (atom,)
    if current:
        validate_block(current, *previous)
        blocks.append(current)
    return tuple(blocks)


def replace_suffix(chain, keep, replacement):
    """Validate a candidate fork as whole blocks without mutating the old chain."""
    need(0 <= keep <= len(chain), "fork point")
    candidate = chain[:keep] + tuple(replacement)
    indexes = (frozenset(), frozenset())
    for block in candidate:
        indexes = validate_block(block, *indexes)
    return candidate
