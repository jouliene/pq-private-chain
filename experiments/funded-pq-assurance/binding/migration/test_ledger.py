import copy
import unittest

from bundle import BridgeBundle, N7_RECEIPT_BYTES
from ledger import BranchContext, CEffect, Ledger, bridge_context


NETWORK = bytes(range(32))
ANCHOR = bytes(range(32, 64))
PARENT = bytes(range(64, 96))


def effect():
    return CEffect(
        ANCHOR,
        25,
        ((1, 2, 3, 4), (5, 6, 7, 8)),
        ((9, 10, 11, 12), (13, 14, 15, 16)),
        3,
        (b"c-receipt-0", b"c-receipt-1"),
        3,
    )


def branch(candidate=26, anchor=ANCHOR, depth=3):
    return BranchContext(NETWORK, PARENT, candidate - 1, candidate, ((anchor, 25, depth),))


RECEIPTS = (b"a" * N7_RECEIPT_BYTES, b"b" * N7_RECEIPT_BYTES)


def statement(view=None, c_packet=b"fresh-MNG3-migration", receipts=RECEIPTS, row=None):
    view, row = view or branch(), row or effect()
    successors = ((101, 102, 103, 104, 105, 106, 107), (201, 202, 203, 204, 205, 206, 207))
    return {
        "bridge_context": list(
            bridge_context(view, c_packet, row, successors, receipts)
        ),
        "c_input_nullifiers": list(map(list, row.nullifiers)),
        "transient_c_outputs": list(map(list, row.outputs)),
        "successor_outputs": list(map(list, successors)),
    }


def bundle(packet=b"fresh-MNG3-migration", proof=b"equality-proof", receipts=RECEIPTS, public=None, view=None):
    public = public or statement(view=view, c_packet=packet, receipts=receipts)
    return BridgeBundle(public, packet, proof, receipts)


def c_verifier(expected=b"fresh-MNG3-migration", row=None):
    def verify(packet):
        if packet != expected:
            raise ValueError("invalid C packet")
        return row or effect()

    return verify


def equality_verifier(expected=b"equality-proof"):
    def verify(_statement, proof):
        if proof != expected:
            raise ValueError("invalid equality proof")

    return verify


def selected_spent(*spent):
    selected = {tuple(nf) for nf in spent}
    return lambda nf: tuple(nf) in selected


EMPTY = {
    "blocks": 0,
    "fees": 0,
    "legacy_spent": 0,
    "successor_outputs": 0,
    "c_packets": 0,
    "equality_proofs": 0,
    "embedded_c_receipts": 0,
    "successor_receipts": 0,
}
BRIDGED = {
    "blocks": 1,
    "fees": 3,
    "legacy_spent": 2,
    "successor_outputs": 2,
    "c_packets": 1,
    "equality_proofs": 1,
    "embedded_c_receipts": 2,
    "successor_receipts": 2,
}


class AtomicLedgerTests(unittest.TestCase):
    def admit(self, ledger, view=None, packet=None, public=None):
        view = view or branch()
        packet = packet or bundle(view=view)
        if public is not None:
            packet = BridgeBundle(public, packet.c_packet, packet.equality_proof, packet.successor_receipts)
        return ledger.admit(
            view,
            packet,
            c_verifier(packet.c_packet),
            equality_verifier(packet.equality_proof),
            selected_spent(),
        )

    def test_admit_retains_artifacts_charges_fee_rolls_back_and_reincludes(self):
        ledger = Ledger()
        self.admit(ledger)
        self.assertEqual(ledger.snapshot(), BRIDGED)
        sizes = ledger.artifact_sizes(26)
        self.assertEqual(sizes["c_packet_including_c_receipts"], len(bundle().c_packet))
        self.assertEqual(sizes["equality_proof"], len(bundle().equality_proof))
        self.assertEqual(sizes["successor_receipts"], 2 * N7_RECEIPT_BYTES)
        self.assertEqual(sizes["derived_c_receipt_index"], 16)
        self.assertEqual(
            sizes["canonical_bundle"],
            sizes["framing"]
            + sizes["statement"]
            + sizes["c_packet_including_c_receipts"]
            + sizes["equality_proof"]
            + sizes["successor_receipts"]
        )
        self.assertFalse(ledger.contains_transient_c_output(effect().outputs[0]))
        ledger.rollback(26)
        self.assertEqual(ledger.snapshot(), EMPTY)
        self.admit(ledger)
        self.assertEqual(ledger.snapshot(), BRIDGED)

    def test_shared_nf_and_version_schedule_reject_both_orderings(self):
        ledger = Ledger(activation_height=26)
        self.admit(ledger)
        with self.assertRaisesRegex(ValueError, "standalone C retired"):
            ledger.ordinary_c_spend(27, effect().nullifiers)
        self.assertEqual(ledger.snapshot(), BRIDGED)

        other = Ledger(activation_height=27)
        other.ordinary_c_spend(26, effect().nullifiers)
        view = branch(candidate=27)
        packet = bundle(public=statement(view=view))
        with self.assertRaisesRegex(ValueError, "already spent on selected branch"):
            other.admit(
                view,
                packet,
                c_verifier(),
                equality_verifier(),
                selected_spent(*effect().nullifiers),
            )
        self.assertEqual(other.snapshot()["legacy_spent"], 2)
        self.assertEqual(other.snapshot()["successor_outputs"], 0)

    def test_verifier_owned_context_branch_receipts_and_proofs(self):
        cases = []
        changed = copy.deepcopy(statement())
        changed["bridge_context"][0] ^= 1
        cases.append((branch(), bundle(), changed, c_verifier(), equality_verifier()))
        cases.append((branch(anchor=b"x" * 32), bundle(), statement(), c_verifier(), equality_verifier()))
        changed_receipt = bundle(receipts=(b"c" * N7_RECEIPT_BYTES, RECEIPTS[1]))
        cases.append((branch(), changed_receipt, statement(), c_verifier(), equality_verifier()))
        bad_packet = bundle(packet=b"corrupt")
        cases.append((branch(), bad_packet, statement(), c_verifier(), equality_verifier()))
        bad_proof = bundle(proof=b"corrupt")
        cases.append((branch(), bad_proof, statement(), c_verifier(), equality_verifier()))
        for view, packet, public, verify_c, verify_equality in cases:
            ledger = Ledger()
            with self.assertRaises(Exception):
                bad = BridgeBundle(public, packet.c_packet, packet.equality_proof, packet.successor_receipts)
                ledger.admit(view, bad, verify_c, verify_equality, selected_spent())
            self.assertEqual(ledger.snapshot(), EMPTY)

    def test_statement_effect_and_fee_mismatches_are_atomic(self):
        for field in ("c_input_nullifiers", "transient_c_outputs", "successor_outputs"):
            ledger = Ledger()
            changed = copy.deepcopy(statement())
            changed[field][0][0] += 1
            with self.assertRaises(ValueError):
                changed_bundle = bundle(public=changed)
                ledger.admit(
                    branch(), changed_bundle, c_verifier(), equality_verifier(), selected_spent()
                )
            self.assertEqual(ledger.snapshot(), EMPTY)
        wrong_fee = copy.copy(effect())
        object.__setattr__(wrong_fee, "fee", 4)
        ledger = Ledger()
        with self.assertRaisesRegex(ValueError, "exact C fee"):
            ledger.admit(
                branch(),
                bundle(),
                c_verifier(row=wrong_fee),
                equality_verifier(),
                selected_spent(),
            )
        self.assertEqual(ledger.snapshot(), EMPTY)

    def test_authenticated_selected_spentness_is_not_replaced_by_bridge_table(self):
        ledger = Ledger()
        packet = bundle()
        with self.assertRaisesRegex(ValueError, "already spent on selected branch"):
            ledger.admit(
                branch(),
                packet,
                c_verifier(),
                equality_verifier(),
                selected_spent(effect().nullifiers[1]),
            )
        self.assertEqual(ledger.snapshot(), EMPTY)


if __name__ == "__main__":
    unittest.main()
