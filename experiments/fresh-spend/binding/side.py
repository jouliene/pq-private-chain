"""An explicit XOR/free-NOT, binary-AND template, without constant folding."""
import json


def schedule():
    # One OR costs one AND; vector equality reduces XOR discrepancies by OR.
    gates = {}
    predicates = 0

    def group(name, gates_before_final_conjunction, predicate_count):
        nonlocal predicates
        gates[name] = gates_before_final_conjunction
        predicates += predicate_count

    # 40 levels * 512 bit differences * two paths. Compute one shared delta
    # per pair, then derive both ordered outputs by XOR. Eighty hash calls use them.
    gates["ordered_paths"] = 2 * 40 * 512
    gates["keccak_chi"] = 99 * 24 * 1600
    # Forty-one steps, borrow'=((~a)&b) XOR ((~(a XOR b))&borrow).
    # Count is a public u41 after canonical parser; index is zero-extended.
    group("occupied_positions", 2 * 41 * 2, 2)
    # Active implies distinct indices. Inactive implies bit-identical private
    # scalar fields (277 bytes incl index); paths are both independently checked.
    group("slot_shape", (40-1) + 1 + (277*8-1) + 1, 2)
    # All hashes are 512 bits. Two roots, two NFs, two output CMs, one auth,
    # followed by a separate requirement that the two public NFs differ.
    group("digest_checks", 8 * (512-1), 8)
    # Four qty-nonzero bits are reused for typed identity and positive inputs.
    gates["quantity_indicators"] = 4 * (64-1)
    group("nonempty_inputs", 2 * ((64-1) + 1), 2)
    # Common ID nonzero iff OR of four qty bits. For each note all 512
    # asset bits equal (qty_nonzero AND common_bit).
    group("asset_types", (512-1) + (4-1) + 4*(512 + 511), 5)
    # Two u64 vectors gated by activation. In a 66-bit full adder, each bit's
    # carry uses (a&b) XOR ((a XOR b)&carry). Keep all 66 carry stages.
    # Native: (in0 + live_in1) == (out0 + out1 + fee); token uses two adds.
    group("integer_balances", 2*64 + 5*66*2 + 2*(66-1), 2)
    gates["final_conjunction"] = predicates - 1
    return gates


if __name__ == "__main__":
    gates = schedule()
    print(json.dumps(dict(and_gates=gates, total=sum(gates.values())), indent=2))
