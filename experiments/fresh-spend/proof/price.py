"""Price the unoptimized FS01 Boolean schedule using both upstream and independent formulas."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "binding"))
from envelope import Body, RECEIPT, SIGNATURE
from relation import DEPTH, W
from side import schedule


def profiles(binary):
    rows = {}
    # (width, grind, maximum opening), FAEST v2 Table 3.2, lambda 256.
    for label, (tau, grind, opening) in {"256s": (22, 6, 218), "256f": (32, 8, 234)}.items():
        gates = schedule()
        # Public parameters parsed as bytes outside the Boolean circuit.
        input_bytes = W + 8 + W + 8 + W + W + 5 + DEPTH * W
        output_bytes = W + 8 + W + 8 + W
        witness_bits = 8 * (2 * input_bytes + 2 * output_bytes + W) + 1
        ell = sum(gates.values()) + witness_bits
        width = 256
        nb = width // 8
        ell_bytes = (ell + 7) // 8
        ellhat_bytes = (ell + 3 * width + 16 + 7) // 8
        sections = {
            "header": 48, "corrections": (tau - 1) * ellhat_bytes, "vole_hash": nb + 2,
            "masked_assignment": ell_bytes, "qs_coefficients": 2 * nb,
            "opening": (2 * tau + opening) * nb, "last_challenge": nb, "iv": 16, "counter": 4,
        }
        proof_bytes = sum(sections.values())
        api_size = int(subprocess.check_output([binary, label, "price", str(ell)], text=True))
        if api_size != proof_bytes:
            raise ValueError("independent count differs from source-built size API")
        k = (width - grind) // tau + 1
        high = (width - grind) % tau
        leaves = (high << k) + ((tau - high) << (k - 1))
        buffers = {
            "one_worker_butterfly": 2 * (1 << k) * ellhat_bytes,
            "retained_vole_matrix": width * ellhat_bytes,
            "transposed_matrix": (ell + 2 * width) * nb,
            "wire_tags_lower_bound": ell * nb,
        }
        fields = dict(backend=1, anchor=bytes(W), fee=3, nfs=(bytes(W),) * 2,
                      cms=(bytes(W),) * 2, receipts=(bytes(RECEIPT),) * 2)
        ordinary = Body(**fields, role=0)
        leg = Body(**fields, role=1, terms=bytes(W), ephemeral=bytes(W), expiry=1)

        def core_size(body):
            return len(body.prefix()) + W + len(body.tails()) + 8 + proof_bytes

        signed_leg = core_size(leg) + SIGNATURE
        frame = core_size(ordinary)
        rows[label] = {
            "and_count": sum(gates.values()), "witness_bits": witness_bits, "ell": ell,
            "ellhat_bytes": ellhat_bytes, "sections": sections, "proof_bytes": proof_bytes,
            "byte_size_from_upstream": api_size, "ordinary": frame, "signed_leg": signed_leg,
            "paired_swap": 4 + 2 * 8 + 2 * signed_leg, "source_buffer_bytes": buffers,
            "concurrent_prover_allocation_lower_bound_bytes": sum(buffers.values()),
            "prover_leaf_prg_payload_bytes": leaves * ellhat_bytes,
            "verifier_leaf_prg_payload_bytes": (leaves - tau) * ellhat_bytes,
            "one_copy_ordinary_bytes_at_100m": 100_000_000 * frame,
        }
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", type=Path)
    print(json.dumps(profiles(parser.parse_args().component.resolve()), indent=2))
