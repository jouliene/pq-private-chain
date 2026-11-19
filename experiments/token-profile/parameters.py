"""Decode the two registered reference keys and the statements in the public D8 archive."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
ARCHIVE = EXPERIMENTS / "delayed-eight"
sys.path.insert(0, str(ARCHIVE / "review"))
from retained import sections
from certificate import read_certificate, layout
from direct_wire import Wire, P, dimensions, parse_packet

# DefaultGateSerializer numeric tags, in qp-plonky2 1.5.5 source order.
GATES = (
    ("Arithmetic", 1), ("ArithmeticExtension", 1), ("BaseSum2", 1), ("Constant", 1),
    ("CosetInterpolation", 2), ("Exponentiation", 1), ("Lookup", None),
    ("LookupTable", None), ("MulExtension", 1), ("Noop", 0), ("PoseidonMds", 0),
    ("Poseidon", 0), ("Poseidon2Mds", 0), ("Poseidon2IntMix", 0), ("Poseidon2", 0),
    ("PublicInput", 0), ("RandomAccess", 3), ("ReducingExtension", 1), ("Reducing", 1),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fri(rd):
    config = {k: rd.integer() for k in ("rate_bits", "cap_height", "queries")}
    config["grinding"] = rd.integer(4)
    assert rd.integer(1) == 1  # ConstantArityBits
    config["constant_arity_bits"] = [rd.integer(), rd.integer()]
    return config


def read_key(raw):
    rd = Wire(raw)
    cap_height = rd.integer()
    assert cap_height == 4
    rd.words(4 * (1 << cap_height))
    circuit_digest = list(rd.words(4))
    cfg = {k: rd.integer() for k in ("wires", "routed", "config_constants", "configured_bits",
                                     "plonk_repetitions", "max_quotient_factor")}
    assert rd.integer(1) == 1  # use_base_arithmetic_gate
    cfg["row_blinding"] = rd.integer(1)
    cfg["fri"] = read_fri(rd)
    trace_bits = rd.integer()
    assert read_fri(rd) == cfg["fri"]
    count = rd.integer()
    assert 0 < count <= 16
    folds = [rd.integer() for _ in range(count)]
    degree_bits = rd.integer()
    leaf_hiding = rd.integer(1)
    assert rd.integer() == trace_bits == degree_bits
    selector_indices = [rd.integer() for _ in range(rd.integer())]
    groups = [[rd.integer(), rd.integer()] for _ in range(rd.integer())]
    data = {k: rd.integer() for k in ("quotient_factor", "gate_constraints", "constant_polys", "pi")}
    assert rd.integer() == cfg["routed"]
    rd.words(cfg["routed"])
    data["partial_products"] = rd.integer()
    assert [rd.integer() for _ in range(3)] == [0, 0, 0]
    gates = []
    for _ in range(rd.integer()):
        tag = rd.integer(4)
        name, width = GATES[tag]
        assert width is not None
        descriptor = dict(name=name, arguments=[rd.integer() for _ in range(width)])
        if name == "CosetInterpolation":
            descriptor["barycentric_weights"] = list(rd.words(rd.integer()))
        gates.append(descriptor)
    assert len(gates) == len(selector_indices) and not rd.read()
    assert cfg["fri"]["cap_height"] == cap_height
    fri, degree = cfg["fri"], 1 << degree_bits
    n = degree << fri["rate_bits"]
    q = fri["queries"]
    # The library hashes to F then reduces mod N on a 64-bit host. Given
    # uniform independent field draws, bound ALL draws landing in a fixed
    # t-element accepted set, placing it on the heaviest residues first.
    fixed_set_examples = {}
    for label, t in (("rate", degree), ("one_quarter", n // 4), ("one_half", n // 2)):
        numerator = (P // n) * t + min(P % n, t)
        fixed_set_examples[label] = round(q * math.log2(P / numerator), 7)
    return dict(sha256=sha(raw), bytes=len(raw), circuit_digest=circuit_digest, config=cfg,
                common=data, gates=gates, selector_groups=groups, selector_indices=selector_indices,
                trace_rows=degree, lde_points=n, folds_bits=folds, final_extension_coefficients=degree >> sum(folds),
                leaf_hiding=leaf_hiding, query_input_remainder=P % n,
                hypothetical_fixed_agreement_query_bits=fixed_set_examples,
                builder_query_screen=q * fri["rate_bits"] + fri["grinding"],
                builder_capped_screen=min((P**2).bit_length(), q * fri["rate_bits"] + fri["grinding"]))


def explain(row):
    return dict(anchor=row[:4], height=row[4], nullifiers=[row[5:9], row[9:13]],
                commitments=[row[13:17], row[17:21]], native_fee=row[21], receipt_digest=row[22:26])


def check():
    pins = json.loads((ARCHIVE / "crypto/registry.json").read_bytes())["key_sha256"]
    keys = {k: (ARCHIVE / "crypto/keys" / k).read_bytes() for k in pins}
    assert sha(keys["direct.vk"]) == sha((EXPERIMENTS / "payment-architecture/direct/registry/direct.vk").read_bytes())
    assert all(sha(v) == pins[k] for k, v in keys.items())
    profiles = {k: read_key(raw) for k, raw in keys.items()}
    token_key = (HERE / "candidate/registry/token.vk").read_bytes()
    registered = json.loads((HERE / "candidate/evidence/REGISTER.json").read_bytes())
    token = read_key(token_key)
    assert registered["suite"] == "TKN1" and token["sha256"] != pins["direct.vk"]
    assert token["trace_rows"] == 1 << registered["degree_bits"]
    assert token["folds_bits"] == registered["folds"] and token["common"]["pi"] == registered["public_inputs"]
    profiles["token.vk"] = token
    # Walk complete proof encodings with the independent bounded layout readers;
    # native cryptographic verification is a separate check.
    _, items = sections((ARCHIVE / "evidence/retained.d8").read_bytes())
    cert, = [item for item in items if item.startswith(b"D8C1")]
    direct, = [item for item in items if item.startswith(b"DLF1")]
    rows = read_certificate(cert, layout(keys["eight.vk"]))
    direct_log = parse_packet(direct, dimensions(keys["direct.vk"]))
    k = cert[4]
    size = int.from_bytes(cert[5:9], "little")
    outer_pi = struct.unpack_from("<210Q", cert, 9 + size - 210 * 8)
    assert outer_pi[:2] == (0x443843310001, k) and len(rows) == k
    slots = [outer_pi[2 + 26*i:2 + 26*(i+1)] for i in range(8)]
    dsize = direct_log["proof_B"]
    drow = struct.unpack_from("<26Q", direct, 9 + dsize - 26 * 8)
    return dict(field_prime=P, extension_size=P**2, profiles=profiles,
                inner=dict(packet_B=len(direct), sha256=sha(direct), statement=explain(drow)),
                archive=dict(packet_B=len(cert), sha256=sha(cert), proof_B=size, domain=outer_pi[0],
                             active=k, slots=[explain(row) for row in slots]))


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Use without -O: the independent layout readers use assertions.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare with the committed observation")
    args = parser.parse_args()
    result = json.dumps(check(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if (HERE / "PARAMETERS.json").read_text() != result:
            sys.exit("Parameter/statement evidence differs")
        print("All three registered keys and the nine reference statements matched.")
    else:
        sys.stdout.write(result)
