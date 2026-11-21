"""Isolated research roles for the pinned LaZer membership example."""
import ast
import ctypes
import json
import lzma
import os
from pathlib import Path
import random
import resource
import sys
import time

if not __debug__:
    raise RuntimeError("membership roles require assertions enabled")
sys.dont_write_bytecode = True
from frame import HEADER, ROOT_BYTES, decode, descriptor, encode

# LD_LIBRARY_PATH and PYTHONPATH select the caller's pinned disposable build.
from membership_proof import (
    DEGREE_HASH, BITS_MODULUS_HASH, NORM_BINARY, RING_FALCON, RING_PROOF,
    SIZE_MODULUS_PROOF, ZERO_IN_RING_PROOF, compute_leaf, compute_parent_node,
    compute_path_trace, compute_root_from_path, compute_number_witnesses_tree,
    compute_number_witnesses_compress, description_knowledge_path, ffi,
    knowledge_path_only, pack_verify, poly_t, proof_statement,
    proof_statement_description,
)

MAX = 1 << 20
DIM = (RING_FALCON.mod - 1).bit_length()


def upstream_api():
    # Import the authors' path generator without running their full 80-proof sweep.
    source = Path("benchmark_membership_proof.py").read_text()
    tree = ast.parse(source)
    tree.body = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
    space = {"dim_binary_pk": DIM}
    exec(compile(tree, "benchmark_membership_proof.py", "exec"), space)
    return space


def fixtures(profile):
    generate = upstream_api()["generate_path"]
    if profile == "stock64":
        return [generate(64)]
    subtrees = [generate(39), generate(39)]
    nodes = []
    for leaf, _, siblings, directions in subtrees:
        node = compute_leaf(leaf)
        for bit, peer in reversed(list(zip(directions, siblings, strict=True))):
            node = compute_parent_node(peer, node) if bit else compute_parent_node(node, peer)
        nodes.append(node)
    paths = []
    for side, (leaf, _, siblings, directions) in enumerate(subtrees):
        full_siblings = [nodes[1-side], *siblings]
        full_directions = [side, *directions]
        root = compute_root_from_path(40, leaf, full_siblings, full_directions)
        paths.append((leaf, root, full_siblings, full_directions))
    assert paths[0][1].to_list() == paths[1][1].to_list()
    return paths


def setup(height, npaths, roots, private=None):
    desc = proof_statement_description()
    for _ in range(npaths):
        desc.list_degrees += [DEGREE_HASH] * DIM
        desc.list_number_polynomials += [1] * DIM
        desc.list_norm_constraints += [NORM_BINARY] * DIM
        desc = description_knowledge_path(DIM, height, desc)
    st = proof_statement(desc.list_degrees, desc.list_number_polynomials,
                         desc.list_norm_constraints, desc.number_constraints, SIZE_MODULUS_PROOF,
                         num_deg0_constraints=desc.num_deg0_constraints, zk=True,
                         approx_norm_list=desc.approx_norm_list)
    if private is None:
        # The author frontend interleaves constraint assembly with witness inserts.
        # Only the inserts are skipped; every public equation is still constructed.
        st.append_witness_pointer = lambda *_: None
    offset = 0
    for i, root in enumerate(roots):
        if private is None:
            trace = ([None] * compute_number_witnesses_compress(DIM, True),
                     [None] * compute_number_witnesses_tree(height))
        else:
            leaf, _, siblings, dirs = private[i]
            trace = compute_path_trace(leaf, siblings, dirs, height)
            for poly in leaf:
                st.append_witness_pointer(ffi.cast("int64_t*", poly), DEGREE_HASH)
        pk_indices = list(range(offset, offset + DIM))
        st, offset = knowledge_path_only(st, offset + DIM, pk_indices, trace, root, height)
    assert offset == st.num_witness_vectors
    assert st.cur_constraint_num == st.num_constraints
    assert st.cur_deg0_constraint_num == st.num_deg0_constraints
    return st


def codec(st, encoded=None):
    z = ctypes.CDLL(os.environ["FIXTURE_ARRAYS"]).fixture_arrays
    z.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    z.restype = ctypes.c_int
    read = encoded is not None
    if read:
        if len(encoded) > MAX or not encoded.startswith(b"LZM1"):
            raise ValueError("wire header")
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 << 20)
        raw = dec.decompress(encoded[4:], max_length=MAX+1)
        if not dec.eof or dec.unused_data or len(raw) > MAX:
            raise ValueError("wire length")
        size = len(raw)
        data = ctypes.create_string_buffer(raw, size)
    else:
        data = ctypes.create_string_buffer(MAX)
        size = MAX
    received = z(int(ffi.cast("uintptr_t", st.params)), int(ffi.cast("uintptr_t", st.proof)),
                 data, size, int(read))
    if received < 0:
        raise ValueError("wire shape")
    if read:
        return received
    return b"LZM1" + lzma.compress(data.raw[:received], format=lzma.FORMAT_XZ, preset=6), received



def bounded_file(path, limit):
    with path.open("rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversized fixture")
    return data

def clock():
    return time.perf_counter(), time.process_time()


def delta(start):
    return dict(zip(("wall_s", "cpu_s"), [round(b-a, 5) for a,b in zip(start, clock())]))


def run(mode, profile, folder):
    if profile not in ("stock64", "shared40") or mode not in ("prove", "verify", "wrong-root", "changed-proof"):
        raise ValueError("unknown role or profile")
    height, count = (64, 1) if profile == "stock64" else (40, 2)
    proof_file = folder / "proof.lzm"
    public_file = folder / "root.bin"
    info = {"profile": profile, "role": mode, "zk": True, "paths": count, "binary_depth": height}
    frame_file = folder / "membership.bin"
    if mode == "prove":
        if proof_file.exists() or public_file.exists():
            raise FileExistsError("new output directory required")
        random.seed(0)  # Only authors' disposable synthetic tree fixture, not prover randomness.
        paths = fixtures(profile)
        roots = [path[1] for path in paths]
        public = bytes(roots[0].to_list())
        assert len(public) == 512 and all(bytes(r.to_list()) == public for r in roots)
        st = setup(height, count, roots, paths)
        t = clock()
        error, _, _ = st.pack_prove()
        assert not error
        info["params_and_prove"] = delta(t)
        t = clock()
        encoded, size = codec(st)
        info["encode"] = delta(t)
        proof_file.write_bytes(encoded)
        public_file.write_bytes(public)
        frame_file.write_bytes(encode(profile, public, encoded))
        info.update(uncompressed_arrays_B=size, custom_wire_B=len(encoded))
    else:
        packet_limit = HEADER.size + ROOT_BYTES + MAX
        public, packet = decode(profile, bounded_file(frame_file, packet_limit))
        assert len(public) == DEGREE_HASH
        if mode == "wrong-root":
            public = bytes([public[0] ^ 1]) + public[1:]
        root = poly_t(RING_PROOF, list(public))
        st = setup(height, count, [root]*count)
        t = clock()
        assert st.gen_params(st.params, st.output_statement(), 1, 0) == 0
        info["public_parameter_generation"] = delta(t)
        if mode == "changed-proof":
            # An alteration of a valid signed 16-bit terminal coefficient with
            # correct format and checksum reaches the actual constraint verifier.
            raw = bytearray(lzma.decompress(packet[4:]))
            raw[-2] ^= 1
            packet = b"LZM1" + lzma.compress(raw)
        t = clock()
        raw_size = codec(st, packet)
        info["decode"] = delta(t)
        info.update(uncompressed_arrays_B=raw_size, custom_wire_B=len(packet))
        t = clock()
        accepted = pack_verify((st.params, st.proof), st.output_statement(), SIZE_MODULUS_PROOF)
        info["verify"] = delta(t)
        info["accepted"] = bool(accepted)
        if bool(accepted) != (mode == "verify"):
            raise RuntimeError("unexpected cryptographic verdict")
    info.update(framed_B=frame_file.stat().st_size, descriptor_sha256=descriptor(profile).hex())
    info.update(public_root_B=512, witness_vectors=st.num_witness_vectors,
                ring_constraints=st.num_constraints, degree0_constraints=st.num_deg0_constraints,
                witness_degree=DEGREE_HASH,
                process_peak_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    print("METRICS " + json.dumps(info,sort_keys=True), flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "upstream":
        # Exact original benchmark function, including in-process verifier.
        random.seed(0)
        trace, prove, verify = upstream_api()["benchmark_membership_proof"](64, 1, True)
        print("UPSTREAM " + json.dumps({"accepted": True, "height": 64, "zk": True,
                                        "trace_s": trace, "prove_s": prove, "verify_s": verify}), flush=True)
    else:
        run(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
