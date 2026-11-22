"""Compute a root independently, then run private proving and public-only verification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

ROLE = Path(__file__).resolve().parents[1] / "gkr" / "role.py"


def oracle_parent(level, left, right):
    if len(left) != 64 or len(right) != 64 or not 0 <= level < 40:
        raise ValueError("invalid tree inputs")
    return hashlib.shake_256(b"\xf1\x07" + bytes([level]) + left + right).digest(64)


def tree(level, depth):
    layers = [[secrets.token_bytes(64) for _ in range(1 << depth)]]
    for height in range(depth):
        nodes = layers[-1]
        layers.append([oracle_parent(level + height, *nodes[i:i+2])
                       for i in range(0, len(nodes), 2)])
    return layers


def opening(layers, index):
    private = bytearray(layers[0][index])
    for nodes in layers[:-1]:
        private.extend(nodes[index ^ 1])
        private.append(index & 1)
        index //= 2
    return bytes(private)


def statement(level, depth, root):
    return b"SGP1" + (1).to_bytes(2, "little") + bytes((level, depth)) + root


def execute(work, native, depth, flatten):
    level = 5
    layers = tree(level, depth)
    public = work / "public"
    public.mkdir(mode=0o700)
    st = public / "expected.bin"
    # Fix the expected root before choosing which private leaf to open.
    st.write_bytes(statement(level, depth, layers[-1][0]))
    env = dict(PATH=os.environ.get("PATH", "/usr/bin:/bin"), LANG="C",
               PYTHONPATH=str(native), PYTHONDONTWRITEBYTECODE="1",
               OPENBLAS_NUM_THREADS="1", SW_FIELD="gf256")
    times = []

    def role(action, proof, data=None, reject=False):
        with tempfile.TemporaryDirectory(dir=work) as run:
            timing = Path(run) / "time"
            command = ["/usr/bin/time", "-f", "%e %U %S %M", "-o", str(timing),
                       sys.executable, "-B", str(ROLE), action, str(st), str(proof), "--flatten", str(flatten)]
            args = dict(input=data) if data is not None else dict(stdin=subprocess.DEVNULL)
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=env, cwd=public, **args)
            if (completed.returncode != 0) != reject:
                # Role diagnostics may mention a private witness. Never echo a failing prover's input.
                raise RuntimeError(f"{action} expected reject={reject}, exit={completed.returncode}")
            if completed.returncode < 0:
                raise RuntimeError("role terminated by signal")
            if reject and not (b"rejected" in completed.stderr.lower() or b"reject" in completed.stdout.lower()):
                raise RuntimeError(f"{action} failed without explicit proof rejection")
            fields = timing.read_text().splitlines()[-1].split()
            wall, user, system = map(float, fields[:3])
            return dict(wall_s=wall, user_s=user, sys_s=system, peak_KiB=int(fields[3]))

    indices = range(4) if depth == 2 else [secrets.randbelow(1 << depth)]
    for number, index in enumerate(indices):
        proof = public / f"honest-{number}.bin"
        prover = role("prove", proof, opening(layers, index))
        verifier = role("verify", proof)
        times.append(dict(case=number, proof_B=proof.stat().st_size, prover=prover, verifier=verifier,
                          public_proof_sha256=hashlib.sha256(proof.read_bytes()).hexdigest()))

    proof = public / "honest-0.bin"
    original = st.read_bytes()
    changed = bytearray(original)
    changed[-1] ^= 1
    st.write_bytes(changed)
    role("verify", proof, reject=True)
    st.write_bytes(original)
    bad = public / "changed.bin"
    content = bytearray(proof.read_bytes())
    content[len(content)//2] ^= 1
    bad.write_bytes(content)
    role("verify", bad, reject=True)
    bad.write_bytes(content[:-1])
    role("verify", bad, reject=True)

    result = dict(depth=depth, flatten=flatten, start_level=level, public_statement_B=len(original),
                  independent_root_sha256=hashlib.sha256(original).hexdigest(), samples=times,
                  changed_root_rejected=True, changed_proof_rejected=True, truncation_rejected=True)
    if depth == 2:
        # Hash two new leaves honestly. Force the second parent to consume the ORIGINAL
        # inner digest. Both standalone hash computations are correct for their own inputs.
        new_left, new_right = secrets.token_bytes(64), secrets.token_bytes(64)
        old_inner = layers[1][0]
        if oracle_parent(level,new_left,new_right) == old_inner:
            raise RuntimeError("independent digests collided")
        if oracle_parent(level+1,old_inner,layers[1][1]) != layers[-1][0]:
            raise RuntimeError("unrelated expected root")
        private = new_left + new_right + b"\0" + layers[1][1] + b"\0" + old_inner
        broken = public / "disconnected.bin"
        role("detached", broken, private)
        if broken.stat().st_size != proof.stat().st_size:
            raise ValueError("disconnected test requires a fully serialized proof")
        role("verify", broken, reject=True)
        result["disconnected_hashes_rejected"] = True
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("new_work_directory", type=Path)
    ap.add_argument("native_module_directory", type=Path)
    ap.add_argument("depth", type=int, choices=(2, 4, 8))
    ap.add_argument("--flatten", type=int, choices=(1,2,3,4,6,8,12,24), default=4)
    a = ap.parse_args()
    os.umask(0o077)
    work = a.new_work_directory.resolve()
    work.mkdir(mode=0o700)
    result = execute(work, a.native_module_directory.resolve(), a.depth, a.flatten)
    (work / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
