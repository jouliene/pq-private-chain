"""Public-branch fixture and fresh, process-separated proof checks for one input."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess


def shake(tag, *parts):
    return hashlib.shake_256(bytes((0xf1, tag)) + b"".join(parts)).digest(64)


def run(exe, command, table, payload=b"", accept=True, timing=None):
    args = [str(exe), command, str(table)]
    if timing:
        args = ["/usr/bin/time", "-f", "%e %U %S %M", "-o", str(timing), *args]
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (result.returncode == 0) != accept:
        raise RuntimeError(f"{command} unexpected status {result.returncode}: {result.stderr.decode()}")
    return result.stdout


def exercise(exe, public, proof_count=1):
    public.mkdir(mode=0o700)
    chain, anchor = secrets.token_bytes(64), secrets.token_bytes(64)
    count = 53
    selected = secrets.randbelow(count)
    rows = []
    for i in range(count):
        # Synthetic already-funded occurrence. No seed, ASK or note leaves the fixture memory.
        ask = secrets.token_bytes(64)
        owner = shake(3, ask)
        fields = (i+1).to_bytes(8, "little") + bytes(64+8) + secrets.token_bytes(64)
        occ = shake(13, chain, i.to_bytes(64, "little"), bytes(1))
        cm = shake(4, chain, owner, fields)
        rows.append(shake(5, occ, cm))
        if i == selected:
            record = ask + fields + occ + bytes([i])
            nf = shake(8, ask, occ)
    header = b"HLT1" + chain + anchor + bytes([count])
    table = public / "eligible.table"
    table.write_bytes(header + b"".join(rows))
    table_check = run(exe, "check-table", table).decode().strip()
    geometry = json.loads(run(exe, "geometry", table))
    for n in (1, 64):
        other = public / f"table-{n}"
        extra = [secrets.token_bytes(64) for _ in range(max(0,n-count))]
        other.write_bytes(header[:-1]+bytes([n])+b"".join((rows+extra)[:n]))
        run(exe, "check-table", other)
    results = []
    for i in range(proof_count):
        path = public / f"proof-{i}.public"
        packet = run(exe, "prove", table, record+nf, timing=public/f"prove-{i}.time")
        if packet[:64] != nf or len(packet) != 64+geometry["proof_bytes"]:
            raise ValueError("incorrect public framing")
        path.write_bytes(packet)
        run(exe, "verify", table, path.read_bytes(), timing=public/f"verify-{i}.time")
        results.append({"prove": (public/f"prove-{i}.time").read_text().strip(),
                        "verify": (public/f"verify-{i}.time").read_text().strip()})
    # Original public proof against validator-owned alt order + same count, also an unrelated row change.
    changed = public / "other-selected-branch.table"
    changed.write_bytes(header + b"".join(reversed(rows)))
    run(exe, "verify", changed, packet, False)
    different = (selected+1) % count
    mutated = list(rows)
    mutated[different] = bytes([rows[different][0]^1])+rows[different][1:]
    changed.write_bytes(header + b"".join(mutated))
    run(exe, "verify", changed, packet, False)
    changed.write_bytes(header[:68] + bytes([header[68]^1]) + header[69:] + b"".join(rows))
    run(exe, "verify", changed, packet, False)
    run(exe, "verify", table, bytes([packet[0]^1])+packet[1:], False)
    run(exe, "verify", table, packet[:-1]+bytes([packet[-1]^1]), False)
    run(exe, "verify", table, packet[:-1], False)
    # Independent instances/clear satisfiability checked at the prover entry point.
    for offset in (0, 64, 72, 136, 144, 208):
        wrong = bytearray(record)
        wrong[offset] ^= 1
        run(exe, "prove", table, wrong+nf, False)
    run(exe, "prove", table, record[:-1]+bytes([different])+nf, False)
    run(exe, "prove", table, record[:-1]+bytes([count])+nf, False)
    run(exe, "prove", table, record+bytes([nf[0]^1])+nf[1:], False)
    print(json.dumps({"profile":"EM-256f", "funded_rows": count, "capacity":64,
                      "table_bytes":table.stat().st_size, "table_check":table_check,
                      "geometry":geometry,"public_packet_bytes":len(packet),
                      "timing_fields":"wall_s user_s system_s max_rss_KiB",
                      "samples":results, "public_rejections":6,
                      "unsatisfied_opening_rejections":9}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("public", type=Path)
    arguments = parser.parse_args()
    exercise(arguments.binary.resolve(), arguments.public)
