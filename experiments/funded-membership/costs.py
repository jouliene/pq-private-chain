"""Measure fresh public verification and durable acceptance of a genuine selected history."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
from statistics import median
import sys
import tempfile
import time


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def ancestry(chain, blocks, target):
    ident = bytes.fromhex(target)
    result = []
    seen = set()
    while ident != chain.GENESIS:
        need(len(ident) == 32 and ident not in seen, "invalid public ancestry")
        seen.add(ident)
        path = blocks / (ident.hex() + ".bin")
        raw = path.read_bytes()
        need(chain.block_id(raw) == ident, "public block identity")
        block = chain.decode_block(raw)
        result.append((block.height, path))
        ident = block.parent
    result.reverse()
    need([h for h, _ in result] == list(range(1, len(result) + 1)), "public block heights")
    return result


def roles(db, resources):
    active = {"A/managed": resources.v}
    if db._swap_verifier is not None:
        active["A/swap"] = db._swap_verifier
    for suite, registered in (("B", db._b_roles), ("C", db._c_roles)):
        active.update({suite + "/" + kind: role for kind, role in registered.items()})
    return active


def measure(db, resources, fn):
    before = {name: os.fstat(r.errors.fileno()).st_size for name, r in roles(db, resources).items()}
    start, cpu = time.perf_counter_ns(), time.process_time_ns()
    answer = fn()
    elapsed = (time.perf_counter_ns() - start) / 1e9
    cpu = (time.process_time_ns() - cpu) / 1e9
    total, setup, peak, calls = 0.0, 0.0, 0, 0
    for name, r in roles(db, resources).items():
        fd = r.errors.fileno()
        offset = before.get(name, 0)
        # The native service writes its meter before returning each public verdict.
        text = os.pread(fd, os.fstat(fd).st_size - offset, offset).decode("ascii")
        for line in text.splitlines():
            tag, operation, _, seconds, rss = line.split()
            need(tag == "METER" and operation in ("public_verify", "verifier_setup"), "native meter format")
            peak = max(peak, int(rss))
            if operation == "public_verify":
                calls += 1
                total += float(seconds)
            else:
                setup += float(seconds)
    return answer, dict(wall_s=elapsed, controller_cpu_s=cpu, verifier_cpu_s=total, setup_cpu_s=setup,
                        verifier_peak_RSS_KiB=peak, native_verdicts=calls)


def warm_group(db, resources, group, height, repeats, swap_wire):
    def verify():
        if len(group) == 1:
            return db.verify_single(group[0], height)
        return db.verify_swap(group, height)

    rows, first = measure(db, resources, verify)
    op = rows[0].operation
    count = 4 if len(group) == 2 else 2 if op in ("register", "mint") else 1
    need(first["native_verdicts"] == count, "missing proof or authorization call")
    repeated = []
    for _ in range(repeats):
        current, readings = measure(db, resources, verify)
        need(rows == current and readings["native_verdicts"] == count, "changed verified public effects")
        repeated.append(readings)
    submitted = group[0] if len(group) == 1 else swap_wire.bundle(group)
    return dict(height=height, operation=op, envelope=group[0][:4].decode("ascii"),
                id=sha256(submitted).hexdigest(), submission_B=len(submitted), frame_B=list(map(len, group)),
                first_observed=first, warm=repeated,
                warm_wall_median_s=median(s["wall_s"] for s in repeated),
                warm_native_cpu_median_s=median(s["verifier_cpu_s"] for s in repeated))


def wallet_readings(obj, selected_ids):
    allowed = ("tx", "real_inputs", "fee", "packet_B", "proving_wall_s", "prover_cpu_s",
               "prover_role_peak_rss_KiB", "anchor_height", "wallet_command_s", "authorization_s",
               "authorization_file_B", "offer_file_B")
    found = {}

    def visit(row, path, operation_id):
        if isinstance(row, dict):
            if "proving_wall_s" in row:
                need(all(k in row for k in ("prover_cpu_s", "prover_role_peak_rss_KiB")),
                     "incomplete wallet proof measurements")
                found[path] = {k: row[k] for k in allowed if k in row}
                found[path].update(logical_id=operation_id, selected=operation_id in selected_ids)
            for key, value in row.items():
                visit(value, path + "." + key, operation_id)
        elif isinstance(row, list):
            for i, value in enumerate(row):
                visit(value, f"{path}[{i}]", operation_id)

    for label, operation in obj["operations"].items():
        visit(operation, label, operation["tx"])
    need(found, "no live wallet proof timings")
    return found


def run(deployment, public_blocks, tip, wallet_report, repeats):
    sys.path.insert(0, str(deployment / "devnet"))
    import chain
    import runtime
    import swap_wire
    from run import Resources
    ordered = ancestry(chain, public_blocks, tip)
    cpu_name = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                     if line.startswith("model name")), platform.machine())
    result = dict(selected_tip=tip, repetitions=repeats, groups=[], blocks=[],
                  execution=dict(machine=platform.machine(), cpu=cpu_name, python=platform.python_version(),
                                 logical_cpus_available=len(os.sched_getaffinity(0)),
                                 kernel=platform.release()))
    with tempfile.TemporaryDirectory(prefix="funded-membership-cost-") as temp:
        path = Path(temp) / "replay.sqlite"
        resources = Resources(runtime.config(deployment / "runtime"))
        try:
            db = chain.Chain(path, resources.backend)
            try:
                result["sqlite"] = {k: db.db.execute("PRAGMA " + k).fetchone()[0]
                                    for k in ("page_size", "synchronous", "journal_mode")}
                need(db.status()["height"] == 0, "nonempty replay")
                for height, source in ordered:
                    raw = source.read_bytes()
                    block = chain.decode_block(raw)
                    groups = list(swap_wire.groups(block.packets))
                    records = [warm_group(db, resources, g, height, repeats, swap_wire) for g in groups]
                    result["groups"].extend(records)
                    size = path.stat().st_size
                    verdict, elapsed = measure(db, resources, lambda: db.accept(raw))
                    need(verdict["selected"] and verdict["changed"] and verdict["id"] == source.stem,
                         "real durable acceptance required")
                    need(elapsed["native_verdicts"] == sum(r["first_observed"]["native_verdicts"] for r in records),
                         "durable replay did not freshly verify all proofs and approvals")
                    result["blocks"].append(dict(height=height, id=source.stem, block_B=len(raw),
                        groups=[r["id"] for r in records], db_file_growth_B=path.stat().st_size-size, **elapsed))
                status = db.status()
                need(status["tip"] == tip, "wrong replay endpoint")
                result["selected"] = {k: status[k] for k in ("height", "fees", "issued", "spent", "notes", "anchor")}
                result["final_sqlite_B"] = path.stat().st_size
            finally:
                db.close()
        finally:
            resources.close()
    result["controller_peak_RSS_KiB"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if wallet_report:
        publication = json.loads(wallet_report.read_bytes())
        need(publication["tips"]["final"]["tip"] == tip, "wallet report is for another selected history")
        result["wallet_measurements"] = wallet_readings(publication, {row["id"] for row in result["groups"]})
        result["wallet_report_sha256"] = sha256(wallet_report.read_bytes()).hexdigest()
        legacy = publication["controls"]["legacy_B"]
        metrics_file = wallet_report.parent / "controls/legacy-b-costs.json"
        metrics = json.loads(metrics_file.read_bytes()) if metrics_file.is_file() else legacy
        fields = ("packet_B", "proving_wall_s", "prover_cpu_s", "prover_role_peak_rss_KiB")
        if all(key in metrics for key in fields):
            packet = (wallet_report.parent / "controls/legacy-b.bin").read_bytes()
            need(metrics["tx"] == legacy["tx"] == sha256(packet).hexdigest()
                 and len(packet) == metrics["packet_B"], "B measurement does not match its public packet")
            result["legacy_B_wallet"] = {k: metrics[k] for k in ("tx", *fields)}
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("deployment", type=Path)
    p.add_argument("public_blocks", type=Path)
    p.add_argument("tip")
    p.add_argument("--wallet-report", type=Path)
    p.add_argument("--repeats", type=int, default=3)
    a = p.parse_args()
    if not 1 <= a.repeats <= 50:
        p.error("choose between 1 and 50 warm samples")
    print(json.dumps(run(a.deployment.resolve(), a.public_blocks.resolve(), a.tip, a.wallet_report, a.repeats),
                     sort_keys=True, indent=2))
