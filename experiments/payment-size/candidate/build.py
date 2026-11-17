#!/usr/bin/env python3
"""Link the standalone public transport to one approved CP03 installation."""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import common  # noqa: E402

EXTERNS = {
    "compact_all_payments_v3": "compact_all_payments_v3",
    "compact_arity_v3": "compact_bounded_arity_v3",
    "compact_proof_v1": "compact_bounded_support_v3",
    "cp03_history": "cp03_bounded_history_codec",
    "p3_air": "p3_air",
    "p3_challenger": "p3_challenger",
    "p3_commit": "p3_commit",
    "p3_dft": "p3_dft",
    "p3_field": "p3_field",
    "p3_fri": "p3_fri",
    "p3_matrix": "p3_matrix",
    "p3_uni_stark": "p3_uni_stark",
    "rand": "rand",
    "serde_json": "serde_json",
    "tiny_keccak": "tiny_keccak",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--approve-installation", required=True)
    parser.add_argument("--output", type=Path, required=True, help="Path to a new attempt directory")
    args = parser.parse_args()
    installation = common.load_installation(args.installation, args.approve_installation)
    common.need(Path(installation["repository"]) == REPO, "installation belongs to another checkout")
    workspace = Path(installation["workspace"])
    source = Path(installation["source_root"])
    deps = workspace / "target/release/deps"
    operator = common.read_json(installation["operator_path"])
    original_build = operator["ledger_build_receipt"]
    build_path = source / original_build["path"]
    common.need(common.sha(build_path) == original_build["sha256"], "approved original build receipt")
    build = common.read_json(build_path)
    common.need(
        build["format"] == "CP03-FRESH-BUILD01"
        and build["wrapper_exit"] == build["process_exit"] == 0
        and build["no_original_source_or_registry_fallback"] is True,
        "successful isolated CP03 build",
    )

    artifacts = {}
    for entry in build["compiler_artifacts"]:
        name = entry["target"]["name"]
        for filename in map(Path, entry["filenames"]):
            if filename.suffix not in (".rlib", ".rmeta", ".so"):
                continue
            common.need(filename.resolve(strict=True) == filename and filename.parent == deps, "isolated artifact path")
            artifacts.setdefault(name, []).append(filename)
    approved_libraries = {
        str(path): common.sha(path) for paths in artifacts.values() for path in paths
    }

    target = args.output.resolve()
    target.mkdir()
    temporary = target / ".tmp"
    temporary.mkdir()
    binary = target / "cp03-public-fixed-transport"
    tools = installation["toolchain"]["tools"]
    rustc = tools["rustc"]
    common.need(common.sha(rustc["path"]) == rustc["sha256"], "approved rustc")
    command = [
        rustc["path"], "--crate-name", "cp03_public_fixed_transport", "--edition", "2024",
        "-O", "-Dwarnings", "-L", f"dependency={deps}", str(HERE / "src/main.rs"),
        "-o", str(binary),
    ]
    for alias, name in EXTERNS.items():
        candidates = [path for path in artifacts[name] if path.suffix == ".rlib"]
        common.need(len(candidates) == 1, f"unique original compiled dependency {name}")
        command.extend(("--extern", f"{alias}={candidates[0]}"))

    inputs = {str(path): common.sha(path) for path in [Path(__file__), *sorted((HERE / "src").glob("*.rs"))]}
    env = common.controlled_env()
    env["TMPDIR"] = str(temporary)
    actual, _, errors = common.run(command, cwd=REPO, env=env, seconds=60, record=target / "compile")
    common.need(actual["process_exit"] == actual["wrapper_exit"] == 0 and not errors, "standalone compiler result")
    common.hashes(inputs)
    common.hashes(approved_libraries)
    common.load_installation(args.installation, args.approve_installation)
    receipt = {
        "format": "CP03-PUBLIC-FIXED-TRANSPORT-BUILD01",
        "installation_sha256": args.approve_installation,
        "original_build_receipt_sha256": original_build["sha256"],
        "original_compiled_artifact_hashes": approved_libraries,
        "candidate_source_sha256": inputs,
        "rustc": rustc,
        "binary_path": str(binary),
        "binary_sha256": common.sha(binary),
        "actual_compile": actual,
    }
    common.save(target / "build-receipt.json", receipt)
    print(receipt["binary_sha256"])


if __name__ == "__main__":
    main()
