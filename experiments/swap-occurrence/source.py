"""Regenerate the registered SLG3 source and compare the shipped verifier and admission code."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
EXPS = HERE.parent
sys.path.insert(0, str(EXPS / "funded-conservation"))
from source_check import load, must

MEMBER = EXPS / "funded-membership"
PINS = json.loads((MEMBER / "registry/BUILD.json").read_bytes())["swap"]
RELEASE_NATIVE = "a144a65b295f7469d59ee52a5c559d1a9ee7cf75bf144e32054f76755f6a7726"


def check(upstream, deployment):
    build = load(EXPS / "atomic-swap/native/build.py", "swap_builder")
    harden = load(MEMBER / "build_c.py", "c_generator")
    must(sha256((MEMBER / "hardening.patch").read_bytes()).hexdigest() == PINS["hardening_patch_sha256"],
         "membership patch")
    class SourceCaptured(Exception):
        pass

    def capture(dest):
        harden.configure(dest, "swap")
        tree = dest.parents[3]
        for name, expected in PINS["generated_sources"].items():
            must(sha256((tree / name).read_bytes()).hexdigest() == expected, "generated source: " + name)
        raise SourceCaptured

    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    with TemporaryDirectory() as temp:
        try:
            build.prepare(Path(temp), upstream.resolve(), None, capture)
        except SourceCaptured:
            pass
        else:
            raise ValueError("generator failed to reach pinned sources")
    dev = deployment / "devnet"
    actual = deployment / "c-swap-runtime/native"
    key = (MEMBER / "registry/swap.vk").read_bytes()
    must(sha256(actual.read_bytes()).hexdigest() == (dev / "approved-c-swap-native.sha256").read_text().strip()
         == RELEASE_NATIVE, "released verifier")
    must(key == (deployment / "c-swap-keys/swap.vk").read_bytes() == (dev / "c-swap.vk").read_bytes()
         and sha256(key).hexdigest() == PINS["registration_sha256"], "registered key")
    with TemporaryDirectory() as temp:
        dest = Path(temp) / "registration"
        out = subprocess.run([actual, "register", dest], check=True, capture_output=True)
        must(json.loads(out.stdout) == PINS["registration"] and (dest / "swap.vk").read_bytes() == key,
             "reproduced registration from released executable")
    # Fresh depth-one controls against the same registered role. The private
    # synthetic witnesses stay in this process; only the fixed verdict names leave.
    controls = {"fee_zero": True, "fee_three": True, "wrong_ephemeral_key": False,
                "fee_one": False, "token_inflation": False, "different_token": False}
    probe = subprocess.run([actual, "check-relation", deployment / "c-swap-keys"], capture_output=True)
    must(probe.returncode == 0 and json.loads(probe.stdout) == controls, "registered SLG3 relation controls")
    # Earlier staging switches public dispatch to route versions A/B/C. These files
    # are inside the SHA256-pinned deployment. Compare the C wire code to its generator.
    base = (EXPS / "atomic-swap/swap_wire.py").read_text()
    expected = base.replace("SWB1","SWB3").replace("SWF1","SWF3").replace("SLG1","SLG3").replace("SWP1","SWP3")
    must((dev / "swap_wire_c.py").read_text() == expected, "C wire version")
    must((dev / "consensus.py").read_bytes() == (MEMBER / "consensus.py").read_bytes(), "C dispatch")
    return dict(relation_controls=controls, generated_sources=len(PINS["generated_sources"]), shipped_native_sha256=RELEASE_NATIVE,
                registered_key_sha256=PINS["registration_sha256"], registration=PINS["registration"],
                selected_files={p:sha256((dev / p).read_bytes()).hexdigest() for p in
                                ("swap_wire_c.py","consensus.py","swap_ledger.py","chain.py")})


if __name__ == "__main__":
    # The generator's patch subprocess writes to fd 1. Keep only JSON on stdout.
    sys.stdout.flush()
    saved = os.dup(1)
    try:
        os.dup2(2, 1)
        result = check(Path(sys.argv[1]), Path(sys.argv[2]))
    finally:
        os.dup2(saved, 1)
        os.close(saved)
    print(json.dumps(result, sort_keys=True))
