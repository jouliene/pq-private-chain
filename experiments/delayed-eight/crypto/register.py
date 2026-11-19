"""Generate, then independently pin and install, public verifier data before authorizing any proof."""
import argparse
import json
from pathlib import Path
import shutil
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from certrole import INNER,ROOT,sha,wire


def register(build,keys):
    inner=ROOT/"experiments/payment-architecture/direct/registry/direct.vk"
    assert sha(inner)==INNER
    record=json.loads((build/"BUILD.json").read_bytes())
    assert sha(build/"native")==record["binary_sha256"]
    keys.mkdir(parents=True,exist_ok=False)
    shutil.copy2(inner,keys/"direct.vk")
    service=wire.Role(build/"native",record["binary_sha256"],["register","/keys"],keys,keys_writable=True)
    try:
        raw=service.proc.stdout.read()
        meters=service.close(graceful=False)
        dimensions=json.loads(raw)
    except BaseException:
        service.abort()
        raise
    assert dimensions["public_inputs"]==210 and dimensions["inner_degree_bits"]==12 and dimensions["domain"]==0x443843310001
    return dict(format="D8C1",key_sha256={p.name:sha(p) for p in sorted(keys.iterdir())},
                key_B={p.name:p.stat().st_size for p in sorted(keys.iterdir())},parameters=dict(
                width=8,active=[1,8],wires=135,routed=60,extension_degree=2,configured_security_bits=128,
                challenges=2,rate_bits=5,queries=26,cap_height=4,grinding=0,reduction=[2,3],
                direct_row_blinding=True,direct_fri_leaf_hiding=True,outer_row_blinding=False,outer_fri_leaf_hiding=False),
                dimensions=dimensions,registration_meters=meters,binary_sha256=record["binary_sha256"],
                build_receipt_sha256=sha(build/"BUILD.json"),preregistration_sha256=sha(HERE/"PROFILE.md"))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("build",type=Path);p.add_argument("fresh_keys",type=Path)
    a=p.parse_args()
    print(json.dumps(register(a.build.resolve(),a.fresh_keys.resolve()),sort_keys=True,indent=2))
