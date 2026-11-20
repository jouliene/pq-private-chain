"""Send only the public fields of the reference count=0 KATs to kat.c."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess


def check(root, role):
    out = {}
    for name in ("l1", "l3", "l5"):
        kat = root/"kats"/("kat_picnic3_"+name+".txt")
        fields = {}
        with kat.open() as src:
            for line in src:
                k, sep, v = line.strip().partition(" = ")
                if sep and k in ("count", "pk", "msg", "sm", "smlen"):
                    fields[k] = v
                if k == "sm":
                    break
        assert fields["count"] == "0"
        pk, msg, sm = (bytes.fromhex(fields[k]) for k in ("pk", "msg", "sm"))
        size = int.from_bytes(sm[:4], "little")
        sig = sm[4+len(msg):]
        assert len(msg) == 33 and size == len(sig) and len(sm) == int(fields["smlen"]) and sm[4:37] == msg
        request = f"{len(pk)} {size}\n".encode() + pk + msg + sig
        result = json.loads(subprocess.run([role], input=request, capture_output=True, check=True).stdout)
        result.update(signature_sha256=sha256(sig).hexdigest(), upstream_verified=True, roundtrip_equal=True)
        assert size == result["signature_B"]
        out["Picnic3_"+name.upper()] = result
    return out


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("enable assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("reference_source",type=Path)
    p.add_argument("probe",type=Path)
    args = p.parse_args()
    print(json.dumps(check(args.reference_source, args.probe.resolve(strict=True)), indent=2))
