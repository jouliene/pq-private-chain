"""Compare public AST1 proof effects from the published and upgraded verifier roles."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import tarfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_issuer import invoke


def packets(archive):
    with tarfile.open(archive, "r:gz") as tar:
        members = sorted((m for m in tar if m.isfile() and Path(m.name).parent.as_posix() == "public/packets"
                          and m.name.endswith(".bin")), key=lambda m: m.name)
        if not members or any(m.size > 262144 for m in members):
            raise ValueError("invalid public capture packet inventory")
        return [tar.extractfile(m).read() for m in members]


def compare(old, new, archive):
    txs = packets(archive)
    if not all(tx.startswith(b"AST1\x01") for tx in txs):
        raise ValueError("historical packet format")
    reference = invoke(old/"native", ["verify", old/"registered"], txs)
    altered = bytearray(txs[0])
    altered[-1] ^= 1
    replies = invoke(new/"native", ["verify", new/"registered"],
                     [*txs, b"MNG1"+txs[0][4:], altered])
    if len(reference) != len(txs) or any(len(x) != 3797 or not x.startswith(b"1") for x in reference):
        raise ValueError("reference public verification")
    if replies != [*reference, b"0", b"0"]:
        raise ValueError("historical effects or rejection differ")
    issue = sum(int.from_bytes(row[-8:], "little") > 0 for row in reference)
    if not (0 < issue < len(reference)):
        raise ValueError("capture must include issuance and transfers")
    return {"source_archive_sha256": sha256(archive.read_bytes()).hexdigest(),
            "full_proofs_verified_by_each_role": len(txs), "issuances": issue,
            "ordinary": len(txs)-issue, "identical_effects_bytes_each": 3797,
            "ordered_public_effects_sha256": sha256(b"".join(reference)).hexdigest(),
            "false_mng1_magic_rejected": True, "changed_receipt_rejected": True}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("original_ast1_build", "upgraded_build", "public_tar_gz"):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    print(json.dumps(compare(a.original_ast1_build.resolve(), a.upgraded_build.resolve(),
                             a.public_tar_gz.resolve()), sort_keys=True))
