"""Freshly verify only public inputs in two independently initialized native role sandboxes."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'experiments/advancing-payments'))
from certificate import layout, read_certificate
from ledger import public_packet, sid
from wire import Role


def check(direct, outer, raw_certificate, packets, roots, direct_sha, outer_sha):
    pins = json.loads((HERE.parent / 'crypto/registry.json').read_bytes())['key_sha256']
    assert (direct / 'keys/direct.vk').read_bytes() == (outer / 'keys/direct.vk').read_bytes()
    for name, digest in pins.items():
        assert sha256((outer / 'keys' / name).read_bytes()).hexdigest() == digest
    declared = read_certificate(raw_certificate, layout((outer / 'keys/eight.vk').read_bytes()), roots)
    assert [public_packet(p)[0] for p in packets] == declared
    first = Role(direct/'runtime/native', direct_sha, ['verify', '/keys'], direct/'keys')
    try:
        for packet, row in zip(packets, declared, strict=True):
            assert first.call(packet) == b'1' + row
        singles = first.close()
    finally:
        first.abort()
    verifier = Role(outer/'native', outer_sha, ['verify', '/keys'], outer/'keys')
    try:
        assert verifier.get() == b'READY'
        assert verifier.call(raw_certificate) == b'1' + b''.join(declared)
        n = len(declared)
        if n > 1:
            start = len(raw_certificate) - n * 3584
            swapped = raw_certificate[:start] + raw_certificate[start+3584:start+7168] + raw_certificate[start:start+3584] + raw_certificate[start+7168:]
            assert verifier.call(swapped) == b'0'
        modified = bytearray(raw_certificate)
        modified[40] ^= 1
        assert verifier.call(bytes(modified)) == b'0'
        cert_meters = verifier.close()
    finally:
        verifier.abort()
    return dict(certificate_sha256=sha256(raw_certificate).hexdigest(), direct_native_sha256=direct_sha,
                certificate_native_sha256=outer_sha, independent_native_and_statement_order_agree=True,
                initialized_public_verifiers=2, approved_slots=len(declared), ids=[sid(x).hex() for x in declared],
                swapped_whole_slot_receipts_rejected=n>1, modified_proof_rejected=True,
                direct_public_verifier=singles, certificate_public_verifier=cert_meters)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('direct_deploy','outer_runtime','certificate','roots'):
        p.add_argument(name,type=Path)
    p.add_argument('--direct-sha',required=True)
    p.add_argument('--outer-sha',required=True)
    p.add_argument('packets',nargs='+',type=Path)
    a = p.parse_args()
    result = check(a.direct_deploy.resolve(),a.outer_runtime.resolve(),a.certificate.read_bytes(),
                   [f.read_bytes() for f in a.packets],a.roots.resolve(),a.direct_sha,a.outer_sha)
    print(json.dumps(result, sort_keys=True, indent=2))
