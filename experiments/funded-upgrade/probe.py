"""Time registered verification of complete transfers and both signed swap legs using public bytes."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from statistics import median
import struct
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from profile import profiles

PREVIOUS = "1ce5693671acbccdcd6ecf7d1d17bf9a153dbde590e0c812762e81612ac2db72"
P = 2**64 - 2**32 + 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def ordinary_pair(public, decode_block):
    by_nf = [{}, {}]
    packets = {packet for file in (public / "blocks").glob("*.bin")
               for packet in decode_block(file.read_bytes()).packets}
    for raw in sorted(packets):
        if raw[:6] not in (b"MSP1\1\0", b"MSP2\1\0"):
            continue
        body = raw[6:]
        end = 9 + int.from_bytes(body[5:9], "little")
        require(end + 3584 == len(body), "transfer frame")
        pi = body[end-31*8:end]
        # Slot zero is real for these funded cases. Use the actual same-input race.
        by_nf[raw[3] - ord("1")][pi[40:72]] = body
    common = sorted(by_nf[0].keys() & by_nf[1].keys())
    require(common, "missing same-input A/B funded transfers")
    return tuple(table[common[0]] for table in by_nf)


def signed_packets(raw, version):
    code = str(version).encode()
    require(raw[:5] == b"SWB" + code + b"\1", "wrong swap version")
    offset, frames = 5, []
    for i in range(2):
        size = int.from_bytes(raw[offset:offset+4], "little")
        frame = raw[offset+4:offset+4+size]
        require(len(frame) == size and size <= 262144 and frame[:6] == b"SWF"+code+b"\1"+bytes([i]), "swap frame")
        frames.append(frame)
        offset += 4 + size
    x, y = frames
    require(offset == len(raw) and x[6:75] == y[6:75] and x[6] <= 1, "swap terms mismatch")
    legs = [f[17195:] for f in frames]
    ids = [sha256(leg).digest() for leg in legs]
    require(x[75:107] == ids[1] and y[75:107] == ids[0], "swap companion hashes")
    domain = b"SWP"+code+b"/joint-authorization/v1\0"
    digest = sha256(domain + x[11:75] + x[7:11] + x[6:7] + b"".join(ids)).digest()
    return legs, [f[107:17195] for f in frames], digest, x[6]


def old_bundle(archive):
    require(sha256(archive.read_bytes()).hexdigest() == PREVIOUS, "unapproved historic comparison")
    with tarfile.open(archive, "r:gz") as tar:
        obj = tar.getmember("public/SWAP.bin")
        require(obj.isfile() and obj.size == 320905, "historic swap member")
        return tar.extractfile(obj).read()


def sample(deploy, name, same, other, sigs, digest, payer, registered):
    from wire import Role

    leg = name.startswith("SLG")
    prefix = ("b-" if name.endswith("2") else "") + ("swap-" if leg else "")
    binary = deploy / (prefix + "runtime") / "native"
    keys = deploy / (prefix + "keys")
    vk = keys / ("swap.vk" if leg else "managed.vk")
    require(sha256(vk.read_bytes()).hexdigest() == registered["verifier_sha256"], "unexpected verifier")
    pin = (deploy / "devnet" / ("approved-"+prefix+"native.sha256")).read_text().strip()
    start = time.monotonic()
    role = Role(binary, pin, ["verify", "/keys"], keys)
    elapsed = []
    try:
        for _ in range(4):
            tic = time.monotonic()
            for i, body in enumerate(same):
                require(body[:5] == name.encode()+b"\1" and len(body)-3593 == registered["proof_B"], "priced proof differs")
                reply = role.call(body)
                require(reply[:1] == b"1" and len(reply) == 1+172+3584+(32 if leg else 40), "reference proof failed")
                if leg:
                    require(int.from_bytes(reply[165:173], "little") == (3 if i == payer else 0), "wrong fee payer")
                    require(role.call(b"V"+reply[-32:]+digest+sigs[i]) == b"1", "reference signature failed")
                else:
                    require(reply[-40:] == bytes(40), "transfer disclosed a supply change")
            elapsed.append(time.monotonic()-tic)
            if len(elapsed) == 1:
                cold = time.monotonic()-start
        # Retain the candidate proof and ciphertexts; use the receiving role's expected magic.
        for body in other:
            require(role.call(name.encode()+body[4:]) == b"0", "other query profile accepted")
        # Preserve encoding and length and change the first public root word to a different canonical field element.
        changed = bytearray(same[0])
        pos = 9 + registered["proof_B"] - 8*registered["public_words"]
        value, = struct.unpack_from("<Q", changed, pos)
        struct.pack_into("<Q", changed, pos, (value+1)%P)
        require(role.call(changed) == b"0" and role.call(same[0])[:1] == b"1", "public statement binding")
        meters = role.close()
    finally:
        role.abort()
    count = 4 if leg else 1
    require(meters[0]["operation"] == "verifier_setup", "setup meter missing")
    positive = meters[1:1 + 4*count]
    require(all(x["operation"] == "public_verify" for x in positive), "acceptance meter missing")
    cpu = [sum(m["cpu_s"] for m in positive[i:i+count]) for i in range(0,len(positive),count)]
    return dict(wallet_submission_B=registered["complete_submission_B"], proof_B=registered["proof_B"],
                sample_sha256=[sha256(b).hexdigest() for b in same], warm_complete_calls=3,
                cold_launch_through_first_verdict_wall_s=cold, setup=meters[0],
                warm_crypto_median_wall_s=median(elapsed[1:]), warm_native_median_cpu_s=median(cpu[1:]),
                native_peak_RSS_KiB=max(x["peak_rss_kib"] for x in positive),
                retagged_other_proofs_rejected=len(other), altered_public_root_rejected=True)


def main(deployment, public, historical):
    # Import the released, namespace-isolated role launcher via the deployment's chain module.
    sys.path.insert(0, str(deployment / "devnet"))
    from chain import decode_block

    a, b = ordinary_pair(public, decode_block)
    old = signed_packets(old_bundle(historical), 1)
    new = signed_packets((public / "SWAP.bin").read_bytes(), 2)
    registered = profiles()
    result = {}
    for name, same, other in (("MNG1", a, b), ("MNG2", b, a)):
        result[name] = sample(deployment, name, [same], [other], None, None, None, registered[name])
    for name, same, other in (("SLG1",old,new), ("SLG2",new,old)):
        legs, signatures, digest, payer = same
        result[name] = sample(deployment,name,legs,other[0],signatures,digest,payer,registered[name])
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("deployment","public","historical"):
        parser.add_argument(name, type=lambda s: Path(s).resolve(strict=True))
    print(json.dumps(main(**vars(parser.parse_args())), indent=2, sort_keys=True))
