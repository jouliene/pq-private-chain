"""Private prover or public-only SGM1 ordinary proof check from signed funding and the wire."""
import json
from pathlib import Path
import resource
import sys
import time

from payment_codec import EXPERIMENTS, parse_head
sys.path[:0] = [str(EXPERIMENTS/"structured-keccak"/"payment"),str(EXPERIMENTS/"structured-keccak"/"funding")]
from argument import FLATTEN, run, shape
from monetary import build_payment, private_witness
from importlib.util import module_from_spec,spec_from_file_location
spec = spec_from_file_location("previous_funding",EXPERIMENTS/"hidden-membership/paths/role.py")
replay = module_from_spec(spec)
spec.loader.exec_module(replay)


def main():
    if len(sys.argv)!=6:
        raise ValueError("expected action, signed funding directory, genesis pin, packet and public header")
    action,directory,pin,packet,header = sys.argv[1:]
    if action not in ("prove","verify","warm"):
        raise ValueError("unknown role")
    chain,root,count = replay.public_state(directory,pin,False)
    if action=="prove":
        head = Path(header).read_bytes()
        private = private_witness(sys.stdin.buffer.read(6156))
    else:
        private = None
        with Path(packet).open("rb") as f:
            wire = f.read(262145)
        if not 3990 < len(wire) <= 262144 or int.from_bytes(wire[3982:3990],"little")!=len(wire)-3990:
            raise ValueError("invalid complete packet length")
        head = wire[:3982]
    s = parse_head(head,pin,chain,root,count)
    w = build_payment(s,FLATTEN,private)
    domain = b"SGM1/complete-FS01/signed-prefix/v1" + bytes.fromhex(pin) + s.encode()
    if action=="prove":
        proof = run(w,domain)
        Path(packet).write_bytes(head+len(proof).to_bytes(8,"little")+proof)
    else:
        result = []
        for _ in range(3 if action=="warm" else 1):
            wall,cpu = time.perf_counter(),time.process_time()
            run(w,domain,wire[3990:])
            result.append(dict(wall_s=time.perf_counter()-wall,cpu_s=time.process_time()-cpu))
        print(json.dumps(dict(geometry=shape(w),complete_bytes=len(wire),passes=result,
                              peak_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)))


if __name__=="__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(f"payment rejected: {error}")
