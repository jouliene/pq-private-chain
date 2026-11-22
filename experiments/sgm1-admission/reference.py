"""Run the original four-group monetary prover/verifier in a separate process."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
EX = HERE.parent
sys.path[:0] = [str(EX/"structured-keccak"/"payment"), str(EX/"structured-keccak"/"funding")]
from monetary import build_payment, public_statement, private_witness
from argument import FLATTEN, run

def main():
    action, pin = sys.argv[1:]
    stream = sys.stdin.buffer
    st = public_statement(stream.read(526))
    data = stream.read(262145)
    domain = b"SGM1/complete-FS01/signed-prefix/v1" + bytes.fromhex(pin) + st.encode()
    if action == "prove":
        w = build_payment(st, FLATTEN, private_witness(data))
        sys.stdout.buffer.write(run(w, domain))
    elif action == "verify":
        run(build_payment(st, FLATTEN), domain, data)
    else:
        raise ValueError("unknown role")
if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        if sys.argv[1:2] != ["verify"]:
            raise
        print(f"Reference proof rejected: {exc}",file=sys.stderr)
        sys.exit(3)
