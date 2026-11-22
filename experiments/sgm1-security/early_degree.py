"""Isolated EAR1 proof registration. Run the funded wallet and verifier in separate processes."""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "structured-keccak" / "harness"))
from payment_codec import Ordinary


class EarlyDegreeEnvelope(Ordinary):
    tag = b"EAR1"


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "cycle":
        from payment_run import main
        main(Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve(),
             envelope=EarlyDegreeEnvelope, role_path=Path(__file__).resolve())
    else:
        from payment_role import main
        try:
            main(envelope=EarlyDegreeEnvelope, early_degree=True)
        except ValueError as error:
            sys.exit(f"EAR1 payment rejected: {error}")
