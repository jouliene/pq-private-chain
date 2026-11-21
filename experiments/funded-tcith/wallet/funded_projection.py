"""The released ciphertext projection and the fixed-parent branch rules."""
import importlib.util
from pathlib import Path
import sys

EX = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(EX / 'lattice-spend/pivot'))
import pivot

_file = EX / 'packed-tcith/encoding/check.py'
_spec = importlib.util.spec_from_file_location('ftl_released_funded_projection', _file)
_public_encoding = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_public_encoding)


def receipt_hash(params, receipts):
    return tuple(_public_encoding.receipt_digest(params, receipts))
