"""Use the pinned binary field, transcript and mixed-field modules from the previous milestone."""
import os
import sys
from pathlib import Path

os.environ["SW_FIELD"] = "gf256"
EXPERIMENTS = Path(__file__).resolve().parents[2]
SMALLWOOD = EXPERIMENTS/"hidden-membership"/"smallwood"
sys.path[:0] = [str(SMALLWOOD/"mixed"),str(SMALLWOOD)]
from field import U, basis, eq_table, fold, inv, mul, product, random_fields, xor
from subfield import EMBED
from transcript import Transcript
