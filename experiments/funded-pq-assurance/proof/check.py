#!/usr/bin/env python3
"""Check committed funded proof calculations."""

import json
import importlib.util
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("funded_pq_calculate", HERE / "calculate.py")
if spec is None or spec.loader is None:
    raise SystemExit("cannot load funded proof calculator")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
expected = json.loads((HERE / "PARAMETERS.json").read_text())
actual = module.calculate()
if actual != expected:
    raise SystemExit("funded proof parameters differ")
print("Funded C registrations, geometry, sizes, and S64 calculation matched.")
