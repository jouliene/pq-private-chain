"""Root allocation02: diagnostic hash only, no CP03/native/proof operation."""
from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
AREA = HERE.parent
REPOSITORY = AREA.parents[2]
APPROVAL = '4a3a6498001099fa195e19a81102552d091246a025374ddc33d781b0dbfd8af0'
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(AREA / 'SOURCE02.json') == APPROVAL
manifest = json.loads((AREA / 'SOURCE02.json').read_text())
assert all(sha(AREA / name) == digest for name, digest in manifest['files'].items())
snapshot = HERE / 'structural02.sources'
snapshot.mkdir()
for name in [*manifest['files'], 'SOURCE02.json']:
    shutil.copyfile(AREA / name, snapshot / name)
spec = importlib.util.spec_from_file_location('public_capture', REPOSITORY / 'scripts/common.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
result, output, errors = capture.run(['/usr/bin/prlimit', '--as=268435456', '--cpu=30', '--core=0',
    '--nofile=64', '--', sys.executable, '-I', str(AREA / 'controls.py'), '--output',
    str(HERE / 'structural02.json')], cwd=REPOSITORY, seconds=30, cap=65536,
    record=HERE / 'structural02-process')
stable = sha(AREA / 'SOURCE02.json') == APPROVAL and all(
    sha(AREA / name) == digest for name, digest in manifest['files'].items())
capture.save(HERE / 'structural02-source-readback.json', {'source_approval_sha256': APPROVAL,
    'source_pre_and_post_unchanged': stable, 'source_hashes': manifest['files'],
    'diagnostic_not_cp03': True, 'actual_gate3_acceptance': False})
print(output.decode(), end='')
print(errors.decode(), end='', file=sys.stderr)
raise SystemExit(0 if result['process_exit'] == result['wrapper_exit'] == 0 and stable and not errors else 1)
