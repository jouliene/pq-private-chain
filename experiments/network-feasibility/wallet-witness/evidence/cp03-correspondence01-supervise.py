"""Root-allocated actual-CP03 public correspondence, not Gate3 acceptance."""
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
APPROVAL = '986b65d246fc51300a886c05d30b926748791c26ab4001599ea2e0a18c88af20'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


assert sha(AREA / 'SOURCE01.json') == APPROVAL
source = json.loads((AREA / 'SOURCE01.json').read_text())
assert all(sha(AREA / name) == digest for name, digest in source['files'].items())
snapshot = HERE / 'cp03-correspondence01.sources'
snapshot.mkdir()
for name in [*source['files'], 'SOURCE01.json']:
    shutil.copyfile(AREA / name, snapshot / name)
spec = importlib.util.spec_from_file_location('public_capture', REPOSITORY / 'scripts/common.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
result, output, errors = capture.run(['/usr/bin/prlimit', '--as=536870912', '--cpu=60', '--core=0',
    '--nofile=64', '--', sys.executable, '-I', str(AREA / 'cp03_fixture.py'), '--output',
    str(HERE / 'cp03-fixture01.json')], cwd=REPOSITORY, seconds=60, cap=65536,
    record=HERE / 'cp03-correspondence01')
stable = sha(AREA / 'SOURCE01.json') == APPROVAL and all(
    sha(AREA / name) == digest for name, digest in source['files'].items())
capture.save(HERE / 'cp03-correspondence01-source-readback.json', {
    'format': 'WALLET-WITNESS-CP03-SOURCE-READBACK01', 'source_approval_sha256': APPROVAL,
    'source_hashes': source['files'], 'source_pre_and_post_unchanged': stable,
    'actual_exit': result.get('process_exit'), 'actual_wrapper_exit': result.get('wrapper_exit'),
    'new_proofs_or_gate3_acceptance': False})
print(output.decode(), end='')
print(errors.decode(), end='', file=sys.stderr)
raise SystemExit(0 if result['process_exit'] == result['wrapper_exit'] == 0 and stable and not errors else 1)
