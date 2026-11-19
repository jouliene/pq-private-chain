"""Build independent public arithmetic helpers against pristine pinned upstream source."""
import argparse
from hashlib import sha256
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
UPSTREAM = 'f04c91307837c0231668383bec76ba98d89d2652'
LOCK = 'ed076404a8d396ddda4acf9a42a915c54472bb70d3dc58300e262f7ecf152a20'


def build(source, upstream, dest):
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=upstream, text=True).strip()
    if revision != UPSTREAM or subprocess.check_output(['git', 'status', '--porcelain'], cwd=upstream):
        raise ValueError('pristine pinned upstream required')
    if sha256((upstream / 'Cargo.lock').read_bytes()).hexdigest() != LOCK:
        raise ValueError('Cargo lock digest')
    dest.mkdir(parents=True, exist_ok=False)
    rust = ['rustup', 'run', '1.93.0']
    target = dest / 'target'
    subprocess.run(rust + ['cargo', 'build', '--locked', '--offline', '--release', '-j2', '-p', 'qnero-notes',
                           '-p', 'qnero-circuit', '--target-dir', target], cwd=upstream, check=True)
    deps = target / 'release/deps'
    programs = [('founding', HERE / 'genesis.rs', ['qnero_notes']),
                ('roots', source / 'experiments/advancing-payments/review/reference_roots.rs', ['qnero_notes', 'qnero_circuit'])]
    for name, path, crates in programs:
        cmd = rust + ['rustc', '--edition=2021', '-C', 'opt-level=2', '-L', 'dependency=' + str(deps)]
        for crate in crates:
            library, = deps.glob('lib' + crate + '-*.rlib')
            cmd += ['--extern', crate + '=' + str(library)]
        subprocess.run(cmd + [path, '-o', dest / name], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('source', 'upstream', 'destination'):
        parser.add_argument(key, type=lambda p: Path(p).resolve())
    args = parser.parse_args()
    build(args.source, args.upstream, args.destination)
