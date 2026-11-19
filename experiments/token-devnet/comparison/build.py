"""Use the pinned TKN1 construction overlay, changing only the proof backend and framing."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = ROOT / 'experiments/token-profile/candidate'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('source did not contain exactly one expected pattern: ' + old)
    return text.replace(old, new)


def build(work, upstream, target):
    work.mkdir(exist_ok=False, parents=True)
    with tempfile.TemporaryDirectory(dir=work) as scratch:
        staged = Path(scratch)
        (staged / 'devnet').symlink_to(ROOT / 'devnet', target_is_directory=True)
        source = staged / 'experiments/token-profile/candidate'
        source.mkdir(parents=True)
        for component in ('payment-architecture', 'advancing-payments'):
            (staged / 'experiments' / component).symlink_to(ROOT / 'experiments' / component, target_is_directory=True)
        for name in ('wallet.rs','pair_codec.rs'):
            shutil.copyfile(BASE / name, source / name)
        shutil.copyfile(HERE / 'REGISTER.md', source / 'PROFILE.md')
        profile = (BASE / 'profile.rs').read_text()
        profile = replace_once(profile, 'use qnero_aggregator::Proof;', (HERE/'config.rs').read_text())
        profile = replace_once(profile, '    C, D, F,', '    D, F,')
        profile = replace_once(profile, 'num_query_rounds = 26', 'num_query_rounds = 64')
        profile = replace_once(profile, '\\"TKN1\\"', '\\"TKQ1\\"')
        (source / 'profile.rs').write_text(profile)
        script = (BASE/'build.py').read_text()
        step = "        (dest/\"codec.rs\").write_text(codec)"
        script = replace_once(script, step, '\n'.join([
            "        codec=codec.replace('b\"TKN1\"', 'b\"TKQ1\"')",
            "        codec=codec.replace('use qnero_aggregator::{Proof, F};', 'use crate::registry::Proof;\\nuse qnero_circuit::F;')", step]))
        (source/'build.py').write_text(script)
        subprocess.run([sys.executable,'-IB',source/'build.py',work,upstream,target],check=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ('work','upstream','target'):
        parser.add_argument(arg,type=Path)
    args=parser.parse_args()
    build(args.work.resolve(),args.upstream.resolve(),args.target.resolve())
