import hashlib, json, os
from pathlib import Path
import stat, subprocess, sys, tarfile, time

here = Path(__file__).resolve().parent
wrapper = Path.cwd() / 'scripts/ci_noble.sh'
raw = wrapper.read_bytes()
before = hashlib.sha256(raw).hexdigest()
marker = 'python3 -I - "$rootfs" "$record/image-temp-permissions.json" <<\'PY\'\n'
assert raw.decode().count(marker) == 1
guard = raw.decode().split(marker)[1].split('\nPY\n')[0]
archive = here / 'public-directories.tar.gz'
with tarfile.open(archive, 'w:gz') as output:
    for name, mode in (('tmp', 0o1777), ('var', 0o755), ('var/tmp', 0o1777)):
        item = tarfile.TarInfo(name)
        item.type, item.mode = tarfile.DIRTYPE, mode
        output.addfile(item)
rows = []
started = time.monotonic()
for flag in ('--no-same-permissions', '--same-permissions'):
    root = here / flag[2:]
    root.mkdir()
    command = ['/usr/bin/tar', '--extract', '--gzip', '--file', str(archive), '--directory', str(root),
               '--no-same-owner', flag]
    actual = subprocess.run(command, preexec_fn=lambda: os.umask(0o002), capture_output=True, timeout=5)
    assert len(actual.stdout) <= 8192 and len(actual.stderr) <= 8192
    guard_passed = True
    old_argv = sys.argv
    try:
        sys.argv = ['exact-wrapper-permission-guard', str(root), str(root / 'guard.json')]
        exec(compile(guard, str(wrapper) + ':permission-guard', 'exec'), {})
    except AssertionError:
        guard_passed = False
    finally:
        sys.argv = old_argv
    rows.append({'argv': command, 'exit': actual.returncode, 'stdout': actual.stdout.decode(),
                 'stderr': actual.stderr.decode(), 'guard_passed': guard_passed,
                 'modes': {name: oct(stat.S_IMODE((root / name).lstat().st_mode))
                           for name in ('tmp', 'var/tmp')}})
after = hashlib.sha256(wrapper.read_bytes()).hexdigest()
passed = (before == after and all(row['exit'] == 0 and not row['stderr'] for row in rows)
          and rows[0]['guard_passed'] is False and rows[1]['guard_passed'] is True
          and set(rows[1]['modes'].values()) == {'0o1777'})
result = {'format': 'CP04-NOBLE-TAR-PERMISSIONS-CONTROL01', 'passed': passed,
          'scope': 'Tiny public directory archive; actual GNU tar and exact wrapper guard; '
                   'no sudo/chroot/apt, existing rootfs change, build or proof.',
          'umask': '0002', 'source_before': before, 'source_after': after, 'rows': rows,
          'wall_seconds': time.monotonic() - started}
with (here / 'RESULT.json').open('x') as output:
    json.dump(result, output, indent=2, sort_keys=True)
    output.write('\n')
print(json.dumps({'passed': passed, 'receipt': str(here / 'RESULT.json')}))
assert passed
