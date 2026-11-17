"""Fresh offline public build: relocated source, fixed programs and native checks."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,importlib.util,json,os,shutil
REPO=Path(__file__).resolve().parents[1]
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()
def need(ok,message):
 if not ok:raise ValueError(message)
def save(p,value):
 with Path(p).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def source_hashes(root):
 return {str(p.relative_to(root)):sha(p)for p in sorted((root/'source').rglob('*'))if p.is_file()and 'target'not in p.relative_to(root).parts}
def command(common, argv, root, env, name, seconds=120, cap=32 * 1024**2, data=b''):
    r, o, e = common.run(argv, cwd=root, env=env, seconds=seconds,
                         cap=cap, data=data, record=root / 'fresh/results' / name)
    need(r['wrapper_exit'] == r['process_exit'] == 0 and not r['timeout'], name + ' actual status')
    return r, o, e


def runtime_python(root, common, installed, binaries):
    import sysconfig
    # Match the old parent's fixed import closure before collecting its mappings.
    p = root / 'source/experiments/compact-all-payments-v3/private04-proposal/next07/private_parent.py'
    load('fresh_parent_inventory', p)
    native = dict(installed['runtime'])
    paths = {Path(sys.executable).resolve(), Path('/usr/bin/ldd').resolve()}
    stdlib = Path(sysconfig.get_path('stdlib')).resolve()
    for base, dirs, files in os.walk(stdlib):
        dirs[:] = [d for d in dirs if d not in ('site-packages', 'dist-packages')]
        for f in files:
            if f.endswith(('.py', '.pyc', '.so')):
                paths.add((Path(base) / f).resolve())
    for line in Path('/proc/self/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].startswith('/'):
            paths.add(Path(fields[5]).resolve(strict=True))
    for binary in [*binaries, Path(sys.executable).resolve()]:
        paths.add(binary)
        _, output, errors = command(common, ['/usr/bin/ldd', str(binary)], root,
                                    common.controlled_env(), 'ldd-' + binary.name, seconds=15)
        need(not errors and b'not found' not in output, 'native linkage')
        linked = set()
        for word in output.decode().split():
            if word.startswith('/'):
                linked.add(Path(word).resolve(strict=True))
        if binary in binaries:
            need(all(installed['runtime'].get(str(p)) == sha(p) for p in linked),
                 'compiled binary linked an unapproved native library')
            if binary.name == 'ledger-cp03':
                need(installed['libcrypto'] in {str(p) for p in linked}, 'actual ledger libcrypto linkage')
        paths.update(linked)
    native.update({str(p): sha(p) for p in sorted(paths)})
    return native


def build(a, root):
    common = load('common', root / 'common.py')
    manifest = common.package_sources()
    installed = common.installation()
    need(not (root / 'target').exists() and not (root / 'cargo-home').exists(), 'fresh isolated target/home')
    home = root / 'cargo-home'
    home.mkdir()
    (home / 'config.toml').write_text('[source.crates-io]\nreplace-with = "audit-vendor"\n[source.audit-vendor]\ndirectory = ' + json.dumps(str(REPO / 'vendor')) + '\n[net]\noffline = true\n')
    cargo = a.cargo.absolute()
    rustup = cargo.parent / 'rustup'
    need(cargo.name == 'cargo' and cargo.resolve(strict=True) == rustup.resolve(strict=True), 'explicit rustup Cargo proxy')
    env = common.controlled_env()
    env.update(CARGO_HOME=str(home), CARGO_TARGET_DIR=str(root / 'target'),
               PATH=str(cargo.parent) + ':/usr/bin:/bin', HOME=str(Path.home()),
               RUSTUP_HOME=os.environ.get('RUSTUP_HOME', str(Path.home() / '.rustup')),
               LIBRARY_PATH=str(Path(installed['libcrypto']).parent), CARGO_BUILD_JOBS='1', TMPDIR=str(root / '.tmp'))
    tools = {}
    for name in ('cargo', 'rustc'):
        _, o, e = command(common, [str(rustup), 'which', '--toolchain', '1.99.1', name], root, env, 'select-' + name, seconds=15)
        need(not e, 'tool selection stderr')
        p = Path(o.decode().strip()).resolve(strict=True)
        _, v, e = command(common, [str(p), '-vV'], root, env, 'version-' + name, seconds=15)
        need(not e and v.decode().startswith(name + ' 1.99.1 '), 'exact installed Rust version')
        tools[name] = {'path': str(p), 'sha256': sha(p), 'version': v.decode()}
    cc = Path(shutil.which('cc', path='/usr/bin:/bin')).resolve(strict=True)
    _, cc_version, cc_errors = command(common, [str(cc), '--version'], root, env, 'version-cc', seconds=15)
    need(not cc_errors, 'C compiler version')
    tools['cc'] = {'path': str(cc), 'sha256': sha(cc), 'version': cc_version.decode()}
    tools['rustup'] = {'path': str(rustup.resolve()), 'sha256': sha(rustup.resolve())}
    env.update(RUSTC=tools['rustc']['path'], CC=str(cc))
    save(root / 'fresh/toolchain.json', {'tools': tools, 'environment': env})
    cargo = tools['cargo']['path']
    path = root / 'fresh/Cargo.toml'
    # Only the finite checksum-verified bundled versions are available. Retain
    # the generated lock before --locked compilation; no network/cache fallback.
    before = source_hashes(root)
    before['fresh/Cargo.toml'] = sha(path)
    before['fresh/Cargo.lock'] = sha(root / 'fresh/Cargo.lock')
    r, output, errors = command(common, [cargo, 'build', '--offline', '--locked', '--release', '-j1', '--message-format=json', '--manifest-path', str(path), '--bins'], root, env, 'build', seconds=a.seconds)
    rows = [json.loads(x) for x in output.splitlines()]
    need(rows[-1] == {'reason': 'build-finished', 'success': True}, 'actual Cargo completion')
    artifacts = [x for x in rows if x.get('reason') == 'compiler-artifact']
    executables = {x['target']['name']: Path(x['executable']).resolve(strict=True) for x in artifacts if x.get('executable')}
    need(set(executables) == {'ledger-cp03', 'compact-all-payments-v3', 'cp03-hash-core', 'provider-controls'}, 'four fresh actual binaries')
    forbidden = {'archive-crash-controls', 'crash-controls', 'admission-cost-trace', 'storage-cost-controls'}
    for item in artifacts:
        p = Path(item['manifest_path']).resolve(strict=True)
        need((any(p.is_relative_to(root / d) for d in ('source', 'fresh')) or p.is_relative_to(REPO / 'vendor')), 'manifest original-tree fallback')
        need(not set(item['features']) & forbidden, 'diagnostic build feature')
    depfiles = {}
    for name, binary in executables.items():
        need(binary == root / 'target/release' / name, 'isolated executable')
        dep = binary.with_suffix('.d')
        names = dep.read_text().replace('\\\n', '').splitlines()[0].partition(': ')[2].split()
        paths = [Path(x).resolve(strict=True) for x in names]
        need(all((any(p.is_relative_to(root / d) for d in ('source', 'fresh')) or p.is_relative_to(REPO / 'vendor')) for p in paths), 'depfile original-tree fallback')
        depfiles[name] = {str(p): sha(p) for p in paths}
    need(all(sha(root / p) == h for p, h in before.items()), 'build input drift')
    common.hashes({item['path']: item['sha256'] for item in tools.values()})
    native = runtime_python(root, common, installed, list(executables.values()))
    need(installed['libcrypto'] in native, 'ledger libcrypto linkage')
    helper = root / 'source/experiments/compact-receiving-v1/cp03/hash-core/target/release/cp03-hash-core'
    helper.parent.mkdir(parents=True)
    shutil.copyfile(executables['cp03-hash-core'], helper)
    helper.chmod(0o700)
    native[str(helper)] = sha(helper)
    cycle = root / 'source/wallet/cp03/cycle.mjs'
    old = cycle.read_text()
    need(old.count('__CP03_INSTALLED_HELPER_SHA256__') == 1, 'fixed helper installation placeholder')
    (root / 'fresh/cycle-preimage.mjs').write_text(old)
    cycle.write_text(old.replace('__CP03_INSTALLED_HELPER_SHA256__', sha(helper)))
    common.save(root / 'source-overrides.json', {'source/wallet/cp03/cycle.mjs': sha(cycle)})
    source = root / 'source'
    (source / 'fresh').mkdir()
    # The bridge's historical format is reused only as an installation schema;
    # all receipts below are produced by this actual new build and inspect.
    sources = {str(Path(p).relative_to('source')): h for p, h in source_hashes(root).items()}
    save(source / 'fresh/source-manifest.json', {'format': 'CP03-FRESH-SOURCE01', 'sources': sources})
    source_sha = sha(source / 'fresh/source-manifest.json')
    build_receipt = dict(format='CP03-FRESH-BUILD01', mode='build', process_exit=0, wrapper_exit=0, timeout=False,
        source_pins_unchanged=True, runtime_pins_unchanged=True, manifest_sha256=source_sha,
        binary_sha256=sha(executables['compact-all-payments-v3']), actual_process=r,
        compiler_artifacts=artifacts, compiled_depfiles=depfiles, build_source_hashes=before,
        executables={k: {'path': str(p), 'sha256': sha(p)} for k, p in executables.items()},
        no_original_source_or_registry_fallback=True)
    save(source / 'fresh/build.json', build_receipt)
    common.hashes(native)
    inspect_r, inspect_o, inspect_e = command(common, [str(executables['compact-all-payments-v3']), 'inspect'], root,
        {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'RUST_BACKTRACE': '0', 'RAYON_NUM_THREADS': '1'}, 'inspect')
    need(not inspect_e, 'inspect stderr')
    prepared = json.loads(inspect_o)['registry']['programs']
    common.hashes(native)
    proof_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'RUST_BACKTRACE': '0', 'RAYON_NUM_THREADS': '1'}
    save(source / 'fresh/inspect.json', dict(format='CP03-FRESH-INSPECT01', mode='inspect', process_exit=0, wrapper_exit=0,
        timeout=False, source_pins_unchanged=True, runtime_pins_unchanged=True, manifest_sha256=source_sha,
        binary_sha256=sha(executables['compact-all-payments-v3']), runtime_before=native, runtime_after=native,
        runtime_details={'python': {'path': str(Path(sys.executable).resolve())}}, controlled_environment=proof_env,
        prepared=prepared, actual_process=inspect_r))
    # Executables are public artifacts, copied under source root for the existing
    # wallet's fixed repository boundary. No historic binary is consulted.
    bins = source / 'fresh/bin'
    bins.mkdir()
    for name in ('ledger-cp03', 'compact-all-payments-v3'):
        shutil.copyfile(executables[name], bins / name)
        (bins / name).chmod(0o700)
    approval = {'format': 'CP-PRIVATE-OPERATOR07', 'source_manifest': 'fresh/source-manifest.json',
        'source_manifest_sha256': source_sha, 'build_receipt': 'fresh/build.json',
        'build_receipt_sha256': sha(source / 'fresh/build.json'), 'binary': 'fresh/bin/compact-all-payments-v3',
        'binary_sha256': sha(bins / 'compact-all-payments-v3'), 'prepared': prepared,
        'runtime_receipt': 'fresh/inspect.json', 'runtime_receipt_sha256': sha(source / 'fresh/inspect.json')}
    save(source / 'fresh/private-approval.json', approval)
    probe = """import importlib.util
from pathlib import Path
p=Path('experiments/compact-all-payments-v3/private04-proposal/next07/private_parent.py').resolve()
s=importlib.util.spec_from_file_location('installed_parent',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.Parent(Path('fresh/private-approval.json'))
print('FRESH_PRIVATE_INSTALLATION_CHECKED')
"""
    probe_r, probe_o, probe_e = common.run([str(Path(sys.executable).resolve()), '-I', '-B', '-c', probe],
        cwd=source, env=proof_env, seconds=60, record=root / 'fresh/results/private-installation-probe')
    need(probe_r['process_exit'] == probe_r['wrapper_exit'] == 0 and not probe_e and
         probe_o == b'FRESH_PRIVATE_INSTALLATION_CHECKED\n', 'actual new-process private installation probe')
    # Real provider-owned prepare/verify path, including eight positive/negative
    # controls. Public request fixtures contain no secret signing material.
    provider_r, provider_o, provider_e = command(common, [str(executables['provider-controls']),
        str(root / 'public/a.request'), str(root / 'public/b.request')], root, proof_env, 'provider-controls')
    provider = common.read_json(root / 'fresh/results/provider-controls.stdout')
    need(not provider_e and provider['format'] == 'CP03-ACTUAL-PROVIDER-CONTROLS02' and
         len(provider['controls']) == 8 and all(x['passed'] is True for x in provider['controls']), 'eight actual signature controls')
    save(source / 'fresh/provider-controls.json', {'actual_process': provider_r, 'result': provider})
    def entry(p):
        return {'path': str(p.relative_to(source)), 'sha256': sha(p)}
    operator = dict(format='CP03-CYCLE-OPERATOR01', helper_sha256=sha(helper),
        ledger_binary=entry(bins / 'ledger-cp03'), ledger_build_receipt=entry(source / 'fresh/build.json'),
        private_approval=entry(source / 'fresh/private-approval.json'),
        provider_controls_receipt=entry(source / 'fresh/provider-controls.json'),
        protocol_manifest=entry(source / 'docs/architecture/CP_PROTOCOL_03.json'))
    save(source / 'fresh/operator.json', operator)
    # Include installed binary copies and all runtime/approval/source inputs in
    # outer checks, independently of private parent's source map.
    pins = {str(source / p): h for p, h in sources.items()}
    pins.update(native)
    for p in sorted((source / 'fresh').rglob('*')):
        if p.is_file():
            pins[str(p)] = sha(p)
    for p in [root / 'installation.json', root / 'MANIFEST.json', root / 'common.py',
              root / 'common.py', root / 'prepare_runtime.py', root / 'replay.py',
              root / 'fresh/Cargo.toml', root / 'fresh/Cargo.lock', root / 'fresh/toolchain.json']:
        pins[str(p)] = sha(p)
    for name, item in common.verify_repository(REPO)['files'].items():
        pins[str(REPO / name)] = item['sha256']
    pins[str(REPO / 'CORE_MANIFEST.json')] = sha(REPO / 'CORE_MANIFEST.json')
    pins.update({item['path']: item['sha256'] for item in tools.values()})
    common.hashes(pins)
    save(root / 'fresh/installation.json', {'format': 'CP03-PUBLIC-INSTALLATION01', 'pins': pins,
         'operator': entry(source / 'fresh/operator.json'), 'proof_environment': proof_env,
         'node': installed['node'], 'new_source_build': True, 'private_inputs': False,
         'repository': str(REPO), 'workspace': str(root), 'source_root': str(source), 'vendor': str(REPO/'vendor'),
         'operator_path': str(source/'fresh/operator.json'), 'operator_sha256': sha(source/'fresh/operator.json'),
         'helper_sha256': sha(helper), 'toolchain': {'tools': tools, 'environment': env},
         'toolchain_path': str(root/'fresh/toolchain.json'), 'toolchain_sha256': sha(root/'fresh/toolchain.json')})
    save(root/'build-result.json', {'format':'CP03-AUDIT-BUILD01','actual_exit':0,'binary':'target/release/ledger-cp03',
        'binary_sha256':sha(executables['ledger-cp03']),'installation_sha256':sha(root/'installation.json')})
    print(json.dumps({'format':'CP03-PUBLIC-BUILD01','installation':str(root/'fresh/installation.json'),
        'approve_installation_sha256':sha(root/'fresh/installation.json'),'fresh_provider_controls':8,'private_smoke_executed':False}))

