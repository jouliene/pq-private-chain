#!/usr/bin/env python3
"""Runtime identity for the PUBLIC frontend jobs.

Adapted from the already executed weighted run_proof05.py runtime inventory:
actual rustup tools, compiler libs, linker tools and ldd closures. Adds explicit
Python stdlib coverage and mapped-wrapper closure. No cryptographic function.
"""
import hashlib,os,shutil,subprocess,sys,sysconfig
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def controlled_env():
    # No inherited LD_, PYTHON*, RUST*, compiler wrapper/flag or Cargo overrides.
    # HOME is solely the documented existing toolchain/package-cache location.
    return dict(PATH=str(Path.home()/'.cargo/bin')+':/usr/bin:/bin',HOME=str(Path.home()),
                LANG='C.UTF-8',CARGO_BUILD_JOBS='1',RUSTFLAGS='',RAYON_NUM_THREADS='1',
                RUST_BACKTRACE='0',RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='')
def capture(cwd,env,selected_binary=None):
    files=set();details={};tools={}
    def add(p):
        p=Path(p).resolve()
        if p.is_file():files.add(p)
    def output(args):return subprocess.check_output([str(x) for x in args],cwd=cwd,env=env,text=True,stderr=subprocess.STDOUT,timeout=5).strip()
    rustup=Path(shutil.which('rustup',path=env['PATH'])).resolve();add(rustup)
    for name in ('cargo','rustc'):
        p=Path(output([rustup,'which',name])).resolve();add(p);tools[name]=p
        details[name]=dict(path=str(p),version=output([p,'--version','--verbose']))
    # Pin the selected compiler, never trust an inherited RUSTC setting.
    env['RUSTC']=str(tools['rustc'])
    lib=tools['rustc'].parent.parent/'lib'
    for p in lib.glob('*.so*'):add(p)
    for p in (lib/'rustlib/x86_64-unknown-linux-gnu/lib').glob('*'):
        if p.is_file() and (p.suffix in ('.rlib','.so','.a') or p.name.endswith('.o')):add(p)
    for name in ('cc','ld','ar'):
        found=shutil.which(name,path=env['PATH'])
        if not found:raise RuntimeError('missing approved linker tool '+name)
        tools[name]=Path(found).resolve();add(tools[name])
        details[name]=dict(path=str(tools[name]),version=output([tools[name],'--version']))
    env.update(CC=str(tools['cc']),AR=str(tools['ar']),CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=str(tools['cc']))
    for name in ('cc1','collect2'):
        p=Path(output([tools['cc'],'-print-prog-name='+name]));add(p);tools[name]=p
    for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbeginS.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a'):
        p=Path(output([tools['cc'],'-print-file-name='+name]));add(p)
    python=Path(sys.executable).resolve();tools['python']=python;add(python)
    details['python']=dict(path=str(python),version=sys.version,stdlib=sysconfig.get_path('stdlib'))
    # Cover actual loaded wrapper modules AND the child's standard-library code,
    # including existing pyc files it may read; omit external site-packages.
    stdlib=Path(sysconfig.get_path('stdlib')).resolve()
    for parent,dirs,names in os.walk(stdlib):
        dirs[:]=[d for d in dirs if d not in ('site-packages','dist-packages')]
        for name in names:
            if name.endswith(('.py','.pyc','.so')):add(Path(parent)/name)
    for module in list(sys.modules.values()):
        file=getattr(module,'__file__',None)
        if file and Path(file).is_file():add(file)
    maps=Path('/proc/self/maps')
    if maps.exists():
        for line in maps.read_text().splitlines():
            cols=line.split()
            if len(cols)>=6 and cols[-1].startswith('/') and Path(cols[-1]).is_file():add(cols[-1])
    add('/usr/bin/ldd');add('/etc/ld.so.cache')
    if selected_binary is not None:tools['selected_binary']=selected_binary;add(selected_binary)
    for executable in list(tools.values()):
        if not executable.is_file():continue
        result=subprocess.run(['/usr/bin/ldd',str(executable)],cwd=cwd,env=env,capture_output=True,text=True,timeout=5)
        details.setdefault('ldd',{})[str(executable)]=dict(exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr)
        for word in (result.stdout+' '+result.stderr).split():
            if word.startswith('/') and Path(word).is_file():add(word)
    # Configuration can affect compiler/linker selection. Record identities;
    # wrappers and tool paths above are explicitly overridden in controlled env.
    for parent in [Path(cwd),*Path(cwd).parents,Path.home()]:
        for suffix in ('.cargo/config','.cargo/config.toml','rust-toolchain','rust-toolchain.toml'):
            add(parent/suffix)
    return tools,details,{str(p):sha(p) for p in sorted(files)}
