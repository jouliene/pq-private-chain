"""Launch SWP1 wallets and validating PoW peers in an isolated local home."""
import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from stage import HERE, ROOT, build, install


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home",type=Path,default=ROOT/".work/atomic-swap-devnet")
    for suite in ("managed","swap"):
        p.add_argument("--"+suite+"-build",type=Path)
        p.add_argument("--"+suite+"-sha")
    ordinary=("start","stop","status","create","export-address","backup","restore","balance","issue","register","mint","burn","send","resume","intents","mine")
    negotiation=("terms","leg","authorize","combine","abort")
    p.add_argument("command",choices=ordinary+negotiation+("list","submit","walkthrough"))
    p.add_argument("args",nargs=argparse.REMAINDER)
    a=p.parse_args()
    home=a.home.resolve()
    home.mkdir(mode=0o700,parents=True,exist_ok=True)
    if home.stat().st_mode&0o077:
        p.error("use a private 0700 home")
    dev=home/"deployment/devnet"
    pins=(a.managed_build,a.managed_sha,a.swap_build,a.swap_sha)
    if any(pins) and not all(pins):
        p.error("supply both local builds and both explicit SHA-256 approvals")
    with (home/".installation.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if not dev.exists():
            if a.command not in ("start","walkthrough"):
                p.error("start a swap network first")
            install(home,*(pins if all(pins) else build(home)))
        if not (dev/"swap.vk").is_file():
            p.error("use a separate SWP1 deployment home")
        if all(pins) and ((dev/"approved-native.sha256").read_text().strip()!=a.managed_sha or
                          (dev/"approved-swap-native.sha256").read_text().strip()!=a.swap_sha):
            p.error("deployment approval mismatch")
    if a.command=="walkthrough":
        if a.args:
            p.error("walkthrough takes no additional arguments")
        args=[HERE/"walkthrough.py",home]
    elif a.command in negotiation:
        sys.path.insert(0,str(dev))
        import swap_wallet
        swap_wallet.main(home,a.command,a.args)
        return
    elif a.command=="submit":
        if len(a.args) not in (1,3) or (len(a.args)==3 and (a.args[1]!="--node" or a.args[2] not in ("a","b","c","d"))):
            p.error("submit FILE [--node NAME]")
        sys.path.insert(0,str(dev))
        from swap_wire import MAX_BUNDLE, split
        from transport import rpc,control
        with Path(a.args[0]).open("rb") as f:
            raw=f.read(MAX_BUNDLE+1)
        split(raw)
        meter={}
        result,_=rpc(control(home,a.args[2] if len(a.args)==3 else "c"),"submit",raw,meter=meter)
        if result["id"]!=sha256(raw).hexdigest():
            raise ValueError("node returned wrong swap identity")
        print(json.dumps(dict(result,transport=meter,bytes=len(raw))))
        return
    elif a.command=="list":
        args=[HERE.parent/"user-assets/assets.py",home,*a.args]
    else:
        args=[dev/"cli.py","--home",home,a.command,*a.args]
    os.execv(sys.executable,[sys.executable,"-IB",*map(str,args)])


if __name__=="__main__":
    main()
