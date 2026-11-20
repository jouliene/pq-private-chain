"""Build witness-producing wallet-only roles from both original registered source generators."""
import argparse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def build(out,upstream,target):
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    for name, family in (("ordinary","managed-assets"),("leg","atomic-swap")):
        source=ROOT/"experiments"/family/"native/build.py"
        def add_capture(dest):
            profile=dest/"registry.rs"
            s=profile.read_text()
            needle='        self.data\n            .prove(witness)\n            .map_err(|_| anyhow!("proof construction"))'
            if s.count(needle)!=1:
                raise ValueError("unexpected registered witness assignment")
            end='delta, &[]' if name=="ordinary" else '0, &words(auth_key)'
            s=s.replace(needle,needle.replace("self.data","let proof = self.data")+
                        '?;\n        capture(w,opened,asset_id,'+end+',&proof)?;\n        Ok(proof)')
            profile.write_text(s+"\n"+(HERE/"capture.rs").read_text())
        marker="        sources={"
        s=source.read_text()
        if s.count(marker)!=1:
            raise ValueError("unexpected original source generator")
        ns={"__file__":str(source),"__name__":"funded_fixture_generator","add_capture":add_capture}
        exec(compile(s.replace(marker,"        add_capture(dest)\n"+marker),str(source),"exec"),ns)
        ns["prepare"](out/name,upstream,target)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for k in ("out","upstream","target"):
        parser.add_argument(k,type=Path)
    a=parser.parse_args()
    build(a.out.resolve(),a.upstream.resolve(),a.target.resolve())
