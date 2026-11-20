"""Build separate K384 native roles using both existing versioned native source generators."""
import argparse
import importlib.util
from pathlib import Path
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
SUITES={"ordinary":("managed-assets","MNG1","K3M1","managed.vk"),
        "leg":("atomic-swap","SLG1","K3L1","swap.vk")}


def once(source,original,replacement):
    if source.count(original)!=1:
        raise ValueError(f"unexpected upstream pattern {original!r}")
    return source.replace(original,replacement)


def overlay(dest,enc,pq,old,new):
    registry=dest/"registry.rs"
    s=once(registry.read_text(),"use qnero_aggregator::Proof;",(HERE/"config.rs").read_text())
    s=once(s,"    C, D, F,","    D, F,")
    s=once(s,"num_query_rounds = 26","num_query_rounds = 64")
    registry.write_text(s.replace(old,new))
    codec=dest/"codec.rs"
    s=once(codec.read_text(),"use qnero_aggregator::{Proof, F};","use crate::registry::Proof;\nuse qnero_circuit::F;")
    codec.write_text(s.replace(old,new))
    if old=="SLG1":
        wallet=dest/"wallet.rs"
        before = """b'S' if cmd.len()==65 => Ok(qnero_notes::encrypt::swap_sign(
                key.expose_bytes(), cmd[1..33].try_into().unwrap(), cmd[33..].try_into().unwrap())),"""
        after = """b'S' if cmd.len()==65 => {
                let meter = Meter::start();
                let signature = qnero_notes::encrypt::swap_sign(
                    key.expose_bytes(), cmd[1..33].try_into().unwrap(), cmd[33..].try_into().unwrap());
                meter.finish("swap_sign");
                Ok(signature)
            },"""
        wallet.write_text(once(wallet.read_text(),before,after))
    if old=="MNG1":
        # No legacy VK can be decoded using a different commitment type.
        main=dest/"main.rs"
        s=once(main.read_text(),"mod legacy;","").replace("            let ast1 = legacy::registered()?;\n","")
        start,end=s.index("                let (selected, magic)"),s.index("                let proof = registry::verify(selected")
        s=s[:start]+'                let p = packet(bytes,b"K3M1")?;\n'+s[end:]
        main.write_text(once(s,"registry::verify(selected","registry::verify(&verifier"))
        (dest/"legacy.rs").unlink()
        (dest/"legacy_ast1.vk").unlink()
    pq.write_text(pq.read_text()+'\npub use sha3 as candidate_sha3;\n')
    enc.write_text(enc.read_text()+'\npub use qnero_pqcrypto::note_encryption::candidate_sha3;\n')


def build(work,upstream,target):
    work.mkdir(exist_ok=False,parents=True)
    for name,(family,old,new,key) in SUITES.items():
        src=ROOT/"experiments"/family/"native"
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            stage=Path(tmp)
            for f in src.glob("*.rs"):
                (stage/f.name).symlink_to(f)
            (stage/"PROFILE.md").symlink_to(HERE/"REGISTER.md")
            code=once((src/"build.py").read_text(), "ROOT = HERE.parents[2]",f"ROOT = Path({str(ROOT)!r})")
            code=once(code,"        sources={",f"        overlay(dest,enc,pq,{old!r},{new!r})\n        sources={{")
            mod=stage/'build.py'
            mod.write_text(code)
            spec=importlib.util.spec_from_file_location('proof_build_'+name,mod)
            b=importlib.util.module_from_spec(spec)
            b.overlay=overlay
            spec.loader.exec_module(b)
            b.prepare(work/name,upstream,target)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("work","upstream","target"):
        p.add_argument(k,type=Path)
    a=p.parse_args()
    build(a.work.resolve(),a.upstream.resolve(),a.target.resolve())
