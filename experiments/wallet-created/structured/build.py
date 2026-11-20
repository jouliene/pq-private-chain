"""Build the registered 2x2 CFW research wallet/independent verifier executable."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DIMS = ROOT / "experiments/node-validation/dimensions"
sys.path.insert(0,str(ROOT/"scripts"))
import common


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--installation",type=Path,required=True)
    p.add_argument("--approve-installation",required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--audit",action="store_true",help="check every actual first-stage coefficient against the published dense oracle")
    a=p.parse_args()
    assert not a.output.exists()
    install=common.load_installation(a.installation,a.approve_installation)
    assert Path(install["repository"])==ROOT
    compiler=install["toolchain"]["tools"]["rustc"]
    assert common.sha(compiler["path"])==compiler["sha256"]
    libs=Path(install["workspace"])/"target/release/deps"
    with tempfile.TemporaryDirectory() as directory:
        tmp=Path(directory)
        # Reuse the frozen compiler literally. The sole addition returns its existing
        # assignment to the wallet through process memory after all rows are generated.
        # Bind the source definition (including the original payment AIR) as
        # well as the verifier-generated fixed fields in the transcript.
        library=Path(install["source_root"])/"experiments/compact-arities-v3/src"
        inputs=[(p.relative_to(library).as_posix(),p) for p in sorted(library.rglob("*.rs"))]
        inputs.append(("registered-r1cs-lowering.rs",DIMS/"lower.rs"))
        h=hashlib.sha256()
        for label,path in inputs:
            h.update(len(label).to_bytes(4,"little")+label.encode())
            content=path.read_bytes(); h.update(len(content).to_bytes(8,"little")+content)
        (tmp/"registered-id").write_bytes(h.digest())
        source=(DIMS/"lower.rs").read_text().split("fn main() {")[0]
        source=source.replace("    mut matrix: Option<&mut Sparse>,","    mut matrix: Option<&mut Sparse>,\n    export: &mut Vec<F>,")
        source=source.replace('    json!({"rows":counts.rows','    let private_count = assigned.len()-public.len()-1;\n    *export=assigned;\n    json!({"rows":counts.rows')
        source=source.replace('"private":assigned.len()-public.len()-1','"private":private_count')
        (tmp/"main.rs").write_text(source+(HERE/"app.rs").read_text())
        (tmp/"matrix.rs").write_text((DIMS/"matrix.rs").read_text()+(HERE/"plan.rs").read_text()+(HERE/"sparse.rs").read_text())
        for f in ("outer.rs","oracle.rs","pcs.rs","tape.rs","algebra.rs"):
            (tmp/f).write_bytes((HERE/f).read_bytes())
        (tmp/"fft.rs").write_bytes((DIMS/"fft.rs").read_bytes())
        if a.audit:
            sys.path.insert(0,str(HERE))
            import audit
            audit.install(tmp,DIMS)
        command=[compiler["path"],"--edition","2024","-O","-Adead_code",str(tmp/"main.rs"),"-L",f"dependency={libs}","-o",str(tmp/"candidate")]
        digests={}
        for name in ("compact_bounded_arity_v3","p3_air","p3_field","p3_goldilocks","p3_dft","p3_matrix","serde_json","tiny_keccak","libc"):
            item,=libs.glob(f"lib{name}-*.rlib")
            alias="compact_arity_v3" if name=="compact_bounded_arity_v3" else name
            command.extend(["--extern",f"{alias}={item}"])
            digests[item.name]=common.sha(item)
        subprocess.run(command,check=True)
        with a.output.open("xb") as out:
            out.write((tmp/"candidate").read_bytes())
        a.output.chmod(0o755)
        print(json.dumps({"binary_sha256":common.sha(a.output),"installation_sha256":a.approve_installation,"dense_oracle_audit":a.audit,
                          "rustc_sha256":compiler["sha256"],"rlibs":digests},sort_keys=True,indent=2))


if __name__=="__main__":
    main()
