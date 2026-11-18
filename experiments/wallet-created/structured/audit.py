"""Generate an audit-only verifier using the published matrix oracle on actual proof coins."""
from pathlib import Path


def install(directory, dimensions):
    tmp = Path(directory)
    frozen = (dimensions/"matrix.rs").read_text()
    basis = frozen.index("        let mut equality = vec![E::ONE];")
    end = frozen.index("        let stage_cpu = cpu_time() - cpu_start;")
    body = frozen[basis:end]
    body = body.replace("for _ in 0..21 {\n            let alpha = draw();", "for &alpha in alpha {")
    body = body.replace("        let rho = draw();", "")
    body = body.replace("        let betas: [F; 4] = core::array::from_fn(|_| F::from_u64(words.next().unwrap()));", "")
    start = body.index("        for _ in 0..4 {")
    end = body.index("            for group in 0..active",start)
    body = body[:start]+"        for &gamma in gamma {\n"+body[end:]
    body = "\n".join(line for line in body.splitlines() if all(needle not in line for needle in
        ("let basis_s =","let contraction_s =","let contraction_cpu =")))
    assert "words" not in body and "draw()" not in body
    added = '''
impl Sparse {
    pub(super) fn audit_actual(&self, alpha:&[E], rho:E,betas:[F;4],gamma:&[E],p:&[E],main:&[E])->String {
'''
    added += body + '''
        assert!(p == &form[..50],"audit public prefix");
        assert!(main == &private[..active],"audit guarded first four folds");
        digest_outputs(p,main)
    }
}
'''
    with (tmp/"matrix.rs").open("a") as out:
        out.write(added)
    p = tmp/"pcs.rs"
    s=p.read_text().replace("pub fn execute(\n","pub fn execute(\n    audit:&Sparse,\n")
    s=s.replace("            let (p, main, _, _) = plan", "            let started=matrix::cpu_time();\n            let (p, main, _, _) = plan")
    needle="            let subtraction: E ="
    assert s.count(needle)==1
    s=s.replace(needle, """            let middle=matrix::cpu_time();
            let digest=audit.audit_actual(&claim.alpha, claim.rho, claim.beta.clone().try_into().unwrap(), &gamma, &p, &main);
            eprintln!("{}",serde_json::json!({"structured_cpu_s":middle-started,"oracle_and_audit_digest_cpu_s":matrix::cpu_time()-middle,
                        "public_prefix":p.len(),"folded_coordinates":main.len(),"checked_fold_shake256_32":digest}));
"""+needle)
    p.write_text(s)
    p=tmp/"main.rs"
    s=p.read_text()
    assert s.count("pcs::execute(&mut tape,")==2
    p.write_text(s.replace("pcs::execute(&mut tape,","pcs::execute(&matrix,&mut tape,"))
