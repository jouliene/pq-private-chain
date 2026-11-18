mod oracle;
mod outer;
mod pcs;
mod tape;
use p3_field::{BasedVectorSpace, Field, TwoAdicField, extension::BinomialExtensionField};
use std::path::PathBuf;
use std::time::Instant;
use tape::Tape;
type E = BinomialExtensionField<F, 5>;

fn eq(xs: &[E]) -> Vec<E> {
    let mut v = vec![E::ONE];
    for &x in xs {
        let n = v.len();
        v.resize(2 * n, E::ZERO);
        for i in 0..n {
            let y = v[i] * x;
            v[i] -= y;
            v[n + i] = y;
        }
    }
    v
}
fn powers(x: E, n: usize) -> Vec<E> {
    let mut v = vec![E::ONE; n];
    for i in 1..n {
        v[i] = v[i - 1] * x;
    }
    v
}
fn horner(c: &[E], x: E) -> E {
    c.iter().rev().fold(E::ZERO, |v, &a| v * x + a)
}
fn dot(a: &[E], b: &[E]) -> E {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&x, &y)| x * y).sum()
}
fn interpolate(input: &[E]) -> Vec<E> {
    let mut ds = input.to_vec();
    let mut form = vec![F::ONE];
    let mut out = vec![E::ZERO; ds.len()];
    for i in 0..input.len() {
        for (j, &c) in form.iter().enumerate() {
            out[j] += ds[0] * c;
        }
        for j in 1..ds.len() {
            ds[j - 1] = ds[j] - ds[j - 1];
        }
        ds.pop();
        let mut next = vec![F::ZERO; form.len() + 1];
        for (j, &c) in form.iter().enumerate() {
            next[j] -= c * F::from_usize(i);
            next[j + 1] += c;
        }
        let inv = F::from_usize(i + 1).inverse();
        for c in &mut next {
            *c *= inv;
        }
        form = next;
    }
    out
}
fn fold_adjacent(v: &mut Vec<E>, x: E) {
    for i in 0..v.len() / 2 {
        let lo = v[2 * i];
        v[i] = lo + (v[2 * i + 1] - lo) * x;
    }
    v.truncate(v.len() / 2);
}

fn main() {
    // Private parser/assertion errors must never dump the input.
    std::panic::set_hook(Box::new(|info| {
        if let Some(s) = info.location() {
            eprintln!(
                "CFW rejection at {}:{}",
                s.file().rsplit('/').next().unwrap(),
                s.line()
            );
        }
    }));
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    assert!(!args.is_empty());
    let mode = args[0].to_str().unwrap();
    let begin = Instant::now();
    let cpu = matrix::cpu_time();
    let air = PaymentAir::new(Arity::Two);
    let program = tape::hash(
        b"registered-program",
        &[
            include_bytes!("registered-id"),
            &air.program().identity_material(),
        ],
    );
    let fixed = &air.program().preprocessing().values;
    let constraints = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air(&air));
    assert_eq!(constraints.len(), 966);
    let mut dag = Dag::default();
    let assertions: Vec<_> = constraints.iter().map(|expr| dag.insert(expr)).collect();
    if mode == "verify" || mode == "verify-many" {
        assert!(if mode == "verify" {
            args.len() == 3
        } else {
            args.len() >= 3 && args.len() % 2 == 1
        });
        let mut matrix = Sparse::default();
        let stats = lower(
            &dag,
            &assertions,
            fixed,
            &[F::ZERO; 49],
            &vec![F::ZERO; 512 * 579],
            Some(&mut matrix),
            &mut Vec::new(),
        );
        assert_eq!(stats["rows"], 614387);
        assert_eq!(stats["private"], 612532);
        let plan = matrix.plan();
        let prep = begin.elapsed().as_secs_f64();
        let prep_cpu = matrix::cpu_time() - cpu;
        let mut records = vec![];
        for pair in args[1..].chunks_exact(2) {
            let clock = Instant::now();
            let start_cpu = matrix::cpu_time();
            let statement_bytes = std::fs::read(&pair[0]).unwrap();
            let statement = Statement::parse(&statement_bytes).unwrap();
            assert_eq!(statement.arity, Arity::Two);
            assert!(std::fs::metadata(&pair[1]).unwrap().len() <= 272556);
            let mut tape = Tape::new(
                &statement_bytes,
                &program,
                Some(std::fs::read(&pair[1]).unwrap()),
            );
            let mut public = vec![F::ONE];
            public.extend(statement.projection().unwrap());
            let initial = pcs::start(&mut tape, None, &mut None);
            let claim = outer::execute(&mut tape, &matrix, &[], &public, None);
            pcs::execute(&mut tape, Some(&plan), claim, &public, initial, &mut None);
            records.push(
                json!({"accepted":true,"mode":"verify","proof_bytes":tape.data.len(),
                                "post_preparation_wall_s":clock.elapsed().as_secs_f64(),
                                "post_preparation_thread_cpu_s":matrix::cpu_time()-start_cpu}),
            );
        }
        let mut report = if mode == "verify" {
            records.pop().unwrap()
        } else {
            json!({"accepted":true,"mode":mode,"records":records})
        };
        report["matrix_preparation_s"] = json!(prep);
        report["matrix_preparation_thread_cpu_s"] = json!(prep_cpu);
        println!("{report}");
        return;
    }
    assert_eq!(mode, "prove");
    assert_eq!(args.len(), 3);
    let statement_bytes = std::fs::read(&args[1]).unwrap();
    let statement = Statement::parse(&statement_bytes).unwrap();
    assert_eq!(statement.arity, Arity::Two);
    let mut public = vec![F::ONE];
    public.extend(statement.projection().unwrap());
    let mut tape = Tape::new(&statement_bytes, &program, None);
    let mut input = Vec::new();
    std::io::stdin()
        .take(8_388_609)
        .read_to_end(&mut input)
        .unwrap();
    assert!(input.len() <= 8_388_608);
    let mut fixture: Value = serde_json::from_slice(&input).unwrap();
    drop(input);
    let expected: String = statement_bytes.iter().map(|x| format!("{x:02x}")).collect();
    assert!(fixture["statement_hex"].as_str() == Some(&expected));
    let witness: Witness = serde_json::from_value(fixture["witness"].take()).unwrap();
    let trace = generate(&air, &statement, &witness).unwrap().matrix.values;
    let mut matrix = Sparse::default();
    let mut assignment = Vec::new();
    let stats = lower(
        &dag,
        &assertions,
        fixed,
        &public[1..],
        &trace,
        Some(&mut matrix),
        &mut assignment,
    );
    assert_eq!(stats["rows"], 614387);
    assert_eq!(stats["private"], 612532);
    assert!(stats["nonzero_residuals"] == 0);
    let prep = begin.elapsed().as_secs_f64();
    let cpu = matrix::cpu_time();
    let t = Instant::now();
    let mut rng = Some(tape::Draw::random());
    let secret = outer::Secret::new(&assignment, rng.as_mut().unwrap());
    let initial = pcs::start(&mut tape, Some(&secret), &mut rng);
    let start_s = t.elapsed().as_secs_f64();
    let claim = outer::execute(&mut tape, &matrix, &assignment, &public, Some(&secret));
    let outer_s = t.elapsed().as_secs_f64();
    drop(secret);
    drop(assignment);
    drop(trace);
    pcs::execute(&mut tape, None, claim, &public, initial, &mut rng);
    let elapsed = t.elapsed().as_secs_f64();
    let cpu_s = matrix::cpu_time() - cpu;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])
        .unwrap();
    file.write_all(&tape.data).unwrap();
    println!(
        "{}",
        json!({"accepted":true,"mode":mode,"proof_bytes":tape.data.len(),"matrix_preparation_s":prep,
                         "initial_commitment_wall_s":start_s,"through_outer_wall_s":outer_s,
                         "post_preparation_wall_s":elapsed,"post_preparation_thread_cpu_s":cpu_s})
    );
}
