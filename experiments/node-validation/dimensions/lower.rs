//! Lower the registered 2x2 AIR to sparse R1CS over the base field.
//! No proof generation. The only witness accepted by the runner is a public fixture.
mod fft;
mod matrix;
use compact_arity_v3::{
    air::PaymentAir,
    statement::{Arity, Statement},
    witness::{Witness, generate},
};
use matrix::Sparse;
use p3_air::{
    AirLayout, BaseEntry, BaseLeaf, SymbolicExpression as Expr, get_symbolic_constraints,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as F;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
enum Op {
    Constant(u64),
    Variable(BaseEntry, usize),
    First,
    Last,
    Transition,
    Add(usize, usize),
    Sub(usize, usize),
    Neg(usize),
    Mul(usize, usize),
}

#[derive(Default)]
struct Dag {
    ops: Vec<Op>,
    ids: HashMap<Op, usize>,
    pointers: HashMap<usize, usize>,
}

impl Dag {
    fn insert(&mut self, expression: &Expr<F>) -> usize {
        let ptr = std::ptr::from_ref(expression) as usize;
        if let Some(&id) = self.pointers.get(&ptr) {
            return id;
        }
        let op = match expression {
            Expr::Leaf(BaseLeaf::Constant(c)) => Op::Constant(c.as_canonical_u64()),
            Expr::Leaf(BaseLeaf::Variable(v)) => Op::Variable(v.entry, v.index),
            Expr::Leaf(BaseLeaf::IsFirstRow) => Op::First,
            Expr::Leaf(BaseLeaf::IsLastRow) => Op::Last,
            Expr::Leaf(BaseLeaf::IsTransition) => Op::Transition,
            Expr::Add { x, y, .. } => Op::Add(self.insert(x), self.insert(y)),
            Expr::Sub { x, y, .. } => Op::Sub(self.insert(x), self.insert(y)),
            Expr::Mul { x, y, .. } => Op::Mul(self.insert(x), self.insert(y)),
            Expr::Neg { x, .. } => Op::Neg(self.insert(x)),
        };
        let index = *self.ids.entry(op).or_insert_with(|| {
            self.ops.push(op);
            self.ops.len() - 1
        });
        self.pointers.insert(ptr, index);
        index
    }
}

// Column 0 is the constant 1. Coefficients reduced to zero are removed.
#[derive(Clone, Default)]
struct Form(BTreeMap<usize, F>);
impl Form {
    fn term(wire: usize, coeff: F) -> Self {
        if coeff == F::ZERO {
            Self::default()
        } else {
            Self(BTreeMap::from([(wire, coeff)]))
        }
    }
    fn wire(wire: usize) -> Self {
        Self::term(wire, F::ONE)
    }
    fn constant(value: F) -> Self {
        Self::term(0, value)
    }
    fn constant_value(&self) -> Option<F> {
        if self.0.is_empty() {
            Some(F::ZERO)
        } else if self.0.len() == 1 {
            self.0.get(&0).copied()
        } else {
            None
        }
    }
    fn scale(&self, coeff: F) -> Self {
        if coeff == F::ZERO {
            return Self::default();
        }
        Self(self.0.iter().map(|(&i, &v)| (i, v * coeff)).collect())
    }
    fn add(&self, other: &Self, sign: F) -> Self {
        let mut result = self.clone();
        for (&index, &value) in &other.0 {
            let c = result.0.entry(index).or_insert(F::ZERO);
            *c += sign * value;
            if *c == F::ZERO {
                result.0.remove(&index);
            }
        }
        result
    }
    fn value(&self, assigned: &[F]) -> F {
        self.0.iter().map(|(&k, &v)| assigned[k] * v).sum()
    }
}

#[derive(Default)]
struct Counts {
    rows: usize,
    nnz: [usize; 3],
    product_rows: usize,
    failed: usize,
}

fn lower(
    dag: &Dag,
    assertions: &[usize],
    fixed: &[F],
    public: &[F],
    trace: &[F],
    mut matrix: Option<&mut Sparse>,
) -> Value {
    let height = 512;
    let width = 579;
    assert_eq!(fixed.len(), height * 114);
    assert_eq!(trace.len(), height * width);
    assert_eq!(public.len(), 49);
    let mut assigned = vec![F::ONE];
    assigned.extend_from_slice(public);
    assigned.extend_from_slice(trace);
    let mut counts = Counts::default();
    for row in 0..height {
        let mut cache: Vec<Form> = Vec::with_capacity(dag.ops.len());
        for &op in &dag.ops {
            let result = match op {
                Op::First => Form::constant(F::from_bool(row == 0)),
                Op::Last => Form::constant(F::from_bool(row == height - 1)),
                Op::Transition => Form::constant(F::from_bool(row != height - 1)),
                Op::Constant(c) => Form::constant(F::from_u64(c)),
                Op::Variable(entry, index) => match entry {
                    BaseEntry::Main { offset } => {
                        Form::wire(1 + public.len() + ((row + offset) % height) * width + index)
                    }
                    BaseEntry::Public => Form::wire(1 + index),
                    BaseEntry::Preprocessed { offset } => {
                        Form::constant(fixed[((row + offset) % height) * 114 + index])
                    }
                    BaseEntry::Periodic => panic!("unexpected periodic column"),
                },
                Op::Add(a, b) => cache[a].add(&cache[b], F::ONE),
                Op::Sub(a, b) => cache[a].add(&cache[b], F::NEG_ONE),
                Op::Neg(a) => cache[a].scale(F::NEG_ONE),
                Op::Mul(a, b) => {
                    let (a, b) = (&cache[a], &cache[b]);
                    if let Some(c) = a.constant_value() {
                        b.scale(c)
                    } else if let Some(c) = b.constant_value() {
                        a.scale(c)
                    } else {
                        let product = a.value(&assigned) * b.value(&assigned);
                        counts.rows += 1;
                        counts.product_rows += 1;
                        counts.nnz[0] += a.0.len();
                        counts.nnz[1] += b.0.len();
                        counts.nnz[2] += 1;
                        let absolute = assigned.len();
                        if let Some(matrix) = matrix.as_deref_mut() {
                            matrix.add([a, b, &Form::wire(absolute)]);
                        }
                        assigned.push(product);
                        Form::wire(absolute)
                    }
                }
            };
            cache.push(result);
        }
        for &index in assertions {
            let x = &cache[index];
            if x.0.is_empty() {
                continue;
            }
            // x * 1 = 0
            if let Some(matrix) = matrix.as_deref_mut() {
                matrix.add([x, &Form::wire(0), &Form::default()]);
            }
            counts.rows += 1;
            counts.nnz[0] += x.0.len();
            counts.nnz[1] += 1;
            counts.failed += usize::from(x.value(&assigned) != F::ZERO);
        }
    }
    json!({"rows":counts.rows,"private":assigned.len()-public.len()-1,
        "public":public.len(),"base_inputs":trace.len(),"nnz_abc":counts.nnz,
        "product_rows":counts.product_rows,"nonzero_residuals":counts.failed})
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--first-row") {
        println!("{}", fft::measure());
        return;
    }
    let air = PaymentAir::new(Arity::Two);
    let fixed = &air.program().preprocessing().values;
    let constraints = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air(&air));
    assert_eq!(constraints.len(), 966);
    let mut dag = Dag::default();
    let assertions: Vec<_> = constraints.iter().map(|expr| dag.insert(expr)).collect();
    let paths: Vec<_> = std::env::args_os().skip(1).collect();
    if !paths.is_empty() {
        // Shape is a function of the registered public program only. No wallet or witness input.
        let begin = std::time::Instant::now();
        let mut matrix = Sparse::default();
        lower(
            &dag,
            &assertions,
            fixed,
            &[F::ZERO; 49],
            &vec![F::ZERO; 512 * 579],
            Some(&mut matrix),
        );
        let prep = begin.elapsed().as_secs_f64();
        let runs: Vec<_> = paths
            .iter()
            .map(|p| matrix.measure(&std::fs::read(p).unwrap()))
            .collect();
        println!("{}", json!({"matrix_prepare_seconds":prep,"runs":runs}));
        return;
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let fixture: Value = serde_json::from_slice(&input).unwrap();
    let hex = fixture["statement_hex"].as_str().unwrap().as_bytes();
    let statement: Vec<u8> = hex
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let statement = Statement::parse(&statement).unwrap();
    let witness: Witness = serde_json::from_value(fixture["witness"].clone()).unwrap();
    let mut trace = generate(&air, &statement, &witness).unwrap().matrix.values;
    let public = statement.projection().unwrap();
    let good = lower(&dag, &assertions, fixed, &public, &trace, None);
    assert_eq!(good["nonzero_residuals"], 0);
    // Break a real permutation trace column while leaving the public instance fixed.
    trace[0] += F::ONE;
    let bad = lower(&dag, &assertions, fixed, &public, &trace, None);
    assert!(bad["nonzero_residuals"].as_u64().unwrap() > 0);
    assert_eq!(good["nnz_abc"], bad["nnz_abc"]);
    println!(
        "{}",
        json!({"symbolic_dag_nodes":dag.ops.len(),"symbolic_assertions":assertions.len(),
        "ordinary":good,"negative_changed_first_trace_word_residuals":bad["nonzero_residuals"]})
    );
}
