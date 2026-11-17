//! Complete fixed-program CP-P2 AIR. Experimental root contract01; no proof/security claim.
use crate::{
    layout::*,
    permutation,
    program::Program,
    statement::{self, MAX, PUBLIC_FIELDS},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks as F;
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone)]
pub struct PaymentAir {
    program: Program,
    permutation: permutation::PermAir,
}
impl PaymentAir {
    pub fn new(height: usize) -> Result<Self, String> {
        Ok(Self {
            program: Program::new(height)?,
            permutation: permutation::air(),
        })
    }
    pub fn program(&self) -> &Program {
        &self.program
    }
}
impl BaseAir<F> for PaymentAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        PP_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(self.program.preprocessing().clone())
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_FIELDS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..WIDTH).collect()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        (0..PP_WIDTH).collect()
    }
    // No degree hint: the allocated compiled control must capture actual symbolic degree.
}

fn sum<E: PrimeCharacteristicRing>(it: impl Iterator<Item = E>) -> E {
    it.fold(E::ZERO, |a, b| a + b)
}
fn active<E: PrimeCharacteristicRing>(p: &[E]) -> E {
    sum(p[PP_ROLE..PP_ROLE + 20].iter().cloned())
}
fn start<E: PrimeCharacteristicRing>(p: &[E]) -> E {
    E::ONE - active(p) + sum((1..=5).map(|role| p[rb(role, 0)].clone()))
}
/// The complete approved message block. Explicit LEFT/RIGHT columns keep transition degree<=3.
pub(crate) fn message<E: Algebra<F>>(r: &[E], p: &[E], v: &[E]) -> [E; 8] {
    let mut result = core::array::from_fn(|_| E::ZERO);
    for role in 1..=5 {
        let mut body = Vec::new();
        match role {
            1 => body.extend_from_slice(&r[WORK_KEY..WORK_KEY + 5]),
            2 => body.extend_from_slice(&r[WORK_NOTE..WORK_NOTE + 20]),
            3 => {
                body.extend_from_slice(&r[WORK_KEY..WORK_KEY + 5]);
                body.extend_from_slice(&r[WORK_ORIGIN..WORK_ORIGIN + 8]);
                body.extend_from_slice(&r[WORK_CM..WORK_CM + 8]);
            }
            4 => {
                body.extend_from_slice(&r[WORK_ORIGIN..WORK_ORIGIN + 8]);
                body.extend_from_slice(&r[WORK_CM..WORK_CM + 8]);
            }
            5 => {
                body.push(p[PP_DEPTH].clone());
                body.extend_from_slice(&r[LEFT..LEFT + 8]);
                body.extend_from_slice(&r[RIGHT..RIGHT + 8]);
            }
            _ => unreachable!(),
        }
        let len = body.len();
        let mut words = vec![E::from_u64(crate::hash::VERSION), E::from_usize(role)];
        words.extend_from_slice(&v[..5]);
        words.push(E::from_usize(len));
        words.extend(body);
        words.push(E::ONE);
        while !words.len().is_multiple_of(8) {
            words.push(E::ZERO);
        }
        for (b, block) in words.chunks_exact(8).enumerate() {
            for j in 0..8 {
                result[j] += p[rb(role, b)].clone() * block[j].clone();
            }
        }
    }
    result
}

impl<AB: AirBuilder<F = F>> Air<AB> for PaymentAir {
    fn eval(&self, b: &mut AB) {
        permutation::eval_prefix(&self.permutation, b);
        let main = b.main();
        let pp = b.preprocessed().clone();
        let l: Vec<AB::Expr> = main
            .current_slice()
            .iter()
            .copied()
            .map(Into::into)
            .collect();
        let n: Vec<AB::Expr> = main.next_slice().iter().copied().map(Into::into).collect();
        let p: Vec<AB::Expr> = pp.current_slice().iter().copied().map(Into::into).collect();
        let pn: Vec<AB::Expr> = pp.next_slice().iter().copied().map(Into::into).collect();
        let v: Vec<AB::Expr> = b.public_values().iter().copied().map(Into::into).collect();
        assert_eq!(
            (l.len(), n.len(), p.len(), pn.len(), v.len()),
            (WIDTH, WIDTH, PP_WIDTH, PP_WIDTH, PUBLIC_FIELDS)
        );
        let one = AB::Expr::ONE;
        let first = b.is_first_row();
        let transition = b.is_transition();
        for j in 0..CONTEXT {
            b.assert_zero(transition.clone() * (n[CTX + j].clone() - l[CTX + j].clone()));
        }
        for j in 0..20 {
            let wanted = sum((0..4).map(|i| p[PP_NOTE + i].clone() * l[note(i, j)].clone()));
            b.assert_eq(l[WORK_NOTE + j].clone(), wanted);
        }
        for j in 0..5 {
            let wanted = sum((0..2).map(|i| p[PP_INPUT + i].clone() * l[key(i, j)].clone()));
            b.assert_eq(l[WORK_KEY + j].clone(), wanted);
        }
        for j in 0..8 {
            b.assert_eq(
                l[WORK_ORIGIN + j].clone(),
                sum((0..2).map(|i| p[PP_INPUT + i].clone() * l[origin(i, j)].clone())),
            );
            let cm_input = sum((0..2).map(|i| p[PP_INPUT + i].clone() * l[cm(i, j)].clone()));
            let cm_output =
                sum((0..2).map(|i| p[PP_NOTE + 2 + i].clone() * v[21 + 8 * i + j].clone()));
            b.assert_eq(l[WORK_CM + j].clone(), cm_input + cm_output);
        }
        for i in 0..2 {
            let mut reconstructed = AB::Expr::ZERO;
            for d in 0..40 {
                let x = l[bit(i, d)].clone();
                b.assert_zero(first.clone() * x.clone() * (x.clone() - one.clone()));
                reconstructed += x * AB::Expr::from_u64(1u64 << d);
            }
            b.assert_zero(first.clone() * (l[index(i)].clone() - reconstructed));
        }
        for i in 0..4 {
            b.assert_zero(first.clone() * l[note(i, 0)].clone());
        }
        b.assert_zero(
            first.clone()
                * (l[note(0, 1)].clone() + l[note(1, 1)].clone()
                    - l[note(2, 1)].clone()
                    - l[note(3, 1)].clone()
                    - v[statement::FEE].clone()),
        );
        b.assert_zero(first.clone() * v[statement::CREDIT].clone());
        b.assert_zero(first.clone() * v[statement::DEBIT].clone());
        let range_active = sum(p[PP_RANGE..PP_RANGE + 5].iter().cloned());
        let wanted = sum((0..4).map(|i| p[PP_RANGE + i].clone() * l[note(i, 1)].clone()))
            + p[PP_RANGE + 4].clone() * v[statement::FEE].clone();
        let mut a = AB::Expr::ZERO;
        let mut d = AB::Expr::ZERO;
        for j in 0..51 {
            let x = l[RANGE_A + j].clone();
            let y = l[RANGE_D + j].clone();
            let power = AB::Expr::from_u64(1u64 << j);
            b.assert_zero(range_active.clone() * x.clone() * (x.clone() - one.clone()));
            b.assert_zero(range_active.clone() * y.clone() * (y.clone() - one.clone()));
            a += x * power.clone();
            d += y * power;
        }
        b.assert_zero(range_active.clone() * (a.clone() - wanted));
        b.assert_zero(range_active * (AB::Expr::from_u64(MAX) - a - d));
        let index_active = p[PP_INDEX].clone() + p[PP_INDEX + 1].clone();
        let mut delta = AB::Expr::ZERO;
        for j in 0..40 {
            let x = l[RANGE_A + j].clone();
            b.assert_zero(index_active.clone() * x.clone() * (x.clone() - one.clone()));
            delta += x * AB::Expr::from_u64(1u64 << j);
        }
        let wanted_delta = sum((0..2).map(|i| {
            p[PP_INDEX + i].clone()
                * (v[statement::COUNT].clone() - one.clone() - l[index(i)].clone())
        }));
        b.assert_zero(wanted_delta - index_active * delta);
        let branch = sum((0..2)
            .flat_map(|i| (0..40).map(move |d| (i, d)))
            .map(|(i, d)| p[PP_NODE + i * 40 + d].clone() * l[bit(i, d)].clone()));
        b.assert_eq(l[BRANCH].clone(), branch);
        let continuing_node = p[rb(5, 0)].clone() + p[rb(5, 1)].clone() + p[rb(5, 2)].clone();
        for j in 0..8 {
            let swap = l[BRANCH].clone() * (l[SIBLING + j].clone() - l[CURRENT + j].clone());
            b.assert_eq(l[LEFT + j].clone(), l[CURRENT + j].clone() + swap.clone());
            b.assert_eq(l[RIGHT + j].clone(), l[SIBLING + j].clone() - swap);
            b.assert_zero(
                transition.clone()
                    * continuing_node.clone()
                    * (n[SIBLING + j].clone() - l[SIBLING + j].clone()),
            );
            // P3's final full-round post-state is the last16 columns of its prefix.
            let out = l[permutation::PERM_COLS - 16 + j].clone();
            let update = p[rb(4, 3)].clone() + p[rb(5, 3)].clone();
            b.assert_zero(
                transition.clone()
                    * (n[CURRENT + j].clone()
                        - (one.clone() - update.clone()) * l[CURRENT + j].clone()
                        - update * out.clone()),
            );
            b.assert_zero(first.clone() * l[CURRENT + j].clone());
            b.assert_zero(p[rb(1, 1)].clone() * (out.clone() - l[WORK_NOTE + 2 + j].clone()));
            b.assert_zero(p[rb(2, 3)].clone() * (out.clone() - l[WORK_CM + j].clone()));
            let nf = sum((0..2).map(|i| p[PP_INPUT + i].clone() * v[5 + 8 * i + j].clone()));
            b.assert_zero(p[rb(3, 3)].clone() * (out.clone() - nf));
            let final_node = p[PP_NODE + 39].clone() + p[PP_NODE + 79].clone();
            b.assert_zero(
                p[rb(5, 3)].clone() * final_node * (out - v[statement::ROOT + j].clone()),
            );
        }
        let msg = message(&l, &p, &v);
        let msg_next = message(&n, &pn, &v);
        let next_start = start(&pn);
        let padding = one.clone() - active(&p);
        for j in 0..16 {
            let add = if j < 8 {
                msg[j].clone()
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero(first.clone() * (l[j].clone() - add));
            let next_add = if j < 8 {
                msg_next[j].clone()
            } else {
                AB::Expr::ZERO
            };
            let out = l[permutation::PERM_COLS - 16 + j].clone();
            b.assert_zero(
                transition.clone()
                    * (n[j].clone() - (one.clone() - next_start.clone()) * out - next_add),
            );
            // Explicitly cover every padding row, including the backend's final row.
            b.assert_zero(padding.clone() * l[j].clone());
        }
    }
}
