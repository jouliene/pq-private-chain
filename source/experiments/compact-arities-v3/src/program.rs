//! Fixed verifier-owned arity schedules. Derived from context02, with no inactive input.
use crate::{layout::*, statement::Arity};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as F;
use p3_matrix::dense::RowMajorMatrix;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op {
    pub role: usize,
    pub item: usize,
    pub depth: usize,
    pub block: usize,
}
impl Op {
    pub fn blocks(self) -> usize {
        if self.role == 1 { 2 } else { 4 }
    }
    pub fn first(self) -> bool {
        self.block == 0
    }
    pub fn last(self) -> bool {
        self.block + 1 == self.blocks()
    }
}
#[derive(Clone)]
pub struct Program {
    arity: Arity,
    ops: Vec<Option<Op>>,
    preprocessed: RowMajorMatrix<F>,
}
impl Program {
    pub fn new(arity: Arity) -> Self {
        let n = arity.n();
        let real = 174 * n + 8;
        let mut ops = Vec::with_capacity(HEIGHT);
        for item in 0..n {
            for role in 1..=4 {
                for block in 0..if role == 1 { 2 } else { 4 } {
                    ops.push(Some(Op {
                        role,
                        item,
                        depth: 0,
                        block,
                    }));
                }
            }
            for depth in 0..40 {
                for block in 0..4 {
                    ops.push(Some(Op {
                        role: 5,
                        item,
                        depth,
                        block,
                    }));
                }
            }
        }
        // Output selector slots remain2/3; these are outputs, never dummy inputs.
        for item in 2..4 {
            for block in 0..4 {
                ops.push(Some(Op {
                    role: 2,
                    item,
                    depth: 0,
                    block,
                }));
            }
        }
        assert_eq!(ops.len(), real);
        ops.resize(HEIGHT, None);
        let mut values = vec![F::ZERO; HEIGHT * PP_WIDTH];
        for row in 0..HEIGHT {
            let p = &mut values[row * PP_WIDTH..(row + 1) * PP_WIDTH];
            if let Some(o) = ops[row] {
                p[PP_NOTE + o.item] = F::ONE;
                if o.item < 2 {
                    p[PP_INPUT + o.item] = F::ONE;
                }
                p[rb(o.role, o.block)] = F::ONE;
                if o.role == 5 {
                    p[PP_NODE + o.depth] = F::ONE;
                    p[PP_DEPTH] = F::from_usize(o.depth);
                }
            }
            let input_end = (0..n).any(|i| row == 174 * i + 173);
            let output_end = [174 * n + 3, 174 * n + 7].contains(&row);
            if !input_end && !output_end {
                p[PP_KEEP] = F::ONE;
            }
            if (0..n).any(|i| row == 174 * i) {
                p[PP_INPUT_START] = F::ONE;
                p[PP_NOTE_START] = F::ONE;
            }
            if [174 * n, 174 * n + 4].contains(&row) {
                p[PP_NOTE_START] = F::ONE;
                p[PP_ZERO_TAIL] = F::ONE;
            }
            if row == real {
                p[PP_ZERO_ALL] = F::ONE;
            }
            if input_end {
                p[PP_AMOUNT_SIGN] = F::ONE;
            }
            if output_end {
                p[PP_AMOUNT_SIGN] = -F::ONE;
            }
            if row == real - 1 {
                p[PP_FEE] = F::ONE;
            }
            for i in 0..n {
                if row == 174 * i {
                    p[PP_RANGE + i] = F::ONE;
                }
                if row == 174 * i + 10 {
                    p[PP_INDEX + i] = F::ONE;
                }
            }
            for j in 0..2 {
                if row == 174 * n + 4 * j {
                    p[PP_RANGE + 2 + j] = F::ONE;
                }
            }
            if row == if n == 0 { 8 } else { 6 } {
                p[PP_RANGE + 4] = F::ONE;
            }
            if n == 0 {
                if row == 9 {
                    p[PP_CREDIT] = F::ONE;
                }
                if row == 10 {
                    p[PP_CREDIT_POS] = F::ONE;
                }
            }
            let checks = p[PP_RANGE..PP_RANGE + 5].iter().copied().sum::<F>()
                + p[PP_INDEX]
                + p[PP_INDEX + 1]
                + p[PP_CREDIT]
                + p[PP_CREDIT_POS];
            assert!(
                checks == F::ZERO || checks == F::ONE,
                "scratch selectors never overlap"
            );
        }
        Self {
            arity,
            ops,
            preprocessed: RowMajorMatrix::new(values, PP_WIDTH),
        }
    }
    pub fn arity(&self) -> Arity {
        self.arity
    }
    pub fn real_rows(&self) -> usize {
        174 * self.arity.n() + 8
    }
    pub fn height(&self) -> usize {
        HEIGHT
    }
    pub fn op(&self, row: usize) -> Option<Op> {
        self.ops[row]
    }
    pub fn preprocessing(&self) -> &RowMajorMatrix<F> {
        &self.preprocessed
    }
    pub fn approved_layout_bytes(&self) -> Vec<u8> {
        self.preprocessed
            .values
            .iter()
            .flat_map(|v| v.as_canonical_u64().to_le_bytes())
            .collect()
    }
    /// A frontend identity preimage, not a producer-selected program or final proof identity.
    pub fn identity_material(&self) -> Vec<u8> {
        let mut b = b"PQPC/CP-P2-03/TRUSTED-PROGRAM\0".to_vec();
        b.push(self.arity.n() as u8);
        b.extend((HEIGHT as u64).to_le_bytes());
        b.extend(self.approved_layout_bytes());
        b
    }
}
