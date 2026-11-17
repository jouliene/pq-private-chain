use crate::layout::*;
use p3_field::PrimeCharacteristicRing;
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
    ops: Vec<Option<Op>>,
    preprocessed: RowMajorMatrix<F>,
}
impl Program {
    pub fn new(height: usize) -> Result<Self, String> {
        if !height.is_power_of_two() || height < REAL_ROWS {
            return Err("verifier-owned height below program/power-of-two".into());
        }
        let mut ops = Vec::with_capacity(height);
        for i in 0..2 {
            for role in 1..=4 {
                for block in 0..if role == 1 { 2 } else { 4 } {
                    ops.push(Some(Op {
                        role,
                        item: i,
                        depth: 0,
                        block,
                    }));
                }
            }
            for depth in 0..40 {
                for block in 0..4 {
                    ops.push(Some(Op {
                        role: 5,
                        item: i,
                        depth,
                        block,
                    }));
                }
            }
        }
        for j in 2..4 {
            for block in 0..4 {
                ops.push(Some(Op {
                    role: 2,
                    item: j,
                    depth: 0,
                    block,
                }));
            }
        }
        assert_eq!(ops.len(), REAL_ROWS);
        ops.resize(height, None);
        let mut values = vec![F::ZERO; height * PP_WIDTH];
        for (row, op) in ops.iter().enumerate() {
            let p = &mut values[row * PP_WIDTH..(row + 1) * PP_WIDTH];
            if let Some(o) = op {
                p[PP_NOTE + o.item] = F::ONE;
                if o.item < 2 {
                    p[PP_INPUT + o.item] = F::ONE;
                }
                p[rb(o.role, o.block)] = F::ONE;
                if o.role == 5 {
                    p[PP_NODE + o.item * 40 + o.depth] = F::ONE;
                    p[PP_DEPTH] = F::from_usize(o.depth);
                }
            }
            for (j, at) in [0, 2, 348, 352, 6].iter().enumerate() {
                if row == *at {
                    p[PP_RANGE + j] = F::ONE;
                }
            }
            for (i, at) in [10, 184].iter().enumerate() {
                if row == *at {
                    p[PP_INDEX + i] = F::ONE;
                }
            }
        }
        Ok(Self {
            ops,
            preprocessed: RowMajorMatrix::new(values, PP_WIDTH),
        })
    }
    pub fn height(&self) -> usize {
        self.ops.len()
    }
    pub fn op(&self, row: usize) -> Option<Op> {
        self.ops[row]
    }
    pub fn preprocessing(&self) -> &RowMajorMatrix<F> {
        &self.preprocessed
    }
    pub fn approved_layout_bytes(&self) -> Vec<u8> {
        use p3_field::PrimeField64;
        self.preprocessed
            .values
            .iter()
            .flat_map(|x| x.as_canonical_u64().to_le_bytes())
            .collect()
    }
}
