//! N7P1 constraints and private witness assignment.
use crate::{
    note::{self, CAPACITY, Note, Statement, Witness},
    sponge::{self, Builder},
};
use anyhow::{Result, ensure};
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::Field};
use plonky2::fri::FriReductionStrategy;
use plonky2::iop::{
    target::Target,
    witness::{PartialWitness, WitnessWrite},
};
use plonky2::plonk::circuit_data::CircuitConfig;

type TD = [Target; 7];
type PW = PartialWitness<F>;
struct NoteTargets {
    words: [Target; 24],
}
struct InputTargets {
    note: NoteTargets,
    sk: TD,
    index: Target,
    path: Vec<TD>,
}
pub struct Targets {
    inputs: [InputTargets; 2],
    outputs: [NoteTargets; 2],
    context: [Target; 12],
    count: Target,
    fee: Target,
}

fn fresh<const N: usize>(b: &mut Builder) -> [Target; N] {
    std::array::from_fn(|_| b.add_virtual_target())
}
fn equal(b: &mut Builder, a: TD, c: TD) {
    for (x, y) in a.into_iter().zip(c) {
        b.connect(x, y);
    }
}
impl NoteTargets {
    fn new(b: &mut Builder) -> Self {
        let words: [Target; 24] = fresh(b);
        let zero = b.zero();
        let mut no_asset = b._true();
        for &limb in &words[7..15] {
            b.range_check(limb, 32);
            let is_zero = b.is_equal(limb, zero);
            no_asset = b.and(no_asset, is_zero);
        }
        b.range_check(words[15], 62);
        b.range_check(words[16], 62);
        let no_token = b.is_equal(words[16], zero);
        b.connect(no_asset.target, no_token.target);
        Self { words }
    }
    fn commit(&self, b: &mut Builder) -> TD {
        sponge::hash(b, sponge::NOTE, &self.words)
    }
    fn assign(&self, pw: &mut PW, n: &Note) -> Result<()> {
        set(pw, &self.words, &n.words())
    }
}
fn set(pw: &mut PW, targets: &[Target], values: &[u64]) -> Result<()> {
    ensure!(targets.len() == values.len(), "assignment shape");
    for (&t, &v) in targets.iter().zip(values) {
        pw.set_target(t, note::scalar(v)?)?;
    }
    Ok(())
}

pub fn circuit(s: &Statement) -> Result<(Builder, Targets)> {
    s.check()?;
    let mut cfg = CircuitConfig::standard_recursion_zk_config();
    cfg.num_wires = 135;
    cfg.num_routed_wires = 60;
    cfg.security_bits = 128;
    cfg.num_challenges = 2;
    cfg.fri_config.rate_bits = 5;
    cfg.fri_config.cap_height = 4;
    cfg.fri_config.num_query_rounds = 32;
    cfg.fri_config.proof_of_work_bits = 0;
    cfg.fri_config.reduction_strategy = FriReductionStrategy::ConstantArityBits(2, 3);
    let mut b = Builder::new(cfg);
    // The full canonical statement also enters the SHA3-384 circuit identity.
    let statement = s.words();
    b.set_domain_separator(
        std::iter::once(F::from_canonical_u64(0x4e375031))
            .chain(statement.iter().copied().map(F::from_canonical_u64))
            .collect(),
    );
    let zero = b.zero();
    let one = b.one();
    let count = b.add_virtual_target();
    let cap = b.constant(F::from_canonical_u64(CAPACITY));
    let room = b.sub(cap, count);
    b.range_check(room, 40);
    let two = b.constant(F::TWO);
    let above_two = b.sub(count, two);
    b.range_check(above_two, 40);
    let last = b.sub(count, one);
    let fee = b.add_virtual_target();
    let three = b.constant(F::from_canonical_u64(3));
    let delta = b.sub(fee, three);
    let fee_rule = b.mul(fee, delta);
    b.connect(fee_rule, zero);
    let context: [Target; 12] = fresh(&mut b);
    for w in context {
        b.range_check(w, 32);
    }
    let mut roots = Vec::new();
    let mut nfs = Vec::new();
    let inputs = std::array::from_fn(|_| {
        let note = NoteTargets::new(&mut b);
        let sk = fresh(&mut b);
        let owner = sponge::hash(&mut b, sponge::OWNER, &sk);
        equal(&mut b, owner, note.words[0..7].try_into().unwrap());
        let total = b.add(note.words[15], note.words[16]);
        let dummy = b.is_equal(total, zero);
        b.connect(dummy.target, zero);
        let index = b.add_virtual_target();
        let bits = b.split_le(index, 40);
        let remaining = b.sub(last, index);
        b.range_check(remaining, 40);
        let cm = note.commit(&mut b);
        let mut preimage = sk.to_vec();
        preimage.push(index);
        preimage.extend(cm);
        nfs.push(sponge::hash(&mut b, sponge::NULLIFIER, &preimage));
        let mut node = cm;
        let mut path = Vec::with_capacity(40);
        for (level, bit) in bits.into_iter().enumerate() {
            let sibling: TD = fresh(&mut b);
            let mut children = Vec::with_capacity(14);
            for i in 0..7 {
                children.push(b.select(bit, sibling[i], node[i]));
            }
            for i in 0..7 {
                children.push(b.select(bit, node[i], sibling[i]));
            }
            node = sponge::hash(&mut b, sponge::PARENT + level as u64, &children);
            path.push(sibling);
        }
        roots.push(node);
        InputTargets {
            note,
            sk,
            index,
            path,
        }
    });
    equal(&mut b, roots[0], roots[1]);
    equal(&mut b, inputs[0].sk, inputs[1].sk);
    let duplicate = b.is_equal(inputs[0].index, inputs[1].index);
    b.connect(duplicate.target, zero);
    let outputs = std::array::from_fn(|_| NoteTargets::new(&mut b));
    let notes = [&inputs[0].note, &inputs[1].note, &outputs[0], &outputs[1]];
    // Every positive token amount has the same nonzero 256-bit asset.
    for i in 0..4 {
        for j in i + 1..4 {
            let neither_zero = b.mul(notes[i].words[16], notes[j].words[16]);
            for k in 7..15 {
                let diff = b.sub(notes[i].words[k], notes[j].words[k]);
                let mismatch = b.mul(diff, neither_zero);
                b.connect(mismatch, zero);
            }
        }
    }
    for idx in [15, 16] {
        let lhs = b.add(notes[0].words[idx], notes[1].words[idx]);
        let mut rhs = b.add(notes[2].words[idx], notes[3].words[idx]);
        if idx == 15 {
            rhs = b.add(rhs, fee);
        }
        b.connect(lhs, rhs);
    }
    let mut effects = roots[0].to_vec();
    effects.extend([count, fee]);
    effects.extend(context);
    effects.extend(nfs.into_iter().flatten());
    for n in &outputs {
        effects.extend(n.commit(&mut b));
    }
    let digest = sponge::hash(&mut b, sponge::STATEMENT, &effects);
    let expected = note::host_hash(sponge::STATEMENT, &statement)?;
    for (t, v) in digest.into_iter().zip(expected) {
        let fixed = b.constant(F::from_canonical_u64(v));
        b.connect(t, fixed);
    }
    Ok((
        b,
        Targets {
            inputs,
            outputs,
            context,
            count,
            fee,
        },
    ))
}
impl Targets {
    pub fn assign(&self, s: &Statement, w: &Witness) -> Result<PW> {
        let mut pw = PW::new();
        set(&mut pw, &self.context, &s.context.map(u64::from))?;
        set(&mut pw, &[self.count, self.fee], &[s.count, s.fee])?;
        for (t, i) in self.inputs.iter().zip(&w.inputs) {
            ensure!(i.path.len() == 40, "path length");
            t.note.assign(&mut pw, &i.note)?;
            set(&mut pw, &t.sk, &i.sk)?;
            set(&mut pw, &[t.index], &[i.index])?;
            for (slot, value) in t.path.iter().zip(&i.path) {
                set(&mut pw, slot, value)?;
            }
        }
        for (t, o) in self.outputs.iter().zip(&w.outputs) {
            t.assign(&mut pw, o)?;
        }
        Ok(pw)
    }
}
