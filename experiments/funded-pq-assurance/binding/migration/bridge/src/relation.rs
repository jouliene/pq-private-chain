//! C-output to N7P2-output equality bridge.
use crate::{
    legacy,
    n7note::{self, Note},
    note::{Statement, TransientCNote, Witness},
    public,
    sponge::{self, Builder},
};
use anyhow::{Result, ensure};
use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, types::Field},
    fri::FriReductionStrategy,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_data::CircuitConfig,
};

type TD4 = [Target; 4];
type TD7 = [Target; 7];
type PW = PartialWitness<F>;

struct LegacyTargets {
    pk: TD4,
    asset: TD4,
    native: Target,
    token: Target,
    rho: TD4,
    raw: TD4,
}

struct WideTargets {
    words: [Target; 24],
}

pub struct Targets {
    legacy: [LegacyTargets; 2],
    successor: [WideTargets; 2],
    bridge_context: [Target; 12],
    c_input_nullifiers: [TD4; 2],
}

fn fresh<const N: usize>(builder: &mut Builder) -> [Target; N] {
    std::array::from_fn(|_| builder.add_virtual_target())
}

fn equal<const N: usize>(builder: &mut Builder, left: [Target; N], right: [Target; N]) {
    for (a, b) in left.into_iter().zip(right) {
        builder.connect(a, b);
    }
}

fn set(pw: &mut PW, targets: &[Target], values: &[u64]) -> Result<()> {
    ensure!(targets.len() == values.len(), "assignment shape");
    for (&target, &value) in targets.iter().zip(values) {
        pw.set_target(target, n7note::scalar(value)?)?;
    }
    Ok(())
}

impl LegacyTargets {
    fn new(builder: &mut Builder) -> Self {
        let pk = fresh(builder);
        let asset = fresh(builder);
        let native = builder.add_virtual_target();
        let token = builder.add_virtual_target();
        let rho = fresh(builder);
        let raw = fresh(builder);
        builder.range_check(native, 62);
        builder.range_check(token, 62);
        let zero = builder.zero();
        let mut no_asset = builder._true();
        for &limb in &asset {
            builder.range_check(limb, 63);
            let is_zero = builder.is_equal(limb, zero);
            no_asset = builder.and(no_asset, is_zero);
        }
        let no_token = builder.is_equal(token, zero);
        builder.connect(no_asset.target, no_token.target);
        Self {
            pk,
            asset,
            native,
            token,
            rho,
            raw,
        }
    }

    fn commitment(&self, builder: &mut Builder) -> TD4 {
        let mut typed_words = vec![builder.constant(F::from_canonical_u64(legacy::OPEN))];
        typed_words.extend(self.asset);
        typed_words.push(self.token);
        typed_words.extend(self.raw);
        let typed = legacy::circuit_hash(builder, &typed_words);

        let mut inner_words = vec![builder.constant(F::from_canonical_u64(legacy::NOTE))];
        inner_words.extend(self.pk);
        inner_words.extend(self.rho);
        inner_words.extend(typed);
        let inner = legacy::circuit_hash(builder, &inner_words);

        let mut outer_words = vec![builder.constant(F::from_canonical_u64(legacy::CM))];
        outer_words.extend(inner);
        outer_words.push(self.native);
        legacy::circuit_hash(builder, &outer_words)
    }

    fn assign(&self, pw: &mut PW, note: &TransientCNote) -> Result<()> {
        note.commitment()?;
        set(pw, &self.pk, &note.pk)?;
        set(pw, &self.asset, &note.asset)?;
        set(pw, &[self.native, self.token], &[note.native, note.token])?;
        set(pw, &self.rho, &note.rho)?;
        set(pw, &self.raw, &note.raw)
    }
}

impl WideTargets {
    fn new(builder: &mut Builder) -> Self {
        let words = fresh(builder);
        let zero = builder.zero();
        let mut no_asset = builder._true();
        for &limb in &words[7..15] {
            builder.range_check(limb, 32);
            let is_zero = builder.is_equal(limb, zero);
            no_asset = builder.and(no_asset, is_zero);
        }
        builder.range_check(words[15], 62);
        builder.range_check(words[16], 62);
        let no_token = builder.is_equal(words[16], zero);
        builder.connect(no_asset.target, no_token.target);
        Self { words }
    }

    fn commitment(&self, builder: &mut Builder) -> TD7 {
        sponge::hash(builder, sponge::NOTE, &self.words)
    }

    fn assign(&self, pw: &mut PW, note: &Note) -> Result<()> {
        note.commitment()?;
        set(pw, &self.words, &note.words())
    }
}

fn connect_value(builder: &mut Builder, legacy: &LegacyTargets, successor: &WideTargets) {
    builder.connect(legacy.native, successor.words[15]);
    builder.connect(legacy.token, successor.words[16]);
    let radix = builder.constant(F::from_canonical_u64(1 << 32));
    for (old, pair) in legacy
        .asset
        .iter()
        .zip(successor.words[7..15].chunks_exact(2))
    {
        let low = pair[0];
        let high = pair[1];
        // The historical asset uses a 63-bit field limb.  The successor uses
        // its exact little-endian low-u32/high-u31 decomposition.
        builder.range_check(high, 31);
        let shifted = builder.mul(radix, high);
        let recomposed = builder.add(low, shifted);
        builder.connect(*old, recomposed);
    }
}

pub fn circuit() -> Result<(Builder, Targets)> {
    let mut config = CircuitConfig::standard_recursion_zk_config();
    config.num_wires = 135;
    config.num_routed_wires = 60;
    config.security_bits = 128;
    config.num_challenges = 2;
    config.fri_config.rate_bits = 5;
    config.fri_config.cap_height = 4;
    config.fri_config.num_query_rounds = 32;
    config.fri_config.proof_of_work_bits = 0;
    config.fri_config.reduction_strategy = FriReductionStrategy::ConstantArityBits(2, 3);
    let mut builder = Builder::new(config);
    builder.set_domain_separator(vec![F::from_canonical_u64(0x43324e37)]);

    let bridge_context = fresh(&mut builder);
    for &word in &bridge_context {
        builder.range_check(word, 32);
    }
    let c_input_nullifiers = std::array::from_fn(|_| fresh(&mut builder));
    let legacy = std::array::from_fn(|_| LegacyTargets::new(&mut builder));
    let successor = std::array::from_fn(|_| WideTargets::new(&mut builder));
    for i in 0..2 {
        connect_value(&mut builder, &legacy[i], &successor[i]);
    }

    let legacy_commitments = legacy.each_ref().map(|note| note.commitment(&mut builder));
    let successor_commitments = successor
        .each_ref()
        .map(|note| note.commitment(&mut builder));
    let mut effects = bridge_context.to_vec();
    effects.extend(c_input_nullifiers.into_iter().flatten());
    effects.extend(legacy_commitments.into_iter().flatten());
    effects.extend(successor_commitments.into_iter().flatten());
    effects.extend([builder.zero(); 7]);
    ensure!(effects.len() == public::WORDS, "public effect width");
    let row = builder.add_gate(public::StatementGate::template(), vec![]);
    for (wire, target) in effects.into_iter().enumerate() {
        builder.connect(target, Target::wire(row, wire));
    }

    Ok((
        builder,
        Targets {
            legacy,
            successor,
            bridge_context,
            c_input_nullifiers,
        },
    ))
}

impl Targets {
    pub fn assign(&self, statement: &Statement, witness: &Witness) -> Result<PW> {
        statement.check()?;
        ensure!(
            statement.transient_c_outputs
                == [
                    witness.transient_c_outputs[0].commitment()?,
                    witness.transient_c_outputs[1].commitment()?
                ],
            "transient C output opening"
        );
        ensure!(
            statement.successor_outputs
                == [
                    witness.successor_outputs[0].commitment()?,
                    witness.successor_outputs[1].commitment()?
                ],
            "successor output opening"
        );
        let mut pw = PW::new();
        set(
            &mut pw,
            &self.bridge_context,
            &statement.bridge_context.map(u64::from),
        )?;
        for (targets, values) in self
            .c_input_nullifiers
            .iter()
            .zip(statement.c_input_nullifiers)
        {
            set(&mut pw, targets, &values)?;
        }
        for (targets, note) in self.legacy.iter().zip(&witness.transient_c_outputs) {
            targets.assign(&mut pw, note)?;
        }
        for (targets, note) in self.successor.iter().zip(&witness.successor_outputs) {
            targets.assign(&mut pw, note)?;
        }
        Ok(pw)
    }
}
