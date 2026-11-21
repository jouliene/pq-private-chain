//! Fixed public copy wires. Native evaluation receives the node's statement.
use crate::note::Statement;
use anyhow::{Result, ensure};
use plonky2::{
    field::{extension::FieldExtension, goldilocks_field::GoldilocksField as F, types::Field},
    gates::{
        gate::{Gate, GateRef},
        util::StridedConstraintConsumer,
    },
    hash::hash_types::BytesHash,
    iop::{ext_target::ExtensionTarget, generator::WitnessGeneratorRef},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CommonCircuitData,
        vars::{EvaluationTargets, EvaluationVars, EvaluationVarsBase},
    },
    util::serialization::{
        Buffer, DefaultGateSerializer, GateSerializer, IoError, IoResult, Read, Write,
    },
};
use sha3::{Digest, Sha3_384};

pub const WORDS: usize = 49;
const ID: &str = "N7P2.fixed-statement.49.v1";
type E = plonky2::field::extension::quartic::QuarticExtension<F>;
type Common = CommonCircuitData<F, 4>;

#[derive(Debug)]
pub struct StatementGate([F; WORDS]);
impl StatementGate {
    pub fn template() -> Self {
        Self([F::ZERO; WORDS])
    }
}
impl Gate<F, 4> for StatementGate {
    fn id(&self) -> String {
        ID.into()
    }
    fn serialize(&self, _: &mut Vec<u8>, _: &Common) -> IoResult<()> {
        // Only the statement-independent registration has a serialization.
        if self.0 != [F::ZERO; WORDS] {
            return Err(IoError);
        }
        Ok(())
    }
    fn deserialize(_: &mut Buffer, _: &Common) -> IoResult<Self> {
        Ok(Self::template())
    }
    fn eval_unfiltered(&self, vars: EvaluationVars<F, 4>) -> Vec<E> {
        self.0
            .iter()
            .enumerate()
            .map(|(i, &s)| vars.local_wires[i] - <E as FieldExtension<4>>::from_basefield(s))
            .collect()
    }
    fn eval_unfiltered_base_one(
        &self,
        vars: EvaluationVarsBase<F>,
        mut out: StridedConstraintConsumer<F>,
    ) {
        out.many(
            self.0
                .iter()
                .enumerate()
                .map(|(i, &s)| vars.local_wires[i] - s),
        );
    }
    fn eval_unfiltered_circuit(
        &self,
        b: &mut CircuitBuilder<F, 4>,
        vars: EvaluationTargets<4>,
    ) -> Vec<ExtensionTarget<4>> {
        self.0
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                let s = b.constant_extension(<E as FieldExtension<4>>::from_basefield(s));
                b.sub_extension(vars.local_wires[i], s)
            })
            .collect()
    }
    fn generators(&self, _: usize, _: &[F]) -> Vec<WitnessGeneratorRef<F, 4>> {
        vec![]
    }
    fn num_wires(&self) -> usize {
        WORDS
    }
    fn num_constants(&self) -> usize {
        0
    }
    fn degree(&self) -> usize {
        1
    }
    fn num_constraints(&self) -> usize {
        WORDS
    }
}

pub struct Registrations;
impl GateSerializer<F, 4> for Registrations {
    fn read_gate(&self, buf: &mut Buffer, common: &Common) -> IoResult<GateRef<F, 4>> {
        match buf.read_u8()? {
            0 => DefaultGateSerializer.read_gate(buf, common),
            1 => Ok(GateRef::new(StatementGate::deserialize(buf, common)?)),
            _ => Err(IoError),
        }
    }
    fn write_gate(&self, buf: &mut Vec<u8>, gate: &GateRef<F, 4>, common: &Common) -> IoResult<()> {
        if gate.0.as_any().is::<StatementGate>() {
            buf.write_u8(1)?;
            gate.0.serialize(buf, common)
        } else {
            buf.write_u8(0)?;
            DefaultGateSerializer.write_gate(buf, gate, common)
        }
    }
}
pub fn bind(
    common: &mut Common,
    fixed: BytesHash<48>,
    statement: &Statement,
) -> Result<BytesHash<48>> {
    statement.check()?;
    let words: [u64; WORDS] = statement
        .words()
        .try_into()
        .map_err(|_| anyhow::anyhow!("statement width"))?;
    let mut slots = common
        .gates
        .iter_mut()
        .filter(|g| g.0.as_any().is::<StatementGate>());
    let slot = slots
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing fixed statement gate"))?;
    ensure!(slots.next().is_none(), "ambiguous fixed statement gate");
    *slot = GateRef::new(StatementGate(words.map(F::from_canonical_u64)));
    let mut h = Sha3_384::new();
    h.update(b"N7P2/registered-statement/FS/v1\0");
    h.update(fixed.0);
    h.update((WORDS as u32).to_le_bytes());
    for w in words {
        h.update(w.to_le_bytes());
    }
    Ok(BytesHash(h.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::plonk::vars::EvaluationVarsBaseBatch;

    #[test]
    fn all_public_wire_equalities_hold_independently_of_transcript() {
        let statement = std::array::from_fn(|i| F::from_canonical_usize(i * 17 + 1));
        let gate = StatementGate(statement);
        let stock_empty = HashOut::ZERO;
        for changed in (0..WORDS).map(Some).chain([None]) {
            let mut wires = statement;
            let mut expected = [F::ZERO; WORDS];
            if let Some(i) = changed {
                wires[i] += F::ONE;
                expected[i] = F::ONE;
            }
            let base = EvaluationVarsBaseBatch::new(1, &[], &wires, &stock_empty);
            assert_eq!(gate.eval_unfiltered_base_batch(base), expected);
            let extension_wires = wires.map(<E as FieldExtension<4>>::from_basefield);
            let extension = EvaluationVars {
                local_constants: &[],
                local_wires: &extension_wires,
                public_inputs_hash: &stock_empty,
            };
            assert_eq!(
                gate.eval_unfiltered(extension),
                expected.map(<E as FieldExtension<4>>::from_basefield)
            );
        }
    }
}
