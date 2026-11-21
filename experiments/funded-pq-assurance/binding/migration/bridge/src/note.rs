use crate::{legacy, n7note};
use anyhow::{Result, ensure};
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::Field64};
use serde::{Deserialize, Serialize};

pub const WORDS: usize = 49;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransientCNote {
    pub pk: legacy::Digest,
    pub asset: legacy::Digest,
    pub native: u64,
    pub token: u64,
    pub rho: legacy::Digest,
    pub raw: legacy::Digest,
}

impl TransientCNote {
    pub fn commitment(&self) -> Result<legacy::Digest> {
        legacy::commitment(
            self.pk,
            self.asset,
            self.native,
            self.token,
            self.rho,
            self.raw,
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub transient_c_outputs: [TransientCNote; 2],
    pub successor_outputs: [n7note::Note; 2],
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub bridge_context: [u32; 12],
    pub c_input_nullifiers: [legacy::Digest; 2],
    pub transient_c_outputs: [legacy::Digest; 2],
    pub successor_outputs: [n7note::Digest; 2],
}

impl Statement {
    pub fn words(&self) -> Vec<u64> {
        let mut words = self.bridge_context.map(u64::from).to_vec();
        words.extend(self.c_input_nullifiers.into_iter().flatten());
        words.extend(self.transient_c_outputs.into_iter().flatten());
        words.extend(self.successor_outputs.into_iter().flatten());
        words.extend([0; 7]);
        assert_eq!(words.len(), WORDS);
        words
    }

    pub fn check(&self) -> Result<()> {
        ensure!(
            self.words().into_iter().all(|word| word < F::ORDER),
            "noncanonical statement word"
        );
        ensure!(
            self.c_input_nullifiers[0] != self.c_input_nullifiers[1],
            "duplicate C input nullifier"
        );
        ensure!(
            self.transient_c_outputs[0] != self.transient_c_outputs[1]
                && self.successor_outputs[0] != self.successor_outputs[1],
            "duplicate bridge output"
        );
        ensure!(
            self.transient_c_outputs
                .iter()
                .all(|digest| *digest != [0; 4])
                && self
                    .successor_outputs
                    .iter()
                    .all(|digest| *digest != [0; 7]),
            "zero bridge output"
        );
        Ok(())
    }

    pub fn derive(
        bridge_context: [u32; 12],
        c_input_nullifiers: [legacy::Digest; 2],
        witness: &Witness,
    ) -> Result<Self> {
        let statement = Self {
            bridge_context,
            c_input_nullifiers,
            transient_c_outputs: [
                witness.transient_c_outputs[0].commitment()?,
                witness.transient_c_outputs[1].commitment()?,
            ],
            successor_outputs: [
                witness.successor_outputs[0].commitment()?,
                witness.successor_outputs[1].commitment()?,
            ],
        };
        statement.check()?;
        Ok(statement)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeriveRequest {
    pub bridge_context: [u32; 12],
    pub c_input_nullifiers: [legacy::Digest; 2],
    pub witness: Witness,
}
