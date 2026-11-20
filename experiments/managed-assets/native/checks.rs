// All signing material and note openings are ephemeral. Emit only case verdicts.
pub fn check_relation(dir: &Path) -> Result<()> {
    use qnero_circuit::{
        header::{HeaderInputs, DIGEST_LOGS_SIZE},
        merkle::{empty_digest, CommitmentTree},
        witness::{InputNote, OutputNote},
    };
    use qnero_notes::{Note, SpendingKey, MAX_VALUE};
    const BURN: u64 = 1 << 62;
    #[derive(Clone, Copy, PartialEq)]
    enum Input {
        Owned,
        Foreign,
        DummyFunds,
        DummyFirst,
    }

    let prover = WalletProver::new(dir)?;
    let verifier = load(dir)?;
    let owner = SpendingKey::from_bytes(rand::random());
    let other = SpendingKey::from_bytes(rand::random());
    let keys = owner.derived();
    let zero = empty_digest();
    let a = Digest([Felt::new(13); 4]);
    let b = Digest([Felt::new(17); 4]);
    let raw: [Digest; 4] =
        std::array::from_fn(|_| Digest::hash_bytes(&[&rand::random::<[u8; 32]>()]));
    let note_id = |qty| if qty == 0 { zero } else { a };

    let accepts = |input_qty, output_qty, output_id, delta, mode| -> Result<bool> {
        let (real_qty, dummy_qty) = if mode == Input::DummyFunds {
            (0, input_qty)
        } else {
            (input_qty, 0)
        };
        let real_r = typed(note_id(real_qty), real_qty, raw[0]);
        let funded_pk = if mode == Input::Foreign {
            other.pk()
        } else {
            owner.pk()
        };
        let funded = Note::new(funded_pk, 13, raw[2], real_r)?;
        let tree = CommitmentTree::new(&[funded.commitment()], 1)?;
        let note = Note::new(owner.pk(), 13, raw[2], real_r)?;
        let real = InputNote::real(&keys, &note, tree.path(0)?)?;
        let dummy = InputNote::dummy(
            &keys,
            raw[3],
            typed(note_id(dummy_qty), dummy_qty, raw[1]),
            1,
        );
        let mut inputs = [real, dummy];
        let mut openings = [
            (real_qty, raw[0]),
            (dummy_qty, raw[1]),
            (output_qty, raw[2]),
            (0, raw[3]),
        ];
        if mode == Input::DummyFirst {
            inputs.swap(0, 1);
            openings.swap(0, 1);
        }
        let witness = SpendWitness {
            header: HeaderInputs::new(
                zero,
                1,
                [0; 32],
                [0; 32],
                tree.root(),
                &[0; DIGEST_LOGS_SIZE],
            )?,
            depth: 1,
            inputs,
            outputs: [
                OutputNote::new(owner.pk(), 6, typed(output_id, output_qty, raw[2])),
                OutputNote::new(owner.pk(), 4, typed(zero, 0, raw[3])),
            ],
            fee: 3,
            ct_digest: zero,
        };
        witness.validate()?;
        Ok(prover
            .prove(&witness, openings, a, delta)
            .and_then(|p| verifier.verify(p))
            .is_ok())
    };
    use Input::*;
    let cases = [
        ("transfer", 7, 7, a, 0, Owned, true),
        ("maximum_mint", 0, MAX_VALUE, a, MAX_VALUE, Owned, true),
        ("partial_burn", 7, 5, a, BURN | 2, Owned, true),
        (
            "entire_maximum_burn",
            MAX_VALUE,
            0,
            zero,
            BURN | MAX_VALUE,
            Owned,
            true,
        ),
        ("foreign_burn", 7, 5, a, BURN | 2, Foreign, false),
        ("dummy_burn", 7, 5, a, BURN | 2, DummyFunds, false),
        ("overburn", 7, 0, zero, BURN | 8, Owned, false),
        ("zero_burn", 7, 7, a, BURN, Owned, false),
        ("reserved_high_bit", 7, 7, a, 1 << 63, Owned, false),
        ("burn_different_asset", 7, 5, b, BURN | 2, Owned, false),
        ("unbalanced_transfer", 7, 8, a, 0, Owned, false),
        ("token_funded_mint", 7, 8, a, 1, Owned, false),
        ("dummy_first_mint", 0, 1, a, 1, DummyFirst, false),
    ];
    let mut results = Vec::new();
    for (name, input, output, id, delta, mode, expected) in cases {
        let accepted = accepts(input, output, id, delta, mode)?;
        ensure!(
            accepted == expected,
            "unexpected relation verdict for {name}"
        );
        results.push(format!("\"{name}\":{accepted}"));
    }
    println!("{{{}}}", results.join(","));
    Ok(())
}
