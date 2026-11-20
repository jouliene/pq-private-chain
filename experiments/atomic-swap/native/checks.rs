pub fn check_relation(dir: &Path) -> Result<()> {
    use qnero_circuit::{
        header::{HeaderInputs, DIGEST_LOGS_SIZE},
        merkle::{empty_digest, CommitmentTree},
        witness::{InputNote, OutputNote},
    };
    use qnero_notes::{Note, SpendingKey};
    let zero = empty_digest();
    let owner = SpendingKey::from_bytes(rand::random());
    let keys = owner.derived();
    let auth: [u8; 32] = rand::random();
    let alternative: [u8; 32] = rand::random();
    let a = Digest([Felt::new(21); 4]);
    let b = Digest([Felt::new(45); 4]);
    let raw: [Digest; 4] =
        std::array::from_fn(|_| Digest::hash_bytes(&[&rand::random::<[u8; 32]>()]));
    let note = Note::new(owner.pk(), 20, raw[2], typed(a, 7, raw[0]))?;
    let tree = CommitmentTree::new(&[note.commitment()], 1)?;
    let prover = WalletProver::new(dir)?;
    let verifier = load(dir)?;
    let cases = [
        ("fee_zero", 0, 7, a, &auth, true),
        ("fee_three", 3, 7, a, &auth, true),
        ("wrong_ephemeral_key", 3, 7, a, &alternative, false),
        ("fee_one", 1, 7, a, &auth, false),
        ("token_inflation", 3, 8, a, &auth, false),
        ("different_token", 3, 7, b, &auth, false),
    ];
    let mut results = Vec::new();
    for (name, fee, qty, id, statement_key, expected) in cases {
        let w = SpendWitness {
            header: HeaderInputs::new(
                zero,
                1,
                [0; 32],
                [0; 32],
                tree.root(),
                &[0; DIGEST_LOGS_SIZE],
            )?,
            depth: 1,
            inputs: [
                InputNote::real(&keys, &note, tree.path(0)?)?,
                InputNote::dummy(&keys, raw[3], typed(zero, 0, raw[1]), 1),
            ],
            outputs: [
                OutputNote::new(owner.pk(), 4, typed(id, qty, output_raw(&auth, raw[2]))),
                OutputNote::new(
                    owner.pk(),
                    16 - fee,
                    typed(zero, 0, output_raw(&auth, raw[3])),
                ),
            ],
            fee,
            ct_digest: zero,
        };
        w.validate()?;
        let accepted = prover
            .prove(
                &w,
                [(7, raw[0]), (0, raw[1]), (qty, raw[2]), (0, raw[3])],
                a,
                statement_key,
            )
            .and_then(|p| verifier.verify(p))
            .is_ok();
        ensure!(accepted == expected, "unexpected verdict for {name}");
        results.push(format!("\"{name}\":{accepted}"));
    }
    println!("{{{}}}", results.join(","));
    Ok(())
}
