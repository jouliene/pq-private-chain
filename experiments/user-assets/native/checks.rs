// This local relation test uses ephemeral openings and prints only case outcomes.
pub fn check_relation(dir: &Path) -> Result<()> {
    use qnero_circuit::{
        header::{HeaderInputs, DIGEST_LOGS_SIZE},
        merkle::{empty_digest, CommitmentTree},
        witness::{InputNote, OutputNote},
    };
    use qnero_notes::{Note, SpendingKey, MAX_VALUE};
    let prover = WalletProver::new(dir)?;
    let vk = load(dir)?;
    let key = SpendingKey::from_bytes(rand::random());
    let keys = key.derived();
    let zero = empty_digest();
    let a = Digest([Felt::new(13); 4]);
    let b = Digest([Felt::new(17); 4]);
    let raw: [Digest; 4] = std::array::from_fn(|_| Digest::hash_bytes(&[&rand::random::<[u8; 32]>()]));
    let prove_case = |input_qty, output_qty, output_id, supply, first_dummy: bool| -> Result<bool> {
        let input_id = if input_qty == 0 { zero } else { a };
        let note = Note::new(key.pk(), 13, raw[2], typed(input_id, input_qty, raw[0]))?;
        let tree = CommitmentTree::new(&[note.commitment()], 1)?;
        let real = InputNote::real(&keys, &note, tree.path(0)?)?;
        let dummy = InputNote::dummy(&keys, raw[3], typed(zero, 0, raw[1]), 1);
        let mut inputs = [real, dummy];
        let mut opening = [(input_qty, raw[0]), (0, raw[1]), (output_qty, raw[2]), (0, raw[3])];
        if first_dummy {
            inputs.swap(0, 1);
            opening.swap(0, 1);
        }
        let w = SpendWitness {
            header: HeaderInputs::new(zero, 1, [0; 32], [0; 32], tree.root(), &[0; DIGEST_LOGS_SIZE])?,
            depth: 1,
            inputs,
            outputs: [
                OutputNote::new(key.pk(), 6, typed(output_id, output_qty, raw[2])),
                OutputNote::new(key.pk(), 4, typed(zero, 0, raw[3])),
            ],
            fee: 3,
            ct_digest: zero,
        };
        w.validate()?;
        // No wallet payment selection or funding checks. A blinded prover can
        // reject an inconsistent assignment or return a proof the verifier rejects.
        Ok(prover.prove(&w, opening, a, supply).and_then(|p| vk.verify(p)).is_ok())
    };
    ensure!(prove_case(7, 7, a, 0, false)?, "valid transfer control");
    ensure!(prove_case(0, MAX_VALUE, a, MAX_VALUE, false)?, "valid max supply");
    ensure!(!prove_case(7, 7, b, 0, false)?, "mixed output ID accepted");
    ensure!(!prove_case(7, 8, a, 0, false)?, "unbalanced transfer accepted");
    ensure!(!prove_case(7, 8, a, 1, false)?, "token-bearing issuer accepted");
    ensure!(!prove_case(0, 1, a, 1, true)?, "dummy first issuer accepted");
    ensure!(!prove_case(0, MAX_VALUE+1, a, MAX_VALUE+1, false)?, "unbounded issuance accepted");
    println!("{{\"valid_transfer\":true,\"max_issue\":true,\"mixed_id_rejected\":true,\"unbalanced_rejected\":true,\"issuer_token_input_rejected\":true,\"dummy_issuer_rejected\":true,\"oversize_rejected\":true}}");
    Ok(())
}
