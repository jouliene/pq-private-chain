// Slot zero is the counterparty receipt and slot one is payer change.
fn pay(
    header: &HeaderInputs,
    choices: &[(MerklePath, Pair)],
    key: &SpendingKey,
    prover: &WalletProver,
    to: &Address,
    native: u64,
    token: u64,
    asset: Digest,
    fee: u64,
    nonce: &[u8; 32],
) -> Result<Vec<u8>> {
    ensure!(
        (native > 0 || token > 0) && native <= MAX_VALUE && token <= MAX_VALUE,
        "offer amounts"
    );
    ensure!(
        matches!(fee, 0 | 3) && (1..=2).contains(&choices.len()),
        "leg shape"
    );
    let native_in: u64 = choices.iter().map(|(_, p)| p.note.value).sum();
    let token_in: u64 = choices.iter().map(|(_, p)| p.token).sum();
    ensure!((token_in == 0) == (asset == empty_digest()), "offer asset");
    ensure!(
        choices.iter().all(|(_, p)| p.token == 0 || p.id == asset),
        "funding asset"
    );
    let change_n = native_in
        .checked_sub(native + fee)
        .context("native funding")?;
    let change_t = token_in.checked_sub(token).context("token funding")?;
    ensure!(
        change_n <= MAX_VALUE && change_t <= MAX_VALUE,
        "change range"
    );
    let auth_key: [u8; 32] = qnero_notes::encrypt::swap_public(key.expose_bytes(), nonce)
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key width"))?;
    let mut rng = rand::rng();
    let mut random = || {
        let mut r = [0; 32];
        rng.fill_bytes(&mut r);
        r
    };
    let mut fresh = || Digest::hash_bytes(&[b"SWP1/fresh/v1", &random()]);
    let keys = key.derived();
    let (path, p) = &choices[0];
    let depth = path.depth();
    let first = InputNote::real(&keys, &p.note, path.clone())?;
    let (second, second_open) = if let Some((path, q)) = choices.get(1) {
        (
            InputNote::real(&keys, &q.note, path.clone())?,
            (q.token, q.raw),
        )
    } else {
        let raw = fresh();
        (
            InputNote::dummy(&keys, fresh(), typed(empty_digest(), 0, raw), depth),
            (0, raw),
        )
    };
    let own = key.address();
    let out = [
        (to, native, token, fresh()),
        (&own, change_n, change_t, fresh()),
    ];
    let note_id = |qty| if qty == 0 { empty_digest() } else { asset };
    let mut w = SpendWitness {
        header: header.clone(),
        depth,
        inputs: [first, second],
        outputs: out.map(|(a, n, t, r)| {
            OutputNote::new(
                a.pk,
                n,
                typed(note_id(t), t, crate::registry::output_raw(&auth_key, r)),
            )
        }),
        fee,
        ct_digest: empty_digest(),
    };
    let mut cts = Vec::with_capacity(2 * CT);
    for (i, (addr, _, quantity, raw)) in out.iter().enumerate() {
        let note = w.output_note(i)?;
        let mut memo = vec![0; 61];
        memo[..32].copy_from_slice(&note_id(*quantity).to_bytes());
        if i == 1 {
            memo[32..].copy_from_slice(&change_marker(key, &note.commitment()));
        }
        let effective = crate::registry::output_raw(&auth_key, *raw);
        let ct =
            encrypt_token_pair(addr, &note, *quantity, effective, &memo, &random())?.to_bytes();
        ensure!(ct.len() == CT, "receipt width");
        cts.extend(ct);
    }
    w.ct_digest = Digest::from_bytes(&ct_digest(&[&cts[..CT], &cts[CT..]]))?;
    let proof = prover.prove(
        &w,
        [
            (p.token, p.raw),
            second_open,
            (token, out[0].3),
            (change_t, out[1].3),
        ],
        asset,
        &auth_key,
    )?;
    Ok(encode(1, &proof, &cts))
}
