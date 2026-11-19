// TKN1 uses the two encrypted integers for amounts; the fixed deployment names both assets.
pub fn encrypt_token_pair(
    address: &crate::Address,
    note: &Note,
    token: u64,
    raw: Digest,
    memo: &[u8],
    random: &[u8; 32],
) -> Result<NoteCiphertext, NotesError> {
    let pt = NotePlaintext::new(
        note.value,
        token,
        note.rho.to_bytes(),
        raw.to_bytes(),
        memo.to_vec(),
    );
    Ok(PqNoteCiphertext::encrypt(
        &address.ek,
        note.pk.to_bytes(),
        CIPHERTEXT_VERSION,
        CRYPTO_SUITE,
        DIVERSIFIER_INDEX,
        &pt,
        random,
    )?)
}

pub fn decrypt_token_pair(
    ivk: &IncomingViewingKey,
    ct: &NoteCiphertext,
) -> Result<(u64, u64, Digest, Digest, Vec<u8>), NotesError> {
    if ct.version != CIPHERTEXT_VERSION || ct.crypto_suite != CRYPTO_SUITE {
        return Err(NotesError::NotOurs);
    }
    let pt = ct
        .decrypt(
            ivk.decapsulation_key(),
            ivk.pk().to_bytes(),
            DIVERSIFIER_INDEX,
        )
        .map_err(|_| NotesError::NotOurs)?;
    Ok((
        pt.value,
        pt.asset_id,
        Digest::from_bytes(&pt.rho)?,
        Digest::from_bytes(&pt.r)?,
        pt.memo,
    ))
}
