// Issuer authentication is a public, separate use of the backed-up wallet seed.
mod issuer_auth {
    use qnero_pqcrypto::{
        hashes::sha256,
        slh_dsa::{SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature},
        traits::{SigningKey, VerifyKey},
    };
    use zeroize::Zeroizing;

    fn issuer_key(wallet_seed: &[u8; 32]) -> SlhDsaSecretKey {
        let domain = b"MNG1/issuer-seed/v1\0";
        let mut input = Zeroizing::new(Vec::with_capacity(domain.len() + 32));
        input.extend_from_slice(domain);
        input.extend_from_slice(wallet_seed);
        let seed = Zeroizing::new(sha256(&input));
        SlhDsaSecretKey::generate_deterministic(seed.as_ref())
    }
    pub fn issuer_public(wallet_seed: &[u8; 32]) -> Vec<u8> {
        issuer_key(wallet_seed).verify_key().to_bytes()
    }
    pub fn issuer_sign(wallet_seed: &[u8; 32], digest: &[u8; 32]) -> Vec<u8> {
        issuer_key(wallet_seed).sign(digest).to_bytes()
    }
    pub fn issuer_verify(body: &[u8]) -> bool {
        if body.len() != 32 + 32 + 17088 {
            return false;
        }
        let Ok(key) = SlhDsaPublicKey::from_bytes(&body[..32]) else {
            return false;
        };
        let Ok(signature) = SlhDsaSignature::from_bytes(&body[64..]) else {
            return false;
        };
        key.verify(&body[32..64], &signature).is_ok()
    }
}
pub use issuer_auth::{issuer_public, issuer_sign, issuer_verify};
