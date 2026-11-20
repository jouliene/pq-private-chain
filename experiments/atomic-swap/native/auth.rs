// A fresh private nonce separates each leg authority from all other wallet roles.
mod swap_auth {
    use qnero_pqcrypto::{
        hashes::sha256,
        slh_dsa::{SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature},
        traits::{SigningKey, VerifyKey},
    };
    use zeroize::Zeroizing;

    fn swap_key(wallet_seed: &[u8; 32], nonce: &[u8; 32]) -> SlhDsaSecretKey {
        let domain = b"SWP1/leg-auth-seed/v1\0";
        let mut input = Zeroizing::new(Vec::with_capacity(domain.len() + 64));
        input.extend_from_slice(domain);
        input.extend_from_slice(wallet_seed);
        input.extend_from_slice(nonce);
        let seed = Zeroizing::new(sha256(&input));
        SlhDsaSecretKey::generate_deterministic(seed.as_ref())
    }
    pub fn swap_public(wallet_seed: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
        swap_key(wallet_seed, nonce).verify_key().to_bytes()
    }
    pub fn swap_sign(wallet_seed: &[u8; 32], nonce: &[u8; 32], digest: &[u8; 32]) -> Vec<u8> {
        swap_key(wallet_seed, nonce).sign(digest).to_bytes()
    }
    pub fn swap_verify(body: &[u8]) -> bool {
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
pub use swap_auth::{swap_public, swap_sign, swap_verify};
