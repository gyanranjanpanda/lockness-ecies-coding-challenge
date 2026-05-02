//! EC-based encryption scheme (ECIES variant) for the Lockness mentorship challenge.
//!
//! Implements the Encrypt/Decrypt functions described in the challenge spec using
//! `generic-ec` for curve arithmetic. The scheme is a simplified ECIES — known
//! to be insecure, but that's intentional per the problem statement.

use generic_ec::{Curve, NonZero, Point, SecretScalar};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("ciphertext too short: need {min_len} bytes, got {actual_len}")]
    TooShort { min_len: usize, actual_len: usize },

    #[error("invalid ephemeral point encoding")]
    InvalidPoint,

    #[error("shared secret is the point at infinity")]
    ZeroSharedSecret,
}

/// Expand(B, L) from the spec — repeats `seed` to fill exactly `out.len()` bytes,
/// truncating the last copy as needed.
fn expand(seed: &[u8], out: &mut [u8]) {
    if seed.is_empty() || out.is_empty() {
        return;
    }
    let full = out.len() / seed.len();
    let tail = out.len() % seed.len();
    for i in 0..full {
        out[i * seed.len()..(i + 1) * seed.len()].copy_from_slice(seed);
    }
    out[full * seed.len()..].copy_from_slice(&seed[..tail]);
}

/// H(encode(point)) — SHA-256 of the compressed point encoding.
fn hash_point<E: Curve>(point: &Point<E>) -> [u8; 32] {
    let enc = point.to_bytes(true);
    Sha256::digest(enc.as_bytes()).into()
}

/// Derives the XOR keystream: Expand(H(encode(shared_secret)), msg_len).
fn derive_keystream<E: Curve>(shared_secret: &Point<E>, msg_len: usize) -> Vec<u8> {
    let digest = hash_point(shared_secret);
    let mut ks = vec![0u8; msg_len];
    expand(&digest, &mut ks);
    ks
}

/// Encrypts `message` under public key `pk`.
///
/// Returns `encode(R) || C` where R is the ephemeral point and C is the
/// XOR'd ciphertext.
pub fn encrypt<E: Curve>(
    pk: &Point<E>,
    message: &[u8],
    rng: &mut (impl RngCore + rand::CryptoRng),
) -> Vec<u8> {
    let eph = NonZero::<SecretScalar<E>>::random(rng);
    let r: Point<E> = Point::generator() * &*eph;
    let shared = pk * &*eph;

    let ks = derive_keystream(&shared, message.len());
    let body: Vec<u8> = message.iter().zip(ks.iter()).map(|(m, k)| m ^ k).collect();

    let r_enc = r.to_bytes(true);
    let mut out = Vec::with_capacity(r_enc.as_bytes().len() + body.len());
    out.extend_from_slice(r_enc.as_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decrypts a ciphertext produced by [`encrypt`].
///
/// # Errors
///
/// Returns `DecryptError` if the ciphertext is truncated, contains an invalid
/// point, or yields a degenerate shared secret.
pub fn decrypt<E: Curve>(sk: &SecretScalar<E>, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let pt_len = Point::<E>::serialized_len(true);

    if ciphertext.len() < pt_len {
        return Err(DecryptError::TooShort {
            min_len: pt_len,
            actual_len: ciphertext.len(),
        });
    }

    let (r_bytes, c) = ciphertext.split_at(pt_len);
    let r: Point<E> = Point::from_bytes(r_bytes).map_err(|_| DecryptError::InvalidPoint)?;
    let shared: Point<E> = r * sk;

    if shared.is_zero() {
        return Err(DecryptError::ZeroSharedSecret);
    }

    let ks = derive_keystream(&shared, c.len());
    let plain: Vec<u8> = c.iter().zip(ks.iter()).map(|(ci, k)| ci ^ k).collect();
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::{
        curves::{Ed25519, Secp256k1, Secp384r1},
        Scalar,
    };
    use rand::rngs::OsRng;

    /// Builds (sk, pk) from a small integer. The spec uses 65537 for all test vectors.
    fn keypair_from_u64<E: Curve>(n: u64) -> (SecretScalar<E>, Point<E>) {
        let mut padded = [0u8; 32];
        padded[24..].copy_from_slice(&n.to_be_bytes());
        let scalar = Scalar::<E>::from_be_bytes_mod_order(&padded);
        let sk = SecretScalar::<E>::new(&mut scalar.clone());
        let pk = Point::generator() * &sk;
        (sk, pk)
    }

    fn roundtrip<E: Curve>(msg: &[u8]) {
        let (sk, pk) = keypair_from_u64::<E>(65537);
        let ct = encrypt(&pk, msg, &mut OsRng);
        let got = decrypt(&sk, &ct).expect("decrypt failed");
        assert_eq!(got, msg);
    }

    #[test]
    fn roundtrip_ed25519_empty() {
        roundtrip::<Ed25519>(&[]);
    }

    #[test]
    fn roundtrip_ed25519_short() {
        roundtrip::<Ed25519>(b"hello world");
    }

    #[test]
    fn roundtrip_ed25519_long() {
        roundtrip::<Ed25519>(&[0xabu8; 200]);
    }

    #[test]
    fn roundtrip_secp256k1() {
        roundtrip::<Secp256k1>(b"secp256k1 test message");
    }

    #[test]
    fn roundtrip_secp384r1() {
        roundtrip::<Secp384r1>(b"secp384r1 test message");
    }

    // Spec test vectors (§2.1) — decrypt known ciphertexts with sk=65537.
    fn check_vector<E: Curve>(enc_hex: &str, plain_hex: &str) {
        let (sk, _) = keypair_from_u64::<E>(65537);
        let ct = hex::decode(enc_hex).expect("bad hex");
        let expected = hex::decode(plain_hex).expect("bad hex");
        let got = decrypt::<E>(&sk, &ct).expect("decrypt failed");
        assert_eq!(got, expected);
    }

    // ed25519 vectors
    #[test]
    fn vector_ed25519_1() {
        check_vector::<Ed25519>(
            "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b1602\
             1c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn vector_ed25519_2() {
        check_vector::<Ed25519>(
            "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e5\
             75cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn vector_ed25519_3() {
        check_vector::<Ed25519>(
            "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c\
             6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde\
             433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98\
             067495fdb24b782dac9da5c0eb246c9fb15c00593e",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    // secp256k1 vectors
    #[test]
    fn vector_secp256k1_4() {
        check_vector::<Secp256k1>(
            "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad\
             4940c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395f1",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn vector_secp256k1_5() {
        check_vector::<Secp256k1>(
            "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d0\
             660ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f6",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn vector_secp256k1_6() {
        check_vector::<Secp256k1>(
            "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd75879\
             5f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661\
             a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24\
             e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    // secp384r1 vectors
    #[test]
    fn vector_secp384r1_7() {
        check_vector::<Secp384r1>(
            "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497a\
             fb8156b91c3f5baa12b4d81b5f44f2eb402399e501ed395e834c44d5c85008ef\
             0a8b281240c5d409e4d1b85a586e493332",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn vector_secp384r1_8() {
        check_vector::<Secp384r1>(
            "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa\
             5abb536caf174cc3258bf387f3e72e496c018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn vector_secp384r1_9() {
        check_vector::<Secp384r1>(
            "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a\
             3e79b4895fe83593a0cbe39b4010d96c63d39a10133ef7f68aabfc63253f4537\
             337539a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268\
             337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b\
             7f773eb58706",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    #[test]
    fn decrypt_too_short() {
        let (sk, _) = keypair_from_u64::<Secp256k1>(65537);
        assert!(matches!(
            decrypt::<Secp256k1>(&sk, &[0u8; 5]),
            Err(DecryptError::TooShort { .. })
        ));
    }

    #[test]
    fn decrypt_bad_point() {
        let (sk, _) = keypair_from_u64::<Secp256k1>(65537);
        let mut garbage = vec![0xffu8; 43];
        garbage[0] = 0x02; // valid prefix, but coordinates are garbage
        assert!(matches!(
            decrypt::<Secp256k1>(&sk, &garbage),
            Err(DecryptError::InvalidPoint)
        ));
    }
}
