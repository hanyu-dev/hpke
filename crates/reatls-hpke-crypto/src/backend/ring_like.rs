use alloc::vec::Vec;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::{
    Crypto, CryptoError, HpkeAead, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeKeyPair, HpkePrivateKey,
    HpkePrivateKeyRef, HpkePublicKey, HpkePublicKeyRef, IkmRef, Okm, Prk, PrkRef, SharedSecret,
};

#[derive(Debug, Clone)]
/// See [module-level](self) documentation.
pub struct HpkeCrypto {
    rng: ring_like::rand::SystemRandom,
    rng_x25519: ChaCha20Rng,
}

impl HpkeCrypto {
    /// Prepare a new `HpkeCrypto` instance.
    ///
    /// # Errors
    ///
    /// This function returns an error if the operating system's random number
    /// generator is not available.
    pub fn new() -> Result<Self, CryptoError> {
        use ring_like::rand::SystemRandom;

        Ok(Self {
            rng: SystemRandom::new(),
            rng_x25519: ChaCha20Rng::try_from_os_rng()
                .map_err(|_| CryptoError::InsufficientRandomness)?,
        })
    }
}

impl Crypto for HpkeCrypto {
    fn secure_random_fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        use ring_like::rand::SecureRandom as _;

        self.rng
            .fill(buf)
            .map_err(|_| CryptoError::InsufficientRandomness)
    }

    fn is_kem_supported(&self, alg: &HpkeKemId) -> bool {
        matches!(alg, HpkeKemId::DHKEM_X25519_HKDF_SHA256)
    }

    fn kem_generate_key_pair(&mut self, alg: HpkeKemId) -> Result<HpkeKeyPair, CryptoError> {
        // `ring` doesn't have a `StaticSecret`, so we use x25519-dalek here.
        match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let sk = x25519_dalek::StaticSecret::random_from_rng(&mut self.rng_x25519);

                HpkeKeyPair::new_unchecked(alg, &sk, x25519_dalek::PublicKey::from(&sk))
            }
            _ => Err(CryptoError::KemUnsupported),
        }
    }

    fn is_kdf_supported(&self, alg: &HpkeKdfId) -> bool {
        matches!(
            alg,
            HpkeKdfId::HKDF_SHA256 | HpkeKdfId::HKDF_SHA384 | HpkeKdfId::HKDF_SHA512
        )
    }

    fn kdf_extract(
        &self,
        alg: HpkeKdfId,
        salt: &[u8],
        ikm: IkmRef<'_>,
    ) -> Result<Prk, CryptoError> {
        macro_rules! extract {
            ($alg:ident, $salt:expr, $ikm:expr) => {{
                // F**k it, here we implement HKDF by ourselves since ring doesn't expose such
                // API.

                // PRK = HMAC-SHA256(salt, IKM)
                let prk = ring_like::hmac::sign(
                    &ring_like::hmac::Key::new(ring_like::hmac::$alg, $salt),
                    $ikm,
                );

                Ok(Prk::new_less_safe(prk.as_ref()))
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => extract!(HMAC_SHA256, salt, &ikm),
            HpkeKdfId::HKDF_SHA384 => extract!(HMAC_SHA384, salt, &ikm),
            HpkeKdfId::HKDF_SHA512 => extract!(HMAC_SHA512, salt, &ikm),
        }
    }

    fn kdf_extract_concated(
        &self,
        alg: HpkeKdfId,
        salt: &[u8],
        ikms: &[IkmRef<'_>],
    ) -> Result<Prk, CryptoError> {
        macro_rules! extract {
            ($alg:ident, $salt:expr, $ikms:expr) => {{
                // F**k it, here we implement HKDF by ourselves since ring doesn't expose such
                // API.

                let s_key = ring_like::hmac::Key::new(ring_like::hmac::$alg, $salt);
                let mut s_ctx = ring_like::hmac::Context::with_key(&s_key);

                for ikm in $ikms {
                    s_ctx.update(ikm);
                }

                Ok(Prk::new_less_safe(s_ctx.sign().as_ref()))
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => extract!(HMAC_SHA256, salt, ikms),
            HpkeKdfId::HKDF_SHA384 => extract!(HMAC_SHA384, salt, ikms),
            HpkeKdfId::HKDF_SHA512 => extract!(HMAC_SHA512, salt, ikms),
        }
    }

    fn kdf_expand(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        info: &[u8],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        self.kdf_expand_multi_info(alg, prk, &[info], l)
    }

    fn kdf_expand_multi_info(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        infos: &[&[u8]],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        macro_rules! expand {
            ($alg:ident, $prk:expr, $info:expr, $l:expr) => {{
                use ring_like::hkdf::KeyType;

                let prk = ring_like::hkdf::Prk::new_less_safe(ring_like::hkdf::$alg, $prk);
                let okm = prk
                    .expand($info, Len($l))
                    .map_err(|_| CryptoError::KdfExpandInvalidPrkLen)?;

                let mut out = Okm::empty();

                // Only accept buffer with hmac output length.
                // https://docs.rs/ring/latest/src/ring/hkdf.rs.html#194
                okm.fill(out.as_mut_buffer($l))
                    .unwrap_or_else(|_| {
                        unreachable!(
                            "Fails if (and only if) the requested output length ({}, {}) is \
                             larger than 255 times the size of the digest algorithm's output ({})",
                            $l,
                            out.len(),
                            ring_like::hkdf::$alg
                                .hmac_algorithm()
                                .len()
                        )
                    });

                Ok(out)
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => expand!(HKDF_SHA256, &prk, infos, l),
            HpkeKdfId::HKDF_SHA384 => expand!(HKDF_SHA384, &prk, infos, l),
            HpkeKdfId::HKDF_SHA512 => expand!(HKDF_SHA512, &prk, infos, l),
        }
    }

    fn is_aead_supported(&self, alg: &HpkeAeadId) -> bool {
        matches!(
            alg,
            HpkeAeadId::AES_128_GCM
                | HpkeAeadId::AES_256_GCM
                | HpkeAeadId::CHACHA20_POLY1305
                | HpkeAeadId::EXPORT_ONLY
        )
    }

    fn aead_seal_in_place(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        macro_rules! seal {
            ($alg:ident, $key:expr, $nonce:expr, $aad:expr, $buffer:expr) => {{
                ring_like::aead::LessSafeKey::new(
                    ring_like::aead::UnboundKey::new(&ring_like::aead::$alg, $key)
                        .expect("Key len must be correct"),
                )
                .seal_in_place_append_tag(
                    ring_like::aead::Nonce::assume_unique_for_key($nonce),
                    ring_like::aead::Aad::from($aad),
                    $buffer,
                )
                .map_err(|_| CryptoError::AeadSeal)
            }};
        }

        match crypto_info {
            HpkeAead::Aes128Gcm { key, nonce } => seal!(AES_128_GCM, key, *nonce, aad, buffer),
            HpkeAead::Aes256Gcm { key, nonce } => seal!(AES_256_GCM, key, *nonce, aad, buffer),
            HpkeAead::ChaCha20Poly1305 { key, nonce } => {
                seal!(CHACHA20_POLY1305, key, *nonce, aad, buffer)
            }
        }
    }

    fn aead_open_in_place(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        macro_rules! open {
            ($alg:ident, $aead_id:expr, $key:expr, $nonce:expr, $aad:expr, $buffer:expr) => {{
                let cipher_inout_len = $buffer
                    .len()
                    .checked_sub($aead_id.n_tag())
                    .ok_or(CryptoError::AeadInvalidCt)?;

                let plaintext = ring_like::aead::LessSafeKey::new(
                    ring_like::aead::UnboundKey::new(&ring_like::aead::$alg, $key)
                        .expect("Key len must be correct"),
                )
                .open_in_place(
                    ring_like::aead::Nonce::assume_unique_for_key($nonce),
                    ring_like::aead::Aad::from($aad),
                    $buffer,
                )
                .map_err(|_| CryptoError::AeadOpen)?;

                debug_assert_eq!(plaintext.len(), cipher_inout_len);

                $buffer.truncate(cipher_inout_len);

                Ok(())
            }};
        }

        let aead_id = crypto_info.aead_id();

        match crypto_info {
            HpkeAead::Aes128Gcm { key, nonce } => {
                open!(AES_128_GCM, aead_id, key, *nonce, aad, buffer)
            }
            HpkeAead::Aes256Gcm { key, nonce } => {
                open!(AES_256_GCM, aead_id, key, *nonce, aad, buffer)
            }
            HpkeAead::ChaCha20Poly1305 { key, nonce } => {
                open!(CHACHA20_POLY1305, aead_id, key, *nonce, aad, buffer)
            }
        }
    }

    fn sk(&self, alg: HpkeKemId, sk: &[u8]) -> Result<HpkePrivateKey, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let _ = x25519_dalek::StaticSecret::from(
                    TryInto::<[u8; _]>::try_into(sk).map_err(|_| CryptoError::KemMalformedSkX)?,
                );

                HpkePrivateKey::new(alg, sk)
            }
            _ => Err(CryptoError::KemUnsupported),
        }
    }

    fn pk(&self, alg: HpkeKemId, sk: HpkePrivateKeyRef<'_>) -> Result<HpkePublicKey, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let sk = x25519_dalek::StaticSecret::from(
                    TryInto::<[u8; _]>::try_into(sk.as_ref())
                        .map_err(|_| CryptoError::KemMalformedSkX)?,
                );
                let pk = x25519_dalek::PublicKey::from(&sk);

                Ok(HpkePublicKey::new(alg, pk.as_bytes()).unwrap())
            }
            _ => Err(CryptoError::KemUnsupported),
        }
    }

    fn dh(
        &self,
        alg: HpkeKemId,
        sk_x: HpkePrivateKeyRef<'_>,
        pk_y: HpkePublicKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let pk = x25519_dalek::PublicKey::from(
                    TryInto::<[u8; _]>::try_into(pk_y.as_ref())
                        .map_err(|_| CryptoError::KemMalformedPkX)?,
                );
                let sk = x25519_dalek::StaticSecret::from(
                    TryInto::<[u8; _]>::try_into(sk_x.as_ref())
                        .map_err(|_| CryptoError::KemMalformedSkX)?,
                );
                let shared_secret = sk.diffie_hellman(&pk);
                Ok(SharedSecret::new(shared_secret.as_bytes()))
            }
            _ => Err(CryptoError::KemOpUnsupported),
        }
    }
}

struct Len(usize);

impl ring_like::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
