//! [`Crypto`] primitives implementation using [`aws_lc_rs`].
//!
//! Requires the `backend-aws-lc` feature.
//!
//! # Supported
//!
//! | KEM | Supported |
//! |:-:|:-:|
//! | `DHKEM_P256_HKDF_SHA256` | ✅ |
//! | `DHKEM_P384_HKDF_SHA384` | ✅ |
//! | `DHKEM_P521_HKDF_SHA512` | ✅ |
//! | `DHKEM_X25519_HKDF_SHA256` | ✅ |
//! | `DHKEM_X448_HKDF_SHA512` | ❌ |
//!
//! | KDF | Supported |
//! |:-:|:-:|
//! | `HKDF_SHA256` | ✅ |
//! | `HKDF_SHA384` | ✅ |
//! | `HKDF_SHA512` | ✅ |
//!
//! | AEAD | Supported |
//! |:-:|:-:|
//! | `AES_128_GCM` | ✅ |
//! | `AES_256_GCM` | ✅ |
//! | `CHACHA20_POLY1305` | ✅ |
//!
//! - ✅: Fully supported
//! - ⚠️: Not supported due to technical reason, the backend itself supports it.
//! - ❌: Not supported

use alloc::vec::Vec;

use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin, EcPrivateKeyBin};

use crate::{
    Crypto, CryptoError, HpkeAead, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeKeyPair, HpkePrivateKey,
    HpkePrivateKeyRef, HpkePublicKey, HpkePublicKeyRef, IkmRef, Okm, Prk, PrkRef, SharedSecret,
};

#[derive(Debug, Clone)]
/// See [module-level](self) documentation.
pub struct HpkeCrypto {
    rng: aws_lc_rs::rand::SystemRandom,
}

impl HpkeCrypto {
    /// Prepare a new `HpkeCrypto` instance.
    ///
    /// # Errors
    ///
    /// This function returns an error if the operating system's random number
    /// generator is not available.
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Self {
            rng: aws_lc_rs::rand::SystemRandom::new(),
        })
    }
}

impl Crypto for HpkeCrypto {
    fn secure_random_fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        use aws_lc_rs::rand::SecureRandom as _;

        self.rng
            .fill(buf)
            .map_err(|_| CryptoError::InsufficientRandomness)
    }

    fn is_kem_supported(&self, alg: &HpkeKemId) -> bool {
        matches!(alg, HpkeKemId::DHKEM_X25519_HKDF_SHA256)
    }

    fn kem_generate_key_pair(&mut self, alg: HpkeKemId) -> Result<HpkeKeyPair, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let sk = aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::X25519)
                    .map_err(|_| CryptoError::Unspecified)?;

                let pk = sk
                    .compute_public_key()
                    .map_err(|_| CryptoError::Unspecified)?;

                let sk = AsBigEndian::<Curve25519SeedBin>::as_be_bytes(&sk)
                    .map_err(|_| CryptoError::Unspecified)?;

                return HpkeKeyPair::new_unchecked(alg, sk.as_ref(), &pk);
            }
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => {
                let sk =
                    aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::ECDH_P256)
                        .map_err(|_| CryptoError::Unspecified)?;

                let pk = sk
                    .compute_public_key()
                    .map_err(|_| CryptoError::Unspecified)?;

                let sk = AsBigEndian::<EcPrivateKeyBin>::as_be_bytes(&sk)
                    .map_err(|_| CryptoError::Unspecified)?;

                HpkeKeyPair::new_unchecked(alg, sk.as_ref(), &pk)
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => {
                let sk =
                    aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::ECDH_P384)
                        .map_err(|_| CryptoError::Unspecified)?;

                let pk = sk
                    .compute_public_key()
                    .map_err(|_| CryptoError::Unspecified)?;

                let sk = AsBigEndian::<EcPrivateKeyBin>::as_be_bytes(&sk)
                    .map_err(|_| CryptoError::Unspecified)?;

                HpkeKeyPair::new_unchecked(alg, sk.as_ref(), &pk)
            }
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => {
                let sk =
                    aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::ECDH_P521)
                        .map_err(|_| CryptoError::Unspecified)?;

                let pk = sk
                    .compute_public_key()
                    .map_err(|_| CryptoError::Unspecified)?;

                let sk = AsBigEndian::<EcPrivateKeyBin>::as_be_bytes(&sk)
                    .map_err(|_| CryptoError::Unspecified)?;

                HpkeKeyPair::new_unchecked(alg, sk.as_ref(), &pk)
            }
            _ => return Err(CryptoError::KemUnsupported),
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
                let prk = aws_lc_rs::hmac::sign(
                    &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::$alg, $salt),
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

                let s_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::$alg, $salt);
                let mut s_ctx = aws_lc_rs::hmac::Context::with_key(&s_key);

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
                use aws_lc_rs::hkdf::KeyType;

                let prk = aws_lc_rs::hkdf::Prk::new_less_safe(aws_lc_rs::hkdf::$alg, $prk);
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
                            aws_lc_rs::hkdf::$alg
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
                aws_lc_rs::aead::LessSafeKey::new(
                    aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::$alg, $key)
                        .expect("Key len must be correct"),
                )
                .seal_in_place_append_tag(
                    aws_lc_rs::aead::Nonce::assume_unique_for_key($nonce),
                    aws_lc_rs::aead::Aad::from($aad),
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

                let plaintext = aws_lc_rs::aead::LessSafeKey::new(
                    aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::$alg, $key)
                        .expect("Key len must be correct"),
                )
                .open_in_place(
                    aws_lc_rs::aead::Nonce::assume_unique_for_key($nonce),
                    aws_lc_rs::aead::Aad::from($aad),
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
        let aws_lc_alg = match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => &aws_lc_rs::agreement::X25519,
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => &aws_lc_rs::agreement::ECDH_P256,
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => &aws_lc_rs::agreement::ECDH_P384,
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => &aws_lc_rs::agreement::ECDH_P521,
            _ => return Err(CryptoError::KemUnsupported),
        };

        let _ = aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_alg, sk)
            .map_err(|_| CryptoError::KemMalformedSkX)?;

        HpkePrivateKey::new(alg, sk)
    }

    fn pk(&self, alg: HpkeKemId, sk: HpkePrivateKeyRef<'_>) -> Result<HpkePublicKey, CryptoError> {
        let aws_lc_alg = match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => &aws_lc_rs::agreement::X25519,
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => &aws_lc_rs::agreement::ECDH_P256,
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => &aws_lc_rs::agreement::ECDH_P384,
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => &aws_lc_rs::agreement::ECDH_P521,
            _ => return Err(CryptoError::KemUnsupported),
        };

        let sk = aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_alg, &sk)
            .map_err(|_| CryptoError::KemMalformedSkX)?;

        let pk = sk
            .compute_public_key()
            .map_err(|_| CryptoError::Unspecified)?;

        HpkePublicKey::new(alg, pk.as_ref())
    }

    fn dh(
        &self,
        alg: HpkeKemId,
        sk_x: HpkePrivateKeyRef<'_>,
        pk_y: HpkePublicKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        let aws_lc_alg = match alg {
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => &aws_lc_rs::agreement::X25519,
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => &aws_lc_rs::agreement::ECDH_P256,
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => &aws_lc_rs::agreement::ECDH_P384,
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => &aws_lc_rs::agreement::ECDH_P521,
            _ => return Err(CryptoError::KemUnsupported),
        };

        let sk_x = aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_alg, &sk_x)
            .map_err(|_| CryptoError::KemMalformedSkX)?;

        let pk_y = aws_lc_rs::agreement::UnparsedPublicKey::new(&aws_lc_alg, pk_y);

        aws_lc_rs::agreement::agree(&sk_x, &pk_y, CryptoError::Unspecified, |shared_secret| {
            Ok(SharedSecret::new(shared_secret))
        })
    }
}

struct Len(usize);

impl aws_lc_rs::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
