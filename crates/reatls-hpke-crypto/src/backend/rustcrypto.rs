//! [`Crypto`] primitives implementation using crates from RustCrypto.
//!
//! Requires the `backend-rustcrypto` feature.
//!
//! # Supported
//!
//! | KEM | Supported |
//! |:-:|:-:|
//! | DHKEM_P256_HKDF_SHA256 | ✅ |
//! | DHKEM_P384_HKDF_SHA384 | ✅ |
//! | DHKEM_P521_HKDF_SHA512 | ⚠️ |
//! | DHKEM_X25519_HKDF_SHA256 | ✅ |
//! | DHKEM_X448_HKDF_SHA512 | ⚠️ |
//!
//! | KDF | Supported |
//! |:-:|:-:|
//! | HKDF_SHA256 | ✅ |
//! | HKDF_SHA384 | ✅ |
//! | HKDF_SHA512 | ✅ |
//!
//! | AEAD | Supported |
//! |:-:|:-:|
//! | AES_128_GCM | ✅ |
//! | AES_256_GCM | ✅ |
//! | CHACHA20_POLY1305 | ✅ |
//!
//! - ✅: Fully supported
//! - ⚠️: Not supported due to technical reason, the backend itself supports it.
//! - ❌: Not supported

use alloc::vec::Vec;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use crate::{
    Crypto, CryptoError, HpkeAead, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeKeyPair, HpkePrivateKey,
    HpkePrivateKeyRef, HpkePublicKey, HpkePublicKeyRef, IkmRef, Okm, Prk, PrkRef, SharedSecret,
};

#[derive(Debug, Clone)]
/// See [module-level](self) documentation.
pub struct HpkeCrypto {
    rng: ChaCha20Rng,
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
            rng: ChaCha20Rng::try_from_os_rng().map_err(|_| CryptoError::InsufficientRandomness)?,
        })
    }
}

impl Crypto for HpkeCrypto {
    fn secure_random_fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        self.rng.fill_bytes(buf);

        Ok(())
    }

    fn is_kem_supported(&self, alg: &HpkeKemId) -> bool {
        matches!(
            alg,
            HpkeKemId::DHKEM_P256_HKDF_SHA256
                | HpkeKemId::DHKEM_P384_HKDF_SHA384
                | HpkeKemId::DHKEM_X25519_HKDF_SHA256
        )
    }

    fn kem_generate_key_pair(&mut self, alg: HpkeKemId) -> Result<HpkeKeyPair, CryptoError> {
        macro_rules! kem_generate_key_pair {
            ($i:ident) => {{
                use elliptic_curve::sec1::ToEncodedPoint as _;

                let sk = $i::SecretKey::random(&mut self.rng);

                HpkeKeyPair::new_unchecked(
                    alg,
                    sk.to_bytes(),
                    sk.public_key().to_encoded_point(false),
                )
            }};
        }

        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => kem_generate_key_pair!(p256),
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => kem_generate_key_pair!(p384),
            // HpkeKemId::DHKEM_P521_HKDF_SHA512 => kem_generate_key_pair!(p521),
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let sk = x25519_dalek::StaticSecret::random_from_rng(&mut self.rng);

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
            ($hmac_mode:ty, $salt:expr, $ikm:expr) => {{
                let hkdf = hkdf::Hkdf::<$hmac_mode>::extract(Some($salt), $ikm);
                Ok(Prk::new_less_safe(hkdf.0.as_slice()))
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => extract!(sha2::Sha256, salt, &ikm),
            HpkeKdfId::HKDF_SHA384 => extract!(sha2::Sha384, salt, &ikm),
            HpkeKdfId::HKDF_SHA512 => extract!(sha2::Sha512, salt, &ikm),
        }
    }

    fn kdf_expand(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        info: &[u8],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        macro_rules! expand {
            ($hmac_mode:ty, $prk:expr, $info:expr, $l:expr) => {{
                let hkdf = hkdf::Hkdf::<$hmac_mode>::from_prk($prk)
                    .map_err(|_| CryptoError::KdfExpandInvalidPrkLen)?;
                let mut okm = Okm::empty();
                hkdf.expand($info, okm.as_mut_buffer($l))
                    .map_err(|_| CryptoError::KdfExpandInvalidOutputLen)?;
                Ok(okm)
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => expand!(sha2::Sha256, &prk, info, l),
            HpkeKdfId::HKDF_SHA384 => expand!(sha2::Sha384, &prk, info, l),
            HpkeKdfId::HKDF_SHA512 => expand!(sha2::Sha512, &prk, info, l),
        }
    }

    fn kdf_expand_multi_info(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        infos: &[&[u8]],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        macro_rules! expand {
            ($hmac_mode:ty, $prk:expr, $infos:expr, $l:expr) => {{
                let hkdf = hkdf::Hkdf::<$hmac_mode>::from_prk($prk)
                    .map_err(|_| CryptoError::KdfExpandInvalidPrkLen)?;
                let mut okm = Okm::empty();
                hkdf.expand_multi_info($infos, okm.as_mut_buffer($l))
                    .map_err(|_| CryptoError::KdfExpandInvalidOutputLen)?;
                Ok(okm)
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => expand!(sha2::Sha256, &prk, infos, l),
            HpkeKdfId::HKDF_SHA384 => expand!(sha2::Sha384, &prk, infos, l),
            HpkeKdfId::HKDF_SHA512 => expand!(sha2::Sha512, &prk, infos, l),
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
            ($c:ident, $alg:ident, $key:expr, $nonce:expr, $aad:expr, $buffer:expr) => {{
                use aead::{AeadInOut as _, KeyInit};

                let cipher = $c::$alg::new($key);
                cipher
                    .encrypt_in_place($nonce, $aad, $buffer)
                    .map_err(|_| CryptoError::AeadSeal)
            }};
        }

        match crypto_info {
            HpkeAead::Aes128Gcm { key, nonce } => {
                seal!(
                    aes_gcm,
                    Aes128Gcm,
                    &aes_gcm::Key::<aes_gcm::Aes128Gcm>::from(*key),
                    nonce.into(),
                    aad,
                    buffer
                )
            }
            HpkeAead::Aes256Gcm { key, nonce } => {
                seal!(
                    aes_gcm,
                    Aes256Gcm,
                    &aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*key),
                    nonce.into(),
                    aad,
                    buffer
                )
            }
            HpkeAead::ChaCha20Poly1305 { key, nonce } => {
                seal!(
                    chacha20poly1305,
                    ChaCha20Poly1305,
                    &chacha20poly1305::Key::from(*key),
                    nonce.into(),
                    aad,
                    buffer
                )
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
            (
                $c:ident,
                $aead_id:expr,
                $alg:ident,
                $key:expr,
                $nonce:expr,
                $aad:expr,
                $buffer:expr
            ) => {{
                use aead::{AeadInOut as _, KeyInit};

                let _ = $buffer
                    .len()
                    .checked_sub($aead_id.n_tag())
                    .ok_or(CryptoError::AeadInvalidCt)?;

                let cipher = $c::$alg::new($key);
                cipher
                    .decrypt_in_place($nonce, $aad, $buffer)
                    .map_err(|_| CryptoError::AeadOpen)
            }};
        }

        let aead_id = crypto_info.aead_id();

        match crypto_info {
            HpkeAead::Aes128Gcm { key, nonce } => {
                open!(
                    aes_gcm,
                    aead_id,
                    Aes128Gcm,
                    &aes_gcm::Key::<aes_gcm::Aes128Gcm>::from(*key),
                    nonce.into(),
                    aad,
                    buffer
                )
            }
            HpkeAead::Aes256Gcm { key, nonce } => {
                open!(
                    aes_gcm,
                    aead_id,
                    Aes256Gcm,
                    &aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*key),
                    nonce.into(),
                    aad,
                    buffer
                )
            }
            HpkeAead::ChaCha20Poly1305 { key, nonce } => {
                open!(
                    chacha20poly1305,
                    aead_id,
                    ChaCha20Poly1305,
                    &chacha20poly1305::Key::from(*key),
                    nonce.into(),
                    aad,
                    buffer
                )
            }
        }
    }

    fn sk(&self, alg: HpkeKemId, sk: &[u8]) -> Result<HpkePrivateKey, CryptoError> {
        macro_rules! sk {
            ($alg:expr, $i:ident, $sk:expr) => {{
                let sk = $i::SecretKey::from_bytes($sk.try_into().unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)?;

                Ok(HpkePrivateKey::new($alg, sk.to_bytes().as_slice()).unwrap())
            }};
        }

        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => sk!(alg, p256, sk),
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => sk!(alg, p384, sk),
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => sk!(alg, p521, sk),
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let _ = x25519_dalek::StaticSecret::from(
                    TryInto::<[u8; _]>::try_into(sk).map_err(|_| CryptoError::KemMalformedSkX)?,
                );
                Ok(HpkePrivateKey::new(alg, sk).unwrap())
            }
            HpkeKemId::DHKEM_X448_HKDF_SHA512 => Err(CryptoError::KemUnsupported),
        }
    }

    fn pk(&self, alg: HpkeKemId, sk: HpkePrivateKeyRef<'_>) -> Result<HpkePublicKey, CryptoError> {
        macro_rules! pk {
            ($alg:expr, $i:ident, $sk:expr) => {{
                use elliptic_curve::sec1::ToEncodedPoint as _;

                let sk = $i::SecretKey::from_bytes($sk.try_into().unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)?;
                let pk = sk.public_key();

                Ok(HpkePublicKey::new($alg, pk.to_encoded_point(false).as_bytes()).unwrap())
            }};
        }

        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => pk!(alg, p256, sk.as_ref()),
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => pk!(alg, p384, sk.as_ref()),
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => pk!(alg, p521, sk.as_ref()),
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let sk = x25519_dalek::StaticSecret::from(
                    TryInto::<[u8; _]>::try_into(sk.as_ref())
                        .map_err(|_| CryptoError::KemMalformedSkX)?,
                );
                let pk = x25519_dalek::PublicKey::from(&sk);

                Ok(HpkePublicKey::new(alg, pk.as_bytes()).unwrap())
            }
            HpkeKemId::DHKEM_X448_HKDF_SHA512 => Err(CryptoError::KemUnsupported),
        }
    }

    fn dh(
        &self,
        alg: HpkeKemId,
        sk_x: HpkePrivateKeyRef<'_>,
        pk_y: HpkePublicKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        macro_rules! dh {
            ($c:ident, $sk:expr, $pk:expr) => {{
                let sk = $c::SecretKey::from_bytes(
                    $sk.try_into()
                        .map_err(|_| CryptoError::KemMalformedSkX)?,
                )
                .map_err(|_| CryptoError::KemMalformedSkX)?;
                let pk = $c::PublicKey::from_sec1_bytes($pk)
                    .map_err(|_| CryptoError::KemMalformedPkX)?;

                Ok(SharedSecret::new(
                    elliptic_curve::ecdh::diffie_hellman(&sk.to_nonzero_scalar(), pk.as_affine())
                        .raw_secret_bytes(),
                ))
            }};
        }

        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => {
                dh!(p256, sk_x.as_ref(), pk_y.as_ref())
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => {
                dh!(p384, sk_x.as_ref(), pk_y.as_ref())
            }
            HpkeKemId::DHKEM_P521_HKDF_SHA512 => {
                dh!(p521, sk_x.as_ref(), pk_y.as_ref())
            }
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
            HpkeKemId::DHKEM_X448_HKDF_SHA512 => Err(CryptoError::KemOpUnsupported),
        }
    }
}
