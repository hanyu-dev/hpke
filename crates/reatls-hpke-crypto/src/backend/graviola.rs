//! [`Crypto`] primitives implementation using [`graviola`].
//!
//! Requires the `backend-graviola` feature.
//!
//! # Supported
//!
//! | KEM | Supported |
//! |:-:|:-:|
//! | DHKEM_P256_HKDF_SHA256 | ✅ |
//! | DHKEM_P384_HKDF_SHA384 | ✅ |
//! | DHKEM_P521_HKDF_SHA512 | ❌ |
//! | DHKEM_X25519_HKDF_SHA256 | ✅ |
//! | DHKEM_X448_HKDF_SHA512 | ❌ |
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

use crate::{
    Crypto, CryptoError, HpkeAead, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeKeyPair, HpkePrivateKey,
    HpkePrivateKeyRef, HpkePublicKey, HpkePublicKeyRef, IkmRef, Okm, Prk, PrkRef, SharedSecret,
};

#[non_exhaustive]
#[derive(Debug, Clone)]
/// See [module-level](self) documentation.
pub struct HpkeCrypto {}

impl HpkeCrypto {
    /// Create a new `HpkeCrypto` instance.
    ///
    /// Currently, this does nothing and always succeeds.
    pub const fn new() -> Result<Self, CryptoError> {
        Ok(Self {})
    }
}

impl Crypto for HpkeCrypto {
    fn secure_random_fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        graviola::random::fill(buf).map_err(|_| CryptoError::InsufficientRandomness)
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
        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => {
                let sk = graviola::key_agreement::p256::StaticPrivateKey::new_random()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;

                HpkeKeyPair::new_unchecked(alg, sk.as_bytes(), sk.public_key_uncompressed())
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => {
                let sk = graviola::key_agreement::p384::StaticPrivateKey::new_random()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;

                HpkeKeyPair::new_unchecked(alg, sk.as_bytes(), sk.public_key_uncompressed())
            }
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let sk = graviola::key_agreement::x25519::StaticPrivateKey::new_random()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;

                HpkeKeyPair::new_unchecked(alg, sk.as_bytes(), sk.public_key().as_bytes())
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
        // TODO: blocked by https://github.com/ctz/graviola/pull/110
        macro_rules! extract {
            ($hmac_mode:ident, $salt:expr, $ikm:expr) => {{
                let mut hmac =
                    graviola::hashing::hmac::Hmac::<graviola::hashing::$hmac_mode>::new($salt);

                hmac.update($ikm);

                Ok(Prk::new_less_safe(hmac.finish().as_ref()))
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => extract!(Sha256, salt, ikm),
            HpkeKdfId::HKDF_SHA384 => extract!(Sha384, salt, ikm),
            HpkeKdfId::HKDF_SHA512 => extract!(Sha512, salt, ikm),
        }
    }

    fn kdf_extract_concated(
        &self,
        alg: HpkeKdfId,
        salt: &[u8],
        ikms: &[IkmRef<'_>],
    ) -> Result<Prk, CryptoError> {
        // TODO: blocked by https://github.com/ctz/graviola/pull/110
        macro_rules! extract {
            ($hmac_mode:ident, $salt:expr, $ikms:expr) => {{
                let mut hmac =
                    graviola::hashing::hmac::Hmac::<graviola::hashing::$hmac_mode>::new($salt);

                for ikm in $ikms {
                    hmac.update(ikm);
                }

                Ok(Prk::new_less_safe(hmac.finish().as_ref()))
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => extract!(Sha256, salt, ikms),
            HpkeKdfId::HKDF_SHA384 => extract!(Sha384, salt, ikms),
            HpkeKdfId::HKDF_SHA512 => extract!(Sha512, salt, ikms),
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
            ($hmac_mode:ident, $prk:expr, $info:expr, $l:expr) => {{
                let mut okm = Okm::empty();

                hkdf_expand::<graviola::hashing::$hmac_mode>($prk, $info, okm.as_mut_buffer($l))?;

                Ok(okm)
            }};
        }

        match alg {
            HpkeKdfId::HKDF_SHA256 => expand!(Sha256, &prk, infos, l),
            HpkeKdfId::HKDF_SHA384 => expand!(Sha384, &prk, infos, l),
            HpkeKdfId::HKDF_SHA512 => expand!(Sha512, &prk, infos, l),
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
                let mut tag_out = [0u8; 16];

                graviola::aead::$alg::new($key).encrypt($nonce, $aad, $buffer, &mut tag_out);

                $buffer.extend(tag_out);

                Ok(())
            }};
        }

        match crypto_info {
            HpkeAead::Aes128Gcm { key, nonce } => seal!(AesGcm, key, &nonce, aad, buffer),
            HpkeAead::Aes256Gcm { key, nonce } => seal!(AesGcm, key, &nonce, aad, buffer),
            HpkeAead::ChaCha20Poly1305 { key, nonce } => {
                seal!(ChaCha20Poly1305, *key, &nonce, aad, buffer)
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

                let (cipher_inout, tag) = $buffer.split_at_mut(cipher_inout_len);

                graviola::aead::$alg::new($key)
                    .decrypt($nonce, $aad, cipher_inout, tag)
                    .map_err(|_| CryptoError::AeadOpen)?;

                $buffer.truncate(cipher_inout_len);

                Ok(())
            }};
        }

        let aead_id = crypto_info.aead_id();

        match crypto_info {
            HpkeAead::Aes128Gcm { key, nonce } => {
                open!(AesGcm, aead_id, key, &nonce, aad, buffer)
            }
            HpkeAead::Aes256Gcm { key, nonce } => {
                open!(AesGcm, aead_id, key, &nonce, aad, buffer)
            }
            HpkeAead::ChaCha20Poly1305 { key, nonce } => {
                open!(ChaCha20Poly1305, aead_id, *key, &nonce, aad, buffer)
            }
        }
    }

    fn sk(&self, alg: HpkeKemId, sk: &[u8]) -> Result<HpkePrivateKey, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => {
                graviola::key_agreement::p256::StaticPrivateKey::from_bytes(sk)
                    .map(|sk| HpkePrivateKey::new(alg, &sk.as_bytes()).unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => {
                graviola::key_agreement::p384::StaticPrivateKey::from_bytes(sk)
                    .map(|sk| HpkePrivateKey::new(alg, &sk.as_bytes()).unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)
            }
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                graviola::key_agreement::x25519::StaticPrivateKey::try_from_slice(sk)
                    .map(|sk| HpkePrivateKey::new(alg, &sk.as_bytes()).unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)
            }
            HpkeKemId::DHKEM_P521_HKDF_SHA512 | HpkeKemId::DHKEM_X448_HKDF_SHA512 => {
                Err(CryptoError::KemUnsupported)
            }
        }
    }

    fn pk(&self, alg: HpkeKemId, sk: HpkePrivateKeyRef<'_>) -> Result<HpkePublicKey, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => {
                graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&sk)
                    .map(|sk| HpkePublicKey::new(alg, &sk.public_key_uncompressed()).unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => {
                graviola::key_agreement::p384::StaticPrivateKey::from_bytes(&sk)
                    .map(|sk| HpkePublicKey::new(alg, &sk.public_key_uncompressed()).unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)
            }
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                graviola::key_agreement::x25519::StaticPrivateKey::try_from_slice(&sk)
                    .map(|sk| HpkePublicKey::new(alg, &sk.public_key().as_bytes()).unwrap())
                    .map_err(|_| CryptoError::KemMalformedSkX)
            }
            HpkeKemId::DHKEM_P521_HKDF_SHA512 | HpkeKemId::DHKEM_X448_HKDF_SHA512 => {
                Err(CryptoError::KemUnsupported)
            }
        }
    }

    fn dh(
        &self,
        alg: HpkeKemId,
        sk_x: HpkePrivateKeyRef<'_>,
        pk_y: HpkePublicKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        match alg {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => {
                let pk = graviola::key_agreement::p256::PublicKey::from_x962_uncompressed(&pk_y)
                    .map_err(|_| CryptoError::KemMalformedPkX)?;
                let sk = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&sk_x)
                    .map_err(|_| CryptoError::KemMalformedSkX)?;

                sk.diffie_hellman(&pk)
                    .map(|shared_secret| SharedSecret::new(&shared_secret.0))
                    .map_err(Into::into)
                    .map_err(CryptoError::Custom)
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => {
                let pk = graviola::key_agreement::p384::PublicKey::from_x962_uncompressed(&pk_y)
                    .map_err(|_| CryptoError::KemMalformedPkX)?;
                let sk = graviola::key_agreement::p384::StaticPrivateKey::from_bytes(&sk_x)
                    .map_err(|_| CryptoError::KemMalformedSkX)?;

                sk.diffie_hellman(&pk)
                    .map(|shared_secret| SharedSecret::new(&shared_secret.0))
                    .map_err(Into::into)
                    .map_err(CryptoError::Custom)
            }
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                let pk = graviola::key_agreement::x25519::PublicKey::try_from_slice(&pk_y)
                    .map_err(|_| CryptoError::KemMalformedPkX)?;
                let sk = graviola::key_agreement::x25519::StaticPrivateKey::try_from_slice(&sk_x)
                    .map_err(|_| CryptoError::KemMalformedSkX)?;

                sk.diffie_hellman(&pk)
                    .map(|shared_secret| SharedSecret::new(&shared_secret.0))
                    .map_err(Into::into)
                    .map_err(CryptoError::Custom)
            }
            HpkeKemId::DHKEM_P521_HKDF_SHA512 | HpkeKemId::DHKEM_X448_HKDF_SHA512 => {
                Err(CryptoError::KemOpUnsupported)
            }
        }
    }
}

// TODO: blocked by https://github.com/ctz/graviola/pull/110
fn hkdf_expand<H: graviola::hashing::Hash + Clone>(
    prk: &[u8],
    infos: &[&[u8]],
    mut okm: &mut [u8],
) -> Result<(), CryptoError> {
    let l = okm.len();
    let hash_len = H::zeroed_output().as_ref().len();

    if prk.len() < hash_len {
        return Err(CryptoError::KdfExpandInvalidPrkLen);
    }

    if l > 255 * hash_len {
        return Err(CryptoError::KdfExpandInvalidOutputLen);
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "l <= 255 * hash_len <=> l / hash_len <= 255"
    )]
    let n = l.div_ceil(hash_len) as u8;

    let hmac_key = graviola::hashing::hmac::Hmac::<H>::new(prk);

    let mut hmac = hmac_key.clone();

    for i in 1..=n {
        for info in infos {
            hmac.update(info);
        }

        hmac.update([i]);

        let t = hmac.finish();
        let t = t.as_ref();

        let len = core::cmp::min(okm.len(), t.len());
        let (chunk, rest) = okm.split_at_mut(len);
        chunk.copy_from_slice(&t[..len]);

        okm = rest;

        if okm.is_empty() {
            return Ok(());
        }

        hmac = hmac_key.clone();
        hmac.update(t);
    }

    Ok(())
}
