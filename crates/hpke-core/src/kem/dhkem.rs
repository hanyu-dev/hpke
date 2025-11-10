//! Implementation of DH-Based KEM functions for HPKE as defined in [RFC 9180,
//! section 4.1].
//!
//! [RFC 9180, section 4.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1

use hpke_crypto::{
    Crypto, CryptoError, EncapsulatedSecret, EncapsulatedSecretRef, HpkeKemId, HpkePrivateKey,
    HpkePrivateKeyRef, HpkePublicKey, HpkePublicKeyRef, IkmRef, SharedSecret,
};
use smallvec::SmallVec;

use crate::error::Error;
use crate::kdf;

/// `GenerateKeyPair()`: Randomized algorithm to generate a key pair (skX, pkX).
///
/// Note that `GenerateKeyPair` can be implemented as
/// `DeriveKeyPair(random(Nsk))`. See [RFC 9180, Section 4] for details.
pub fn generate_key_pair<C: Crypto>(
    crypto_backend: &mut C,
    alg: HpkeKemId,
) -> Result<(HpkePrivateKey, HpkePublicKey), Error> {
    let mut ikm: SmallVec<_, 56> = SmallVec::new();
    let ikm = {
        // `ikm` SHOULD have at least `Nsk` bytes of entropy.
        ikm.resize(alg.n_sk(), 0);
        crypto_backend.secure_random_fill(&mut ikm)?;

        IkmRef::from(&ikm)
    };

    derive_key_pair(crypto_backend, alg, ikm)
}

/// `DeriveKeyPair(ikm)`: Deterministic algorithm to derive a key pair(skX, pkX)
/// from the byte string `ikm`, where `ikm` SHOULD have at least `Nsk` bytes of
/// entropy (see [RFC 9180, Section 7.1.3] for discussion).
///
/// 7.1.3 DeriveKeyPair
///
/// For P-256, P-384, and P-521, the `DeriveKeyPair()` function of the KEM
/// performs rejection sampling over field elements:
///
/// ```no_run
/// def DeriveKeyPair(ikm):
///   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
///   sk = 0
///   counter = 0
///   while sk == 0 or sk >= order:
///     if counter > 255:
///       raise DeriveKeyPairError
///     bytes = LabeledExpand(dkp_prk, "candidate",
///                           I2OSP(counter, 1), Nsk)
///     bytes[0] = bytes[0] & bitmask
///     sk = OS2IP(bytes)
///     counter = counter + 1
///   return (sk, pk(sk))
/// ```
///
/// For X25519 and X448, the `DeriveKeyPair()` function applies a KDF to the
/// input:
///
/// ```no_run
/// def DeriveKeyPair(ikm):
///   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
///   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
///   return (sk, pk(sk))
/// ```
///
/// See [RFC 9180, Section 4] for details.
///
/// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
/// [RFC 9180, Section 7.1.3]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3
pub fn derive_key_pair<C: Crypto>(
    crypto_backend: &mut C,
    alg: HpkeKemId,
    ikm: IkmRef<'_>,
) -> Result<(HpkePrivateKey, HpkePublicKey), Error> {
    let dkp_prk = kdf::labeled_extract(
        crypto_backend,
        alg.kdf_id(),
        &alg.suite_id(),
        &[],
        "dkp_prk",
        ikm,
    )?;

    let sk = match alg {
        HpkeKemId::DHKEM_X25519_HKDF_SHA256 | HpkeKemId::DHKEM_X448_HKDF_SHA512 => {
            let sk = kdf::labeled_expand(
                crypto_backend,
                alg.kdf_id(),
                &alg.suite_id(),
                &dkp_prk,
                "sk",
                &[],
                alg.n_sk(),
            )?;

            crypto_backend
                .sk(alg, &sk)
                .map_err(|_| Error::CryptoError(CryptoError::KemDeriveKeyPair))?
        }
        HpkeKemId::DHKEM_P256_HKDF_SHA256
        | HpkeKemId::DHKEM_P384_HKDF_SHA384
        | HpkeKemId::DHKEM_P521_HKDF_SHA512 => {
            let mut counter = 0u8;

            loop {
                let candidate = kdf::labeled_expand(
                    crypto_backend,
                    alg.kdf_id(),
                    &alg.suite_id(),
                    &dkp_prk,
                    "candidate",
                    &counter.to_be_bytes(),
                    alg.n_sk(),
                );

                if let Ok(sk) = &candidate {
                    // let the crypto backend validate the private key
                    match crypto_backend.sk(alg, sk) {
                        Ok(sk) => break sk,
                        Err(e) if matches!(e, CryptoError::KemMalformedSkX) => {}
                        Err(_) => return Err(Error::CryptoError(CryptoError::KemDeriveKeyPair)),
                    }
                }

                counter = counter
                    .checked_add_signed(1)
                    .ok_or(Error::CryptoError(CryptoError::KemDeriveKeyPair))?;
            }
        }
        _ => {
            return Err(Error::CryptoError(CryptoError::KemUnsupported));
        }
    };

    let pk = crypto_backend.pk(alg, (&sk).into())?;

    Ok((sk, pk))
}

/// ```no_run
/// def Encap(pkR):
///   skE, pkE = GenerateKeyPair()
///   dh = DH(skE, pkR)
///   enc = SerializePublicKey(pkE)
///   pkRm = SerializePublicKey(pkR)
///   kem_context = concat(enc, pkRm)
///   shared_secret = ExtractAndExpand(dh, kem_context)
///   return shared_secret, enc
/// ```
pub fn encap<C: Crypto>(
    crypto_backend: &mut C,
    alg: HpkeKemId,
    pk_r: HpkePublicKeyRef<'_>,
) -> Result<(SharedSecret, EncapsulatedSecret), Error> {
    // skE, pkE = GenerateKeyPair() = DeriveKeyPair(random(Nsk)).
    let (sk_e, pk_e) = generate_key_pair(crypto_backend, alg)?;

    // dh = DH(skE, pkR)
    let dh = crypto_backend.dh(alg, (&sk_e).into(), pk_r)?;

    // enc = SerializePublicKey(pkE), though here pkE is already serialized
    let enc = EncapsulatedSecret::new_from_pk_e(pk_e);

    // pkRm = SerializePublicKey(pkR), though here pkR is already serialized
    let pk_rm = EncapsulatedSecret::new(&pk_r);

    // kem_context = concat(enc, pkRm)
    let kem_context = [&*enc, &*pk_rm].concat();

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret =
        extract_and_expand(crypto_backend, alg, &alg.suite_id(), &dh, &kem_context)?;

    Ok((shared_secret, enc))
}

/// ```no_run
/// def Decap(enc, skR):
///   pkE = DeserializePublicKey(enc)
///   dh = DH(skR, pkE)
///
///   pkRm = SerializePublicKey(pk(skR))
///   kem_context = concat(enc, pkRm)
///
///   shared_secret = ExtractAndExpand(dh, kem_context)
///   return shared_secret
/// ```
pub(crate) fn decap<C: Crypto>(
    crypto_backend: &mut C,
    alg: HpkeKemId,
    enc: EncapsulatedSecretRef<'_>,
    sk_r: HpkePrivateKeyRef<'_>,
) -> Result<SharedSecret, Error> {
    // pkE = DeserializePublicKey(enc), here we assume enc is already deserialized
    let pk_e = HpkePublicKeyRef::from(&enc);

    // dh = DH(skR, pkE)
    let dh = crypto_backend.dh(alg, sk_r, pk_e)?;

    // pkRm = SerializePublicKey(pk(skR)), though here pk(skR) is already serialized
    let pk_rm = crypto_backend.pk(alg, sk_r)?;

    // kem_context = concat(enc, pkRm)
    let kem_context = [&*enc, &pk_rm].concat();

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret =
        extract_and_expand(crypto_backend, alg, &alg.suite_id(), &dh, &kem_context)?;

    Ok(shared_secret)
}

/// ```no_run
/// def AuthEncap(pkR, skS):
///   skE, pkE = GenerateKeyPair()
///   dh = concat(DH(skE, pkR), DH(skS, pkR))
///   enc = SerializePublicKey(pkE)
//
///   pkRm = SerializePublicKey(pkR)
///   pkSm = SerializePublicKey(pk(skS))
///   kem_context = concat(enc, pkRm, pkSm)
//
///   shared_secret = ExtractAndExpand(dh, kem_context)
///   return shared_secret, enc
/// ```
pub fn auth_encap<C: Crypto>(
    crypto_backend: &mut C,
    alg: HpkeKemId,
    pk_r: HpkePublicKeyRef<'_>,
    sk_s: HpkePrivateKeyRef<'_>,
) -> Result<(SharedSecret, EncapsulatedSecret), Error> {
    // skE, pkE = GenerateKeyPair() = DeriveKeyPair(random(Nsk)).
    let (sk_e, pk_e) = generate_key_pair(crypto_backend, alg)?;

    // dh = concat(DH(skE, pkR), DH(skS, pkR))
    let dh = [
        &*crypto_backend.dh(alg, (&sk_e).into(), pk_r)?,
        &*crypto_backend.dh(alg, sk_s, pk_r)?,
    ]
    .concat();

    // enc = SerializePublicKey(pkE), though here pkE is already serialized
    let enc = EncapsulatedSecret::new_from_pk_e(pk_e);

    // pkRm = SerializePublicKey(pkR), though here pkR is already serialized
    let pk_rm = EncapsulatedSecret::new(&pk_r);

    // pkSm = SerializePublicKey(pk(skS)), though here pk(skS) is already serialized
    let pk_sm = EncapsulatedSecret::new(&crypto_backend.pk(alg, sk_s)?);

    // kem_context = concat(enc, pkRm, pkSm)
    let kem_context = [&*enc, &*pk_rm, &*pk_sm].concat();

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret =
        extract_and_expand(crypto_backend, alg, &alg.suite_id(), &dh, &kem_context)?;

    Ok((shared_secret, enc))
}

/// ```no_run
/// def AuthDecap(enc, skR, pkS):
///   pkE = DeserializePublicKey(enc)
///   dh = concat(DH(skR, pkE), DH(skR, pkS))
///
///   pkRm = SerializePublicKey(pk(skR))
///   pkSm = SerializePublicKey(pkS)
///   kem_context = concat(enc, pkRm, pkSm)
///
///   shared_secret = ExtractAndExpand(dh, kem_context)
///   return shared_secret
/// ```
pub fn auth_decap<C: Crypto>(
    crypto_backend: &mut C,
    alg: HpkeKemId,
    enc: EncapsulatedSecretRef<'_>,
    sk_r: HpkePrivateKeyRef<'_>,
    pk_s: HpkePublicKeyRef<'_>,
) -> Result<SharedSecret, Error> {
    // pkE = DeserializePublicKey(enc), here we assume enc is already deserialized
    let pk_e = HpkePublicKeyRef::from(&enc);

    // dh = concat(DH(skR, pkE), DH(skR, pkS))
    let dh = [
        &*crypto_backend.dh(alg, sk_r, pk_e)?,
        &*crypto_backend.dh(alg, sk_r, pk_s)?,
    ]
    .concat();

    // pkRm = SerializePublicKey(pk(skR)), though here pk(skR) is already
    // serialized
    let pk_rm = crypto_backend.pk(alg, sk_r)?;

    // pkSm = SerializePublicKey(pkS), though here pkS is already serialized
    let pk_sm = EncapsulatedSecret::new(&pk_s);

    // kem_context = concat(enc, pkRm, pkSm)
    let kem_context = [&*enc, &pk_rm, &*pk_sm].concat();

    // shared_secret = ExtractAndExpand(dh, kem_context)
    let shared_secret =
        extract_and_expand(crypto_backend, alg, &alg.suite_id(), &dh, &kem_context)?;

    Ok(shared_secret)
}

/// ```no_run
/// def ExtractAndExpand(dh, kem_context):
///   eae_prk = LabeledExtract("", "eae_prk", dh)
///   shared_secret = LabeledExpand(eae_prk, "shared_secret",
///                                 kem_context, Nsecret)
///   return shared_secret
/// ```
fn extract_and_expand<C: Crypto>(
    crypto_backend: &C,
    alg: HpkeKemId,
    suite_id: &[u8],
    dh: &[u8],
    kem_context: &[u8],
) -> Result<SharedSecret, Error> {
    let prk = kdf::labeled_extract(
        crypto_backend,
        alg.kdf_id(),
        &[],
        suite_id,
        "eae_prk",
        IkmRef::from(dh),
    )?;

    let okm = kdf::labeled_expand(
        crypto_backend,
        alg.kdf_id(),
        suite_id,
        &prk,
        "shared_secret",
        kem_context,
        alg.n_secret(),
    )?;

    Ok(SharedSecret::from_okm(okm))
}
