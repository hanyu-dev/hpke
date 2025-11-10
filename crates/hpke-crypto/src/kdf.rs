//! Extended KDF functions for HPKE as defined in RFC 9180.
//!
//! Here we implement the `LabeledExtract` and `LabeledExpand` functions.

use crate::{Crypto, CryptoError, HpkeKdfId, IkmRef, Okm, Prk, PrkRef};

const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// Implements the `LabeledExtract` function from RFC 9180.
///
/// ```text
/// def LabeledExtract(salt, label, ikm):
///   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
///   return Extract(salt, labeled_ikm)
/// ```
///
/// See [RFC 9180, Section 4](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) for details.
///
/// # Errors
///
/// See [`CryptoError`] for possible error conditions.
///
/// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
pub fn labeled_extract<C: Crypto>(
    crypto_backend: &C,
    alg: HpkeKdfId,
    suite_id: &[u8],
    salt: &[u8],
    label: &str,
    ikm: IkmRef<'_>,
) -> Result<Prk, CryptoError> {
    crypto_backend.kdf_extract_concated(
        alg,
        salt,
        &[
            IkmRef::from(HPKE_VERSION),
            IkmRef::from(suite_id),
            IkmRef::from(label.as_bytes()),
            ikm,
        ],
    )
}

/// Implements the `LabeledExpand` function from RFC 9180.
///
/// ```text
/// def LabeledExpand(prk, label, info, L):
///  labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
///  return Expand(prk, labeled_info, L)
/// ```
///
/// See [RFC 9180, Section 4](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) for details.
///
/// # Errors
///
/// See [`CryptoError`] for possible error conditions.
///
/// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
pub fn labeled_expand<'a, C, PRK>(
    crypto_backend: &C,
    alg: HpkeKdfId,
    suite_id: &[u8],
    prk: PRK,
    label: &'static str,
    info: &[u8],
    len: usize,
) -> Result<Okm, CryptoError>
where
    C: Crypto,
    PRK: Into<PrkRef<'a>>,
{
    #[allow(
        clippy::cast_possible_truncation,
        reason = "`len` will not exceed u16::MAX in our use cases"
    )]
    crypto_backend.kdf_expand_multi_info(
        alg,
        prk.into(),
        &[
            &(len as u16).to_be_bytes(),
            HPKE_VERSION,
            suite_id,
            label.as_bytes(),
            info,
        ],
        len,
    )
}
