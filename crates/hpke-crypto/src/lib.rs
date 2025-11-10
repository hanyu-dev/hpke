#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "_backend")]
pub mod backend;
pub mod kdf;

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::DerefMut;

use smallvec::SmallVec;
use subtle::ConstantTimeEq;

/// Cryptographic primitives for HPKE.
pub trait Crypto: fmt::Debug + Send + Sync {
    /// Fill the provided buffer with secure random bytes.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    fn secure_random_fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError>;

    /// Helper function to check if a KEM algorithm is supported by this
    /// backend.
    fn is_kem_supported(&self, alg: &HpkeKemId) -> bool;

    /// `GenerateKeyPair()`: Randomized algorithm to generate a key pair (skX,
    /// pkX).
    ///
    /// For DH-Based KEMs, this is the generation of a private key skX and
    /// computation of the corresponding public key pkX.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn kem_generate_key_pair(&mut self, alg: HpkeKemId) -> Result<HpkeKeyPair, CryptoError>;

    /// `Encap(pkR)`: Randomized algorithm to generate an ephemeral,
    /// fixed-length symmetric key (the KEM shared secret) and a
    /// fixed-length encapsulation of that key that can be decapsulated by
    /// the holder of the private key corresponding to `pkR`.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// Currently, we only support DHKEM and `Encap(pkR)` is implemented in
    /// the core library.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn kem_encap(
        &self,
        _alg: HpkeKemId,
        _pk_r: HpkePublicKeyRef<'_>,
    ) -> Result<(SharedSecret, EncapsulatedSecret), CryptoError> {
        Err(CryptoError::KemOpUnsupported)
    }

    /// `Decap(enc, skR)`: Deterministic algorithm using the private key `skR`
    /// to recover the ephemeral symmetric key (the KEM shared secret) from
    /// its encapsulated representation `enc`.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// Currently, we only support DHKEM and `Decap(enc, skR)` is implemented in
    /// the core library.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn kem_decap(
        &self,
        _alg: HpkeKemId,
        _enc: EncapsulatedSecret,
        _sk_r: HpkePrivateKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        Err(CryptoError::KemOpUnsupported)
    }

    /// Helper function to check if a KDF algorithm is supported by this
    /// backend.
    fn is_kdf_supported(&self, alg: &HpkeKdfId) -> bool;

    /// `Extract(salt, ikm)`: Extract a pseudorandom key of fixed length `Nh`
    /// bytes from input keying material `ikm` and an optional byte string
    /// `salt`.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn kdf_extract(&self, alg: HpkeKdfId, salt: &[u8], ikm: IkmRef<'_>)
    -> Result<Prk, CryptoError>;

    /// See [`kdf_extract`](Crypto::kdf_extract).
    ///
    /// `concat(x0, ..., xN)`: Concatenation of byte strings. `concat(0x01,
    /// 0x0203, 0x040506) = 0x010203040506`.
    ///
    /// The default implementation concatenates the input keying materials and
    /// calls `kdf_extract`. This is a convenience function, but for those who
    /// support multiple IKM inputs natively, they can override this
    /// function.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    fn kdf_extract_concated(
        &self,
        alg: HpkeKdfId,
        salt: &[u8],
        ikms: &[IkmRef<'_>],
    ) -> Result<Prk, CryptoError> {
        let mut concated = Vec::new();

        for ikm in ikms {
            concated.extend_from_slice(ikm);
        }

        self.kdf_extract(alg, salt, IkmRef::from(&concated))
    }

    /// `Expand(prk, info, L)`: Expand a pseudorandom key `prk` using optional
    /// string `info` into `L` bytes of output keying material.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn kdf_expand(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        info: &[u8],
        l: usize,
    ) -> Result<Okm, CryptoError>;

    /// See [`kdf_expand`](Crypto::kdf_expand).
    ///
    /// `concat(x0, ..., xN)`: Concatenation of byte strings. `concat(0x01,
    /// 0x0203, 0x040506) = 0x010203040506`.
    ///
    /// The default implementation concatenates the info slices and calls
    /// `kdf_expand`. This is a convenience function, but for those who
    /// support multiple info inputs natively, they can override this
    /// function.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    fn kdf_expand_multi_info(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        infos: &[&[u8]],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        self.kdf_expand(alg, prk, &infos.concat(), l)
    }

    /// Helper function to check if a AEAD algorithm is supported by this
    /// backend.
    fn is_aead_supported(&self, alg: &HpkeAeadId) -> bool;

    /// `Seal(key, nonce, aad, pt)`: Encrypt and authenticate plaintext with
    /// associated data `aad` using symmetric key `key` and nonce `nonce`,
    /// yielding ciphertext and tag `ct`.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// For in-place encryption, see
    /// [`aead_seal_in_place`](Crypto::aead_seal_in_place).
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn aead_seal(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = plaintext.to_vec();
        self.aead_seal_in_place(crypto_info, aad, &mut buffer)?;
        Ok(buffer)
    }

    /// `Seal(key, nonce, aad, pt)`: Encrypt and authenticate plaintext `pt`
    /// with associated data `aad` using symmetric key `key` and nonce
    /// `nonce`, yielding ciphertext and tag `ct`.
    ///
    /// This function operates in-place, modifying the `buffer` directly. The
    /// buffer should contain the plaintext followed by space for the
    /// authentication tag.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn aead_seal_in_place(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError>;

    /// `Open(key, nonce, aad, ct)`: Decrypt ciphertext and tag `ct` using
    /// associated data `aad` with symmetric key `key` and nonce `nonce`,
    /// returning plaintext message `pt`.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// For in-place decryption, see
    /// [`aead_open_in_place`](Crypto::aead_open_in_place).
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn aead_open(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = ciphertext.to_vec();
        self.aead_open_in_place(crypto_info, aad, &mut buffer)?;
        Ok(buffer)
    }

    /// `Open(key, nonce, aad, ct)`: Decrypt ciphertext and tag `ct` using
    /// associated data `aad` with symmetric key `key` and nonce `nonce`,
    /// returning plaintext message `pt`.
    ///
    /// This function operates in-place, modifying the `buffer` directly. The
    /// buffer should contain the ciphertext followed by the authentication
    /// tag.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// Notes that some implementations may clear the buffer on failure.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn aead_open_in_place(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError>;

    /// This is not part of the HPKE spec, but a utility function to
    /// validate a private key for the KEM and wrap it in a
    /// [`HpkePrivateKey`] if valid.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    fn sk(&self, alg: HpkeKemId, sk: &[u8]) -> Result<HpkePrivateKey, CryptoError>;

    /// The notation `pk(skX)`, depending on its use and the KEM and its
    /// implementation, is either the computation of the public key using the
    /// private key, or just syntax expressing the retrieval of the public key,
    /// assuming it is stored along with the private key object.
    ///
    /// See [RFC 9180, Section 4] for details.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    fn pk(&self, alg: HpkeKemId, sk: HpkePrivateKeyRef<'_>) -> Result<HpkePublicKey, CryptoError>;

    /// Perform a non-interactive Diffie-Hellman exchange using the private key
    /// `skX` and public key `pkY` to produce a Diffie-Hellman shared secret of
    /// length `Ndh`.
    ///
    /// See [RFC 9180, Section 4.1] for details.
    ///
    /// Notes that only DH-Based KEM supports this operation.
    ///
    /// # Errors
    ///
    /// See [`CryptoError`] for possible errors.
    ///
    /// [RFC 9180, Section 4.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
    fn dh(
        &self,
        alg: HpkeKemId,
        sk_x: HpkePrivateKeyRef<'_>,
        pk_y: HpkePublicKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError>;
}

impl<T> Crypto for T
where
    T: DerefMut<Target = dyn Crypto> + fmt::Debug + Send + Sync + ?Sized,
{
    fn secure_random_fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        (**self).secure_random_fill(buf)
    }

    fn is_kem_supported(&self, alg: &HpkeKemId) -> bool {
        (**self).is_kem_supported(alg)
    }

    fn kem_generate_key_pair(&mut self, alg: HpkeKemId) -> Result<HpkeKeyPair, CryptoError> {
        (**self).kem_generate_key_pair(alg)
    }

    fn kem_encap(
        &self,
        alg: HpkeKemId,
        pk_r: HpkePublicKeyRef<'_>,
    ) -> Result<(SharedSecret, EncapsulatedSecret), CryptoError> {
        (**self).kem_encap(alg, pk_r)
    }

    fn kem_decap(
        &self,
        alg: HpkeKemId,
        enc: EncapsulatedSecret,
        sk_r: HpkePrivateKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        (**self).kem_decap(alg, enc, sk_r)
    }

    fn is_kdf_supported(&self, alg: &HpkeKdfId) -> bool {
        (**self).is_kdf_supported(alg)
    }

    fn kdf_extract(
        &self,
        alg: HpkeKdfId,
        salt: &[u8],
        ikm: IkmRef<'_>,
    ) -> Result<Prk, CryptoError> {
        (**self).kdf_extract(alg, salt, ikm)
    }

    fn kdf_extract_concated(
        &self,
        alg: HpkeKdfId,
        salt: &[u8],
        ikms: &[IkmRef<'_>],
    ) -> Result<Prk, CryptoError> {
        (**self).kdf_extract_concated(alg, salt, ikms)
    }

    fn kdf_expand(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        info: &[u8],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        (**self).kdf_expand(alg, prk, info, l)
    }

    fn kdf_expand_multi_info(
        &self,
        alg: HpkeKdfId,
        prk: PrkRef<'_>,
        infos: &[&[u8]],
        l: usize,
    ) -> Result<Okm, CryptoError> {
        (**self).kdf_expand_multi_info(alg, prk, infos, l)
    }

    fn is_aead_supported(&self, alg: &HpkeAeadId) -> bool {
        (**self).is_aead_supported(alg)
    }

    fn aead_seal(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        (**self).aead_seal(crypto_info, aad, plaintext)
    }

    fn aead_seal_in_place(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        (**self).aead_seal_in_place(crypto_info, aad, buffer)
    }

    fn aead_open(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        (**self).aead_open(crypto_info, aad, ciphertext)
    }

    fn aead_open_in_place(
        &self,
        crypto_info: &HpkeAead,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        (**self).aead_open_in_place(crypto_info, aad, buffer)
    }

    fn sk(&self, alg: HpkeKemId, sk: &[u8]) -> Result<HpkePrivateKey, CryptoError> {
        (**self).sk(alg, sk)
    }

    fn pk(&self, alg: HpkeKemId, sk: HpkePrivateKeyRef<'_>) -> Result<HpkePublicKey, CryptoError> {
        (**self).pk(alg, sk)
    }

    fn dh(
        &self,
        alg: HpkeKemId,
        sk_x: HpkePrivateKeyRef<'_>,
        pk_y: HpkePublicKeyRef<'_>,
    ) -> Result<SharedSecret, CryptoError> {
        (**self).dh(alg, sk_x, pk_y)
    }
}

#[derive(Debug)]
/// Errors thrown by implementations.
pub enum CryptoError {
    /// `Expand()` failed due to invalid PRK length.
    ///
    /// This error is returned when:
    ///
    /// 1. For HKDF-Expand, the PRK length MUST be at least `Nh` bytes.
    KdfExpandInvalidPrkLen,

    /// `Expand()` failed due to invalid output length.
    ///
    /// This error is returned when:
    ///
    /// 1. For HKDF-Expand, the requested output length MUST NOT exceed the
    ///    maximum allowed length (255 * `Nh`).
    KdfExpandInvalidOutputLen,

    /// The KDF algorithm is unknown or unsupported by the crypto backend.
    KdfUnsupported,

    /// Failed to derive a key pair from the input keying material.
    ///
    /// This error is returned when:
    ///
    /// 1. Failed to generate valid private key from the input keying material
    ///    in 255 iterations.
    KemDeriveKeyPair,

    /// The `skX` is malformed and cannot be used as a private key for the KEM.
    KemMalformedSkX,

    /// The `pkX` is malformed and cannot be used as a public key for the KEM.
    KemMalformedPkX,

    /// The operation is not supported by the KEM algorithm.
    ///
    /// This error is returned when the KEM algorithm does not support
    /// the requested operation, e.g., `Encap` or `Decap`.
    KemOpUnsupported,

    /// The KEM algorithm is unknown or unsupported by the crypto backend.
    KemUnsupported,

    /// Invalid key for the AEAD algorithm.
    AeadInvalidKey,

    /// Invalid nonce for the AEAD algorithm.
    AeadInvalidNonce,

    /// The cipher text `ct` is invalid for the AEAD algorithm.
    ///
    /// This error is returned when:
    ///
    /// 1. The cipher text length is less than the tag length.
    AeadInvalidCt,

    /// Error sealing an AEAD cipher text.
    AeadSeal,

    /// Error opening an AEAD cipher text.
    AeadOpen,

    /// Unknown or unsupported AEAD algorithm.
    AeadUnsupported,

    /// Insufficient randomness to perform the operation.
    ///
    /// This error is rarely returned.
    InsufficientRandomness,

    /// A crypto library error.
    Custom(Box<dyn core::error::Error + Send + Sync + 'static>),
}

impl core::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Custom(e) => Some(&**e),
            _ => None,
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KdfExpandInvalidPrkLen => write!(f, "KDF expand: invalid PRK length"),
            Self::KdfExpandInvalidOutputLen => write!(f, "KDF expand: invalid output length"),
            Self::KdfUnsupported => write!(f, "KDF unsupported"),
            Self::KemDeriveKeyPair => write!(f, "KEM derive key pair failed"),
            Self::KemMalformedSkX => write!(f, "KEM malformed private key"),
            Self::KemMalformedPkX => write!(f, "KEM malformed public key"),
            Self::KemOpUnsupported => write!(f, "KEM operation unsupported"),
            Self::KemUnsupported => write!(f, "KEM unsupported"),
            Self::AeadInvalidKey => write!(f, "AEAD invalid key"),
            Self::AeadInvalidNonce => write!(f, "AEAD invalid nonce"),
            Self::AeadInvalidCt => write!(f, "AEAD invalid cipher text"),
            Self::AeadSeal => write!(f, "AEAD seal error"),
            Self::AeadOpen => write!(f, "AEAD open error"),
            Self::AeadUnsupported => write!(f, "AEAD unsupported"),
            Self::InsufficientRandomness => write!(f, "Insufficient randomness"),
            Self::Custom(e) => write!(f, "Crypto library error: {}", e),
        }
    }
}

// === Algorithm Identifiers ===

#[derive(Debug, Clone, Copy)]
/// A `ciphersuite` is a triple (KEM, KDF, AEAD) containing a choice of
/// algorithm for each primitive.
pub struct HpkeCipherSuite {
    /// KEM algorithm identifier.
    pub kem_id: HpkeKemId,

    /// KDF algorithm identifier.
    pub kdf_id: HpkeKdfId,

    /// AEAD algorithm identifier.
    pub aead_id: HpkeAeadId,
}

impl HpkeCipherSuite {
    /// The value of `suite_id` depends on where the KDF is used; it is assumed
    /// implicit from the implementation and not passed as a parameter. If used
    /// inside a KEM algorithm, `suite_id` MUST start with "KEM" and identify
    /// this KEM algorithm; if used in the remainder of HPKE, it MUST start
    /// with "HPKE" and identify the entire ciphersuite in use.
    ///
    /// The HPKE algorithm identifiers, i.e., the KEM kem_id, KDF kdf_id, and
    /// AEAD aead_id 2-byte code points, as defined in other places,
    /// respectively, are assumed implicit from the implementation and
    /// not passed as parameters. The implicit suite_id value used within
    /// LabeledExtract and LabeledExpand is defined based on them as follows:
    ///
    /// ```text
    /// suite_id = concat(
    ///   "HPKE",
    ///   I2OSP(kem_id, 2),
    ///   I2OSP(kdf_id, 2),
    ///   I2OSP(aead_id, 2)
    /// )
    /// ```
    ///
    /// See [RFC 9180, Section 4], [RFC 9180, Section 5.1] for details.
    ///
    /// # Examples
    ///
    /// ```
    /// # use hpke_crypto::{HpkeCipherSuite, HpkeKemId, HpkeKdfId, HpkeAeadId};
    /// let suite = HpkeCipherSuite {
    ///     kem_id: HpkeKemId::DHKEM_P256_HKDF_SHA256,
    ///     kdf_id: HpkeKdfId::HKDF_SHA256,
    ///     aead_id: HpkeAeadId::CHACHA20_POLY1305,
    /// };
    /// assert_eq!(suite.suite_id(), [72, 80, 75, 69, 0, 16, 0, 1, 0, 3]);
    /// ```
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    /// [RFC 9180, Section 5.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
    pub fn suite_id(&self) -> [u8; 10] {
        let mut suite_id = [0u8; 10];

        suite_id[0..4].copy_from_slice(b"HPKE");
        suite_id[4..6].copy_from_slice(&self.kem_id.to_int().to_be_bytes());
        suite_id[6..8].copy_from_slice(&self.kdf_id.to_int().to_be_bytes());
        suite_id[8..10].copy_from_slice(&self.aead_id.to_int().to_be_bytes());

        suite_id
    }
}

macro_rules! enum_builder {
    (
        type Error = $error:ident;
        #[repr($uint:ty)]
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident
        {
            $(
                $(#[doc = $registry_comment:literal])*
                $registry_name:ident = $registry_value:literal
            ),+
            $(,)?
        }
    ) => {
        #[non_exhaustive]
        #[allow(clippy::upper_case_acronyms)]
        #[allow(non_camel_case_types)]
        #[derive(PartialEq, Eq, Clone, Copy)]
        #[repr($uint)]
        $(#[$enum_meta])*
        $vis enum $name {
            $(
                $(#[doc = $registry_comment])*
                $registry_name = $registry_value,
            )+
        }

        impl $name {
            #[inline]
            #[allow(unused)]
            /// Constructs an enum value from its integer representation.
            $vis const fn try_from_int(x: $uint) -> Result<Self, $error> {
                match x {
                    $(
                        $registry_value => Ok(Self::$registry_name),
                    )+
                    _ => Err($error (x)),
                }
            }

            #[inline]
            #[allow(unused)]
            /// Returns the integer representation of this value.
            $vis const fn to_int(self) -> $uint {
                self as $uint
            }

            #[inline]
            #[allow(unused)]
            /// Returns the big-endian byte representation of this value.
            $vis const fn to_array(self) -> [u8; core::mem::size_of::<$uint>()] {
                self.to_int().to_be_bytes()
            }

            #[inline]
            #[allow(unused)]
            /// Returns the string representation of this value.
            $vis const fn as_str(&self) -> &'static str {
                match self {
                    $(
                        Self::$registry_name => stringify!($registry_name),
                    )+
                }
            }
        }

        impl From<$name> for $uint {
            fn from(value: $name) -> Self {
                value.to_int()
            }
        }

        impl TryFrom<$uint> for $name {
            type Error = $error;

            fn try_from(x: $uint) -> Result<Self, Self::Error> {
                Self::try_from_int(x)
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $(
                        Self::$registry_name => f.write_str(stringify!($registry_name)),
                    )+
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{:?}", self)
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.to_int().serialize(serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'a> serde::Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'a>,
            {
                let v = <$uint>::deserialize(deserializer)?;

                Self::try_from(v).map_err(serde::de::Error::custom)
            }
        }
    };
}

#[derive(Debug, Clone, Copy)]
/// An unknown KEM identifier.
pub struct UnknownHpkeKemId(pub u16);

impl fmt::Display for UnknownHpkeKemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown HPKE KEM ID: {}", self.0)
    }
}

enum_builder!(
    type Error = UnknownHpkeKemId;

    #[repr(u16)]
    /// HPKE Key Encapsulation Mechanisms (KEMs) identifiers.
    ///
    /// See [RFC 9180, Section 7.1].
    ///
    /// [RFC 9180, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
    pub enum HpkeKemId {
        /// DHKEM(P-256, HKDF-SHA256)
        DHKEM_P256_HKDF_SHA256 = 0x0010,

        /// DHKEM(P-384, HKDF-SHA384)
        DHKEM_P384_HKDF_SHA384 = 0x0011,

        /// DHKEM(P-521, HKDF-SHA512)
        DHKEM_P521_HKDF_SHA512 = 0x0012,

        /// DHKEM(X25519, HKDF-SHA256)
        DHKEM_X25519_HKDF_SHA256 = 0x0020,

        /// DHKEM(X448, HKDF-SHA512)
        DHKEM_X448_HKDF_SHA512 = 0x0021,
    }
);

impl HpkeKemId {
    #[inline]
    /// Returns the KDF algorithm associated with the DHKEM.
    ///
    /// If the KEM is not a DHKEM, returns `None`.
    pub const fn kdf_id(&self) -> HpkeKdfId {
        match self {
            Self::DHKEM_P256_HKDF_SHA256 | Self::DHKEM_X25519_HKDF_SHA256 => HpkeKdfId::HKDF_SHA256,
            Self::DHKEM_P384_HKDF_SHA384 => HpkeKdfId::HKDF_SHA384,
            Self::DHKEM_P521_HKDF_SHA512 | Self::DHKEM_X448_HKDF_SHA512 => HpkeKdfId::HKDF_SHA512,
        }
    }

    #[inline]
    /// The value of `suite_id` depends on where the KDF is used; it is assumed
    /// implicit from the implementation and not passed as a parameter. If used
    /// inside a KEM algorithm, `suite_id` MUST start with "KEM" and identify
    /// this KEM algorithm; if used in the remainder of HPKE, it MUST start
    /// with "HPKE" and identify the entire ciphersuite in use.
    ///
    /// The implicit `suite_id` value used within `LabeledExtract` and
    /// `LabeledExpand` is defined as follows:
    ///
    /// ```text
    /// suite_id = concat("KEM", I2OSP(kem_id, 2))
    /// ```
    ///
    /// See [RFC 9180, Section 4], [RFC 9180, Section 4.1] for details.
    ///
    /// # Example
    ///
    /// ```
    /// # use hpke_crypto::{HpkeKemId};
    /// assert_eq!(
    ///     HpkeKemId::DHKEM_P521_HKDF_SHA512.suite_id(),
    ///     [75, 69, 77, 0, 18]
    /// );
    /// ```
    ///
    /// [RFC 9180, Section 4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
    /// [RFC 9180, Section 4.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
    pub fn suite_id(&self) -> [u8; 5] {
        let mut suite_id = [0u8; 5];

        suite_id[0..3].copy_from_slice(b"KEM");
        suite_id[3..5].copy_from_slice(&self.to_int().to_be_bytes());

        suite_id
    }

    #[inline]
    /// Returns the length in bytes of a KEM shared secret produced by this KEM
    /// (Nsecret).
    ///
    /// See [RFC 9180, Section 7.1].
    ///
    /// [RFC 9180, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
    pub const fn n_secret(&self) -> usize {
        match self {
            Self::DHKEM_P256_HKDF_SHA256 => 32,
            Self::DHKEM_P384_HKDF_SHA384 => 48,
            Self::DHKEM_P521_HKDF_SHA512 => 64,
            Self::DHKEM_X25519_HKDF_SHA256 => 32,
            Self::DHKEM_X448_HKDF_SHA512 => 64,
        }
    }

    #[inline]
    /// Returns the length in bytes of an encapsulated key produced by this KEM.
    /// (Nenc).
    ///
    /// See [RFC 9180, Section 7.1].
    ///
    /// [RFC 9180, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
    pub const fn n_enc(&self) -> usize {
        match self {
            Self::DHKEM_P256_HKDF_SHA256 => 65,
            Self::DHKEM_P384_HKDF_SHA384 => 97,
            Self::DHKEM_P521_HKDF_SHA512 => 133,
            Self::DHKEM_X25519_HKDF_SHA256 => 32,
            Self::DHKEM_X448_HKDF_SHA512 => 56,
        }
    }

    #[inline]
    /// Returns the length in bytes of an encoded public key for this KEM
    /// (Npk).
    ///
    /// See [RFC 9180, Section 7.1].
    ///
    /// [RFC 9180, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
    pub const fn n_pk(&self) -> usize {
        match self {
            Self::DHKEM_P256_HKDF_SHA256 => 65,
            Self::DHKEM_P384_HKDF_SHA384 => 97,
            Self::DHKEM_P521_HKDF_SHA512 => 133,
            Self::DHKEM_X25519_HKDF_SHA256 => 32,
            Self::DHKEM_X448_HKDF_SHA512 => 56,
        }
    }

    #[inline]
    /// Returns the length in bytes of an encoded private key for this KEM
    /// (Nsk).
    ///
    /// See [RFC 9180, Section 7.1].
    ///
    /// [RFC 9180, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
    pub const fn n_sk(&self) -> usize {
        match self {
            Self::DHKEM_P256_HKDF_SHA256 => 32,
            Self::DHKEM_P384_HKDF_SHA384 => 48,
            Self::DHKEM_P521_HKDF_SHA512 => 66,
            Self::DHKEM_X25519_HKDF_SHA256 => 32,
            Self::DHKEM_X448_HKDF_SHA512 => 56,
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// An unknown KDF identifier.
pub struct UnknownHpkeKdfId(pub u16);

impl fmt::Display for UnknownHpkeKdfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown HPKE KDF ID: {}", self.0)
    }
}

enum_builder!(
    type Error = UnknownHpkeKdfId;

    #[repr(u16)]
    /// HPKE Key Derivation Functions (KDFs) identifiers.
    ///
    /// See [RFC 9180, Section 7.2].
    ///
    /// [RFC 9180, Section 7.2]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2
    pub enum HpkeKdfId {
        /// HKDF-SHA256
        HKDF_SHA256 = 0x0001,

        /// HKDF-SHA384
        HKDF_SHA384 = 0x0002,

        /// HKDF-SHA512
        HKDF_SHA512 = 0x0003,
    }
);

impl HpkeKdfId {
    #[inline]
    /// Returns the length in bytes of the hash output for this KDF (Nh).
    pub const fn n_hash(&self) -> usize {
        match self {
            Self::HKDF_SHA256 => 32,
            Self::HKDF_SHA384 => 48,
            Self::HKDF_SHA512 => 64,
        }
    }
}

impl From<HpkeKemId> for HpkeKdfId {
    #[inline]
    fn from(kem: HpkeKemId) -> Self {
        match kem {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 | HpkeKemId::DHKEM_X25519_HKDF_SHA256 => {
                Self::HKDF_SHA256
            }
            HpkeKemId::DHKEM_P384_HKDF_SHA384 => Self::HKDF_SHA384,
            HpkeKemId::DHKEM_P521_HKDF_SHA512 | HpkeKemId::DHKEM_X448_HKDF_SHA512 => {
                Self::HKDF_SHA512
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// An unknown AEAD identifier.
pub struct UnknownAeadAlgorithm(pub u16);

impl fmt::Display for UnknownAeadAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown HPKE AEAD ID: {}", self.0)
    }
}

enum_builder!(
    type Error = UnknownAeadAlgorithm;

    #[repr(u16)]
    /// HPKE Authenticated Encryption with Associated Data (AEAD) Functions
    /// identifiers.
    ///
    /// See [RFC 9180, Section 7.3].
    ///
    /// [RFC 9180, Section 7.3]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3
    pub enum HpkeAeadId {
        /// AES-128-GCM
        AES_128_GCM = 0x0001,

        /// AES-256-GCM
        AES_256_GCM = 0x0002,

        /// ChaCha20Poly1305
        CHACHA20_POLY1305 = 0x0003,

        /// Export-only
        EXPORT_ONLY = 0xFFFF,
    }
);

impl HpkeAeadId {
    #[inline]
    /// Returns the length in bytes of a key for this algorithm (`Nk`).
    pub const fn n_key(&self) -> usize {
        match self {
            Self::AES_128_GCM => 16,
            Self::AES_256_GCM => 32,
            Self::CHACHA20_POLY1305 => 32,
            Self::EXPORT_ONLY => 0,
        }
    }

    #[inline]
    /// Returns the length in bytes of a nonce for this algorithm (`Nn`).
    pub const fn n_nonce(&self) -> usize {
        match self {
            Self::AES_128_GCM => 12,
            Self::AES_256_GCM => 12,
            Self::CHACHA20_POLY1305 => 12,
            Self::EXPORT_ONLY => 0,
        }
    }

    #[inline]
    /// Returns the length in bytes of the authentication tag for this
    /// algorithm (`Nt`).
    pub const fn n_tag(&self) -> usize {
        match self {
            Self::AES_128_GCM => 16,
            Self::AES_256_GCM => 16,
            Self::CHACHA20_POLY1305 => 16,
            Self::EXPORT_ONLY => 0,
        }
    }

    #[inline]
    /// Create the AEAD cryptographic material from the given key and nonce.
    ///
    /// Returns `None` if the AEAD algorithm is `EXPORT_ONLY`.
    ///
    /// # Errors
    ///
    /// Invalid key or nonce length.
    pub fn new_crypto_info(
        &self,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<Option<HpkeAead>, CryptoError> {
        Ok(match self {
            Self::AES_128_GCM => Some(HpkeAead::Aes128Gcm {
                key: key
                    .try_into()
                    .map_err(|_| CryptoError::AeadInvalidKey)?,
                nonce: nonce
                    .try_into()
                    .map_err(|_| CryptoError::AeadInvalidNonce)?,
            }),
            Self::AES_256_GCM => Some(HpkeAead::Aes256Gcm {
                key: key
                    .try_into()
                    .map_err(|_| CryptoError::AeadInvalidKey)?,
                nonce: nonce
                    .try_into()
                    .map_err(|_| CryptoError::AeadInvalidNonce)?,
            }),
            Self::CHACHA20_POLY1305 => Some(HpkeAead::ChaCha20Poly1305 {
                key: key
                    .try_into()
                    .map_err(|_| CryptoError::AeadInvalidKey)?,
                nonce: nonce
                    .try_into()
                    .map_err(|_| CryptoError::AeadInvalidNonce)?,
            }),
            Self::EXPORT_ONLY => None,
        })
    }
}

macro_rules! debug_hex {
    ($name:ty, $inner:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(core::any::type_name::<Self>())
                    .field(&const_hex::encode(&self.$inner).as_str())
                    .finish()
            }
        }
    };
}

#[derive(Clone, PartialEq, Eq)]
/// A HPKE public/private key pair.
pub struct HpkeKeyPair {
    inner: SmallVec<u8, 240>,
    split_offset: u8,
}

impl fmt::Debug for HpkeKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("sk", &self.sk())
            .field("pk", &self.pk())
            .finish()
    }
}

impl HpkeKeyPair {
    #[inline]
    /// Creates a new len-validated [`HpkePublicKey`] of the given KEM
    /// algorithm.
    ///
    /// Notes that this does *not* validate the keys cryptographically. Usually
    /// one can avoid using this except when implementing [`Crypto`] trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the key's length is invalid for the given KEM
    /// algorithm.
    pub fn new_unchecked(
        alg: HpkeKemId,
        sk: impl AsRef<[u8]>,
        pk: impl AsRef<[u8]>,
    ) -> Result<Self, CryptoError> {
        if sk.as_ref().len() != alg.n_sk() {
            return Err(CryptoError::KemMalformedSkX);
        }

        if pk.as_ref().len() != alg.n_pk() {
            return Err(CryptoError::KemMalformedPkX);
        }

        let mut inner = SmallVec::new();
        inner.extend_from_slice(sk.as_ref());
        inner.extend_from_slice(pk.as_ref());

        Ok(Self {
            inner,
            split_offset: sk.as_ref().len() as u8,
        })
    }

    #[inline]
    /// Returns the private key (skX).
    pub fn sk<'a>(&'a self) -> HpkePrivateKeyRef<'a> {
        HpkePrivateKeyRef::const_from(&self.inner[..self.split_offset as usize])
    }

    #[inline]
    /// Returns the public key (pkX).
    pub fn pk<'a>(&'a self) -> HpkePublicKeyRef<'a> {
        HpkePublicKeyRef::const_from(&self.inner[self.split_offset as usize..])
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[derive(Clone, PartialEq, Eq)]
    /// A HPKE public key (pkX).
    ///
    /// Notes that the key is not validated cryptographically.
    pub struct HpkePublicKey(SmallVec<u8, 184>);
);

debug_hex!(HpkePublicKey, inner);

impl HpkePublicKey {
    #[inline]
    /// Creates a new len-validated [`HpkePublicKey`] of the given KEM
    /// algorithm.
    ///
    /// Notes that this does *not* validate the public key itself
    /// cryptographically.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key's length is invalid for the given
    /// KEM algorithm.
    pub fn new(alg: HpkeKemId, bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != alg.n_pk() {
            return Err(CryptoError::KemMalformedPkX);
        }

        Ok(Self {
            inner: SmallVec::from_slice(bytes),
        })
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    /// A HPKE public key (pkX).
    pub struct HpkePublicKeyRef<'a>(&'a [u8]);
);

debug_hex!(HpkePublicKeyRef<'_>, inner);

impl<'a> From<&'a HpkePublicKey> for HpkePublicKeyRef<'a> {
    fn from(value: &'a HpkePublicKey) -> Self {
        Self::const_from(&value.inner)
    }
}

impl HpkePublicKeyRef<'_> {
    #[inline]
    /// Converts this reference to an owned [`HpkePublicKey`].
    pub fn to_owned(&self) -> HpkePublicKey {
        HpkePublicKey {
            inner: SmallVec::from_slice(self.inner),
        }
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[derive(Eq)]
    #[derive(zeroize_derive::ZeroizeOnDrop)]
    #[cfg_attr(feature = "hazmat", derive(Clone))]
    /// A HPKE private key (skX).
    ///
    /// Notes that the key is not validated cryptographically.
    pub struct HpkePrivateKey(SmallVec<u8, 120>);
);

impl PartialEq for HpkePrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner
            .ct_eq(other.inner.as_ref())
            .into()
    }
}

impl fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "hazmat")]
        {
            f.debug_tuple(core::any::type_name::<Self>())
                .field(&const_hex::encode(self.inner.as_ref()).as_str())
                .finish()
        }

        #[cfg(not(feature = "hazmat"))]
        {
            f.debug_tuple(core::any::type_name::<Self>())
                .finish_non_exhaustive()
        }
    }
}

impl HpkePrivateKey {
    #[inline]
    /// Creates a new [`HpkePrivateKey`] of the given KEM algorithm.
    ///
    /// Notes that this does *not* validate the private key itself
    /// cryptographically.
    ///
    /// # Errors
    ///
    /// Returns an error if the private key's length is invalid for the given
    /// KEM algorithm.
    pub fn new(alg: HpkeKemId, bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != alg.n_sk() {
            return Err(CryptoError::KemMalformedSkX);
        }

        Ok(Self {
            inner: SmallVec::from_slice(bytes),
        })
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, Copy, Eq)]
    /// A HPKE private key (skX).
    ///
    /// Notes that the key is not validated cryptographically.
    pub struct HpkePrivateKeyRef<'a>(&'a [u8]);
);

impl fmt::Debug for HpkePrivateKeyRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "hazmat")]
        {
            f.debug_tuple(core::any::type_name::<Self>())
                .field(&const_hex::encode(self.inner.as_ref()).as_str())
                .finish()
        }

        #[cfg(not(feature = "hazmat"))]
        {
            f.debug_tuple(core::any::type_name::<Self>())
                .finish_non_exhaustive()
        }
    }
}

impl PartialEq for HpkePrivateKeyRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.inner
            .ct_eq(other.inner.as_ref())
            .into()
    }
}

impl<'a> From<&'a HpkePrivateKey> for HpkePrivateKeyRef<'a> {
    fn from(value: &'a HpkePrivateKey) -> Self {
        Self::const_from(&value.inner)
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, PartialEq, Eq)]
    /// The shared secret produced by the KEM.
    pub struct SharedSecret(SmallVec<u8, 56>);
);

debug_hex!(SharedSecret, inner);

impl SharedSecret {
    #[inline]
    /// Constructs a new [`SharedSecret`] produced by the KEM.
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            inner: SmallVec::from_slice(bytes),
        }
    }

    #[inline]
    /// Constructs a new [`SharedSecret`] from the output keying material
    /// (OKM).
    pub fn from_okm(okm: Okm) -> Self {
        Self { inner: okm.inner }
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, PartialEq, Eq)]
    /// The shared secret produced by the KEM.
    pub struct SharedSecretRef<'a>(&'a [u8]);
);

debug_hex!(SharedSecretRef<'_>, inner);

impl<'a> From<&'a SharedSecret> for SharedSecretRef<'a> {
    fn from(value: &'a SharedSecret) -> Self {
        Self::const_from(&value.inner)
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, PartialEq, Eq)]
    /// The encapsulated secret produced by the KEM.
    pub struct EncapsulatedSecret(SmallVec<u8, 184>);
);

debug_hex!(EncapsulatedSecret, inner);

impl EncapsulatedSecret {
    #[inline]
    /// Constructs a new [`EncapsulatedSecret`] received from the sender for
    /// decapsulating the shared secret.
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            inner: SmallVec::from_slice(bytes),
        }
    }

    /// Constructs a new [`EncapsulatedSecret`] from the ephemeral public key
    /// (pkE).
    pub fn new_from_pk_e(pk: HpkePublicKey) -> Self {
        Self { inner: pk.inner }
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, PartialEq, Eq)]
    /// The encapsulated secret produced by the KEM.
    pub struct EncapsulatedSecretRef<'a>(&'a [u8]);
);

debug_hex!(EncapsulatedSecretRef<'_>, inner);

impl<'a> From<&'a EncapsulatedSecret> for EncapsulatedSecretRef<'a> {
    fn from(value: &'a EncapsulatedSecret) -> Self {
        Self::const_from(&value.inner)
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    /// The input keying material (IKM), see HKDF-Extract.
    pub struct IkmRef<'a>(&'a [u8]);
);

debug_hex!(IkmRef<'_>, inner);

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[derive(Clone, PartialEq, Eq)]
    /// A pseudorandom key (PRK) used in the KDF functions.
    pub struct Prk(SmallVec<u8, 64>);
);

debug_hex!(Prk, inner);

impl Prk {
    #[inline]
    /// Construct a new [`Prk`] directly with the given value.
    pub fn new_less_safe(bytes: &[u8]) -> Self {
        Self {
            inner: SmallVec::from_slice(bytes),
        }
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[wrapper_impl(From)]
    #[derive(Clone, PartialEq, Eq)]
    /// A pseudorandom key (PRK) used in the KDF functions.
    pub struct PrkRef<'a>(&'a [u8]);
);

debug_hex!(PrkRef<'_>, inner);

impl<'a> From<&'a Prk> for PrkRef<'a> {
    fn from(value: &'a Prk) -> Self {
        Self::const_from(&value.inner)
    }
}

wrapper_lite::wrapper!(
    #[wrapper_impl(AsRef<[u8]>)]
    #[wrapper_impl(Deref<[u8]>)]
    #[derive(Clone, PartialEq, Eq)]
    /// The output keying material (OKM), see HKDF-Expand.
    pub struct Okm(SmallVec<u8, 56>);
);

debug_hex!(Okm, inner);

impl Okm {
    #[inline]
    /// Construct a new empty [`Okm`].
    ///
    /// Usually one can avoid using this except when implementing [`Crypto`]
    /// trait.
    pub const fn empty() -> Self {
        Self {
            inner: SmallVec::new(),
        }
    }

    /// Truncates the internal buffer to the given length.
    ///
    /// Usually one can avoid using this except when implementing [`Crypto`]
    /// trait.
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Returns a mutable buffer of the specified length, resizing the internal
    /// storage if necessary.
    ///
    /// Usually one can avoid using this except when implementing [`Crypto`]
    /// trait.
    pub fn as_mut_buffer(&mut self, len: usize) -> &mut [u8] {
        self.inner.resize(len, 0);
        &mut self.inner
    }
}

#[non_exhaustive]
#[derive(Debug)]
#[derive(zeroize_derive::ZeroizeOnDrop)]
#[cfg_attr(feature = "hazmat", derive(PartialEq, Eq, Clone))]
/// AEAD cryptographic material.
pub enum HpkeAead {
    /// AES-128-GCM
    Aes128Gcm {
        /// The AEAD key.
        key: [u8; HpkeAeadId::AES_128_GCM.n_key()],

        /// The AEAD nonce.
        nonce: [u8; HpkeAeadId::AES_128_GCM.n_nonce()],
    },

    /// AES-256-GCM
    Aes256Gcm {
        /// The AEAD key.
        key: [u8; HpkeAeadId::AES_256_GCM.n_key()],

        /// The AEAD nonce.
        nonce: [u8; HpkeAeadId::AES_256_GCM.n_nonce()],
    },

    /// ChaCha20-Poly1305
    ChaCha20Poly1305 {
        /// The AEAD key.
        key: [u8; HpkeAeadId::CHACHA20_POLY1305.n_key()],

        /// The AEAD nonce.
        nonce: [u8; HpkeAeadId::CHACHA20_POLY1305.n_nonce()],
    },
}

impl HpkeAead {
    #[inline]
    /// Returns the AEAD algorithm identifier for this cryptographic material.
    pub const fn aead_id(&self) -> HpkeAeadId {
        match self {
            Self::Aes128Gcm { .. } => HpkeAeadId::AES_128_GCM,
            Self::Aes256Gcm { .. } => HpkeAeadId::AES_256_GCM,
            Self::ChaCha20Poly1305 { .. } => HpkeAeadId::CHACHA20_POLY1305,
        }
    }

    /// Copies the AEAD cryptographic material, updating the nonce using the
    /// given function and returns the final copy for the actual AEAD operation.
    ///
    /// This is for updating the nonce for each AEAD operation.
    pub fn copied_updating_nonce<F>(&self, update_nonce_f: F) -> Self
    where
        F: FnOnce(&mut [u8]),
    {
        // Manually implement `Clone` to avoid `zeroize` on the original key and the
        // base nonce.
        match self {
            Self::Aes128Gcm { key, nonce } => {
                let mut nonce = *nonce;

                update_nonce_f(&mut nonce);

                Self::Aes128Gcm { key: *key, nonce }
            }
            Self::Aes256Gcm { key, nonce } => {
                let mut nonce = *nonce;

                update_nonce_f(&mut nonce);

                Self::Aes256Gcm { key: *key, nonce }
            }
            Self::ChaCha20Poly1305 { key, nonce } => {
                let mut nonce = *nonce;

                update_nonce_f(&mut nonce);

                Self::ChaCha20Poly1305 { key: *key, nonce }
            }
        }
    }

    #[inline]
    /// Returns the AEAD key.
    pub const fn key(&self) -> &[u8] {
        match self {
            Self::Aes128Gcm { key, .. } => key,
            Self::Aes256Gcm { key, .. } => key,
            Self::ChaCha20Poly1305 { key, .. } => key,
        }
    }

    #[inline]
    /// Returns the AEAD nonce.
    pub const fn nonce(&self) -> &[u8] {
        match self {
            Self::Aes128Gcm { nonce, .. } => nonce,
            Self::Aes256Gcm { nonce, .. } => nonce,
            Self::ChaCha20Poly1305 { nonce, .. } => nonce,
        }
    }
}

impl zeroize::Zeroize for HpkeAead {
    fn zeroize(&mut self) {
        match self {
            Self::Aes128Gcm { key, .. } => {
                key.zeroize();
            }
            Self::Aes256Gcm { key, .. } => {
                key.zeroize();
            }
            Self::ChaCha20Poly1305 { key, .. } => {
                key.zeroize();
            }
        }
    }
}
