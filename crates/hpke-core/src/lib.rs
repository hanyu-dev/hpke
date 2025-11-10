#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
#![allow(clippy::must_use_candidate)]

pub mod error;
pub mod kem;

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

pub use hpke_crypto::*;

pub use crate::error::Error;

/// The HPKE configuration.
#[derive(Debug, Clone, Copy)]
pub struct Hpke<C> {
    /// The HPKE ciphersuite in use.
    cipher_suite: HpkeCipherSuite,

    /// The crypto backend.
    _crypto_backend: PhantomData<C>,
}

impl<C: Crypto> Hpke<C> {
    /// Create a new HPKE configuration with the given ciphersuite.
    pub fn prepare(cipher_suite: HpkeCipherSuite) -> Self {
        Self {
            cipher_suite,
            _crypto_backend: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// 5.1. Creating the Encryption Context
    ///
    /// This is a convenience function that wraps all four setup functions.
    ///
    /// See [RFC 9180, Section 5.1] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process, or if the provided PSK does not meet security requirements.
    ///
    /// [RFC 9180, Section 5.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
    pub fn setup_s(
        &self,
        crypto_backend: C,
        mode: HpkeMode,
        pk_r: HpkePublicKeyRef<'_>,
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        sk_s: Option<HpkePrivateKeyRef<'_>>,
    ) -> Result<(EncapsulatedSecret, Context<C, Sender>), Error> {
        match mode {
            HpkeMode::Base => self.setup_base_s(crypto_backend, pk_r, info),
            HpkeMode::Psk => self.setup_psk_s(
                crypto_backend,
                pk_r,
                info,
                psk.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk"))?,
                psk_id.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk_id"))?,
            ),
            HpkeMode::Auth => self.setup_auth_s(
                crypto_backend,
                pk_r,
                info,
                sk_s.ok_or_else(|| Error::InvalidInput("For Auth mode, must provide sk_s"))?,
            ),
            HpkeMode::AuthPsk => self.setup_auth_psk_s(
                crypto_backend,
                pk_r,
                info,
                psk.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk"))?,
                psk_id.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk_id"))?,
                sk_s.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide sk_s"))?,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// 5.1. Creating the Encryption Context
    ///
    /// This is a convenience function that wraps all four setup functions.
    ///
    /// See [RFC 9180, Section 5.1] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process, or if the provided PSK does not meet security requirements.
    ///
    /// [RFC 9180, Section 5.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
    pub fn setup_r(
        &self,
        crypto_backend: C,
        mode: HpkeMode,
        enc: EncapsulatedSecretRef<'_>,
        sk_r: HpkePrivateKeyRef<'_>,
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        pk_s: Option<HpkePublicKeyRef<'_>>,
    ) -> Result<Context<C, Recipient>, Error> {
        match mode {
            HpkeMode::Base => self.setup_base_r(crypto_backend, enc, sk_r, info),
            HpkeMode::Psk => self.setup_psk_r(
                crypto_backend,
                enc,
                sk_r,
                info,
                psk.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk"))?,
                psk_id.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk_id"))?,
            ),
            HpkeMode::Auth => self.setup_auth_r(
                crypto_backend,
                enc,
                sk_r,
                info,
                pk_s.ok_or_else(|| Error::InvalidInput("For Auth mode, must provide pk_s"))?,
            ),
            HpkeMode::AuthPsk => self.setup_auth_psk_r(
                crypto_backend,
                enc,
                sk_r,
                info,
                psk.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk"))?,
                psk_id.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide psk_id"))?,
                pk_s.ok_or_else(|| Error::InvalidInput("For PSK mode, must provide pk_s"))?,
            ),
        }
    }

    /// 5.1.1. Encryption to a Public Key
    ///
    /// The most basic function of an HPKE scheme is to enable encryption to the
    /// holder of a given KEM private key. The `SetupBaseS()` and `SetupBaseR()`
    /// procedures establish contexts that can be used to encrypt and decrypt,
    /// respectively, for a given private key.
    ///
    /// The KEM shared secret is combined via the KDF with information
    /// describing the key exchange, as well as the explicit `info` parameter
    /// provided by the caller.
    ///
    /// The parameter `pkR` is a public key, and `enc` is an encapsulated KEM
    /// shared secret.
    ///
    /// ```no_run
    /// def SetupBaseS(pkR, info):
    ///   shared_secret, enc = Encap(pkR)
    ///   return enc, KeyScheduleS(mode_base, shared_secret, info,
    ///                            default_psk, default_psk_id)
    /// ```
    ///
    /// See [RFC 9180, Section 5.1.1] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process.
    ///
    /// [RFC 9180, Section 5.1.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.1
    pub fn setup_base_s(
        &self,
        mut crypto_backend: C,
        pk_r: HpkePublicKeyRef<'_>,
        info: &[u8],
    ) -> Result<(EncapsulatedSecret, Context<C, Sender>), Error> {
        let (shared_secret, enc) = kem::encap(&mut crypto_backend, self.cipher_suite.kem_id, pk_r)?;

        let context = self.key_schedule(
            crypto_backend,
            HpkeMode::Base,
            &shared_secret,
            info,
            &[],
            &[],
        )?;

        Ok((enc, context))
    }

    /// 5.1.1. Encryption to a Public Key
    ///
    /// The most basic function of an HPKE scheme is to enable encryption to the
    /// holder of a given KEM private key. The `SetupBaseS()` and `SetupBaseR()`
    /// procedures establish contexts that can be used to encrypt and decrypt,
    /// respectively, for a given private key.
    ///
    /// The KEM shared secret is combined via the KDF with information
    /// describing the key exchange, as well as the explicit `info` parameter
    /// provided by the caller.
    ///
    /// The parameter `pkR` is a public key, and `enc` is an encapsulated KEM
    /// shared secret.
    ///
    /// ```no_run
    /// def SetupBaseR(enc, skR, info):
    ///   shared_secret = Decap(enc, skR)
    ///   return KeyScheduleR(mode_base, shared_secret, info,
    ///                       default_psk, default_psk_id)
    /// ```
    ///
    /// See [RFC 9180, Section 5.1.1] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process.
    ///
    /// [RFC 9180, Section 5.1.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.1
    pub fn setup_base_r(
        &self,
        mut crypto_backend: C,
        enc: EncapsulatedSecretRef<'_>,
        sk_r: HpkePrivateKeyRef<'_>,
        info: &[u8],
    ) -> Result<Context<C, Recipient>, Error> {
        let shared_secret = kem::decap(&mut crypto_backend, self.cipher_suite.kem_id, enc, sk_r)?;

        self.key_schedule(
            crypto_backend,
            HpkeMode::Base,
            shared_secret.as_ref(),
            info,
            &[],
            &[],
        )
    }

    /// 5.1.2. Authentication Using a Pre-Shared Key
    ///
    /// This variant extends the base mechanism by allowing the recipient to
    /// authenticate that the sender possessed a given PSK. The PSK also
    /// improves confidentiality guarantees in certain adversary models, as
    /// described in more detail in [RFC 9180, Section 9.1]. We assume that both
    /// parties have been provisioned with both the PSK value `psk` and
    /// another byte string `psk_id` that is used to identify which PSK
    /// should be used.
    ///
    /// The primary difference from the base case is that the `psk` and `psk_id`
    /// values are used as `ikm` inputs to the KDF (instead of using the empty
    /// string).
    ///
    /// The PSK MUST have at least 32 bytes of entropy and SHOULD be of length
    /// `Nh` bytes or longer. See [RFC 9180, Section 9.5] for a more detailed
    /// discussion.
    ///
    /// ```no_run
    /// def SetupPSKS(pkR, info, psk, psk_id):
    ///   shared_secret, enc = Encap(pkR)
    ///   return enc, KeyScheduleS(mode_psk, shared_secret, info, psk, psk_id)
    /// ```
    ///
    /// See [RFC 9180, Section 5.1.2] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process, or if the provided PSK does not meet security requirements.
    ///
    /// [RFC 9180, Section 5.1.2]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2
    /// [RFC 9180, Section 9.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1
    /// [RFC 9180, Section 9.5]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.5
    pub fn setup_psk_s(
        &self,
        mut crypto_backend: C,
        pk_r: HpkePublicKeyRef<'_>,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(EncapsulatedSecret, Context<C, Sender>), Error> {
        let (shared_secret, enc) = kem::encap(&mut crypto_backend, self.cipher_suite.kem_id, pk_r)?;

        let context = self.key_schedule(
            crypto_backend,
            HpkeMode::Psk,
            shared_secret.as_ref(),
            info,
            psk,
            psk_id,
        )?;

        Ok((enc, context))
    }

    /// 5.1.2. Authentication Using a Pre-Shared Key
    ///
    /// This variant extends the base mechanism by allowing the recipient to
    /// authenticate that the sender possessed a given PSK. The PSK also
    /// improves confidentiality guarantees in certain adversary models, as
    /// described in more detail in [RFC 9180, Section 9.1]. We assume that both
    /// parties have been provisioned with both the PSK value `psk` and
    /// another byte string `psk_id` that is used to identify which PSK
    /// should be used.
    ///
    /// The primary difference from the base case is that the `psk` and `psk_id`
    /// values are used as `ikm` inputs to the KDF (instead of using the empty
    /// string).
    ///
    /// The PSK MUST have at least 32 bytes of entropy and SHOULD be of length
    /// `Nh` bytes or longer. See [RFC 9180, Section 9.5] for a more detailed
    /// discussion.
    ///
    /// ```no_run
    /// def SetupPSKR(enc, skR, info, psk, psk_id):
    ///   shared_secret = Decap(enc, skR)
    ///   return KeyScheduleR(mode_psk, shared_secret, info, psk, psk_id)
    /// ```
    ///
    /// See [RFC 9180, Section 5.1.2] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process, or if the provided PSK does not meet security requirements.
    ///
    /// [RFC 9180, Section 5.1.2]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2
    /// [RFC 9180, Section 9.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1
    /// [RFC 9180, Section 9.5]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.5
    pub fn setup_psk_r(
        &self,
        mut crypto_backend: C,
        enc: EncapsulatedSecretRef<'_>,
        sk_r: HpkePrivateKeyRef<'_>,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Context<C, Recipient>, Error> {
        let shared_secret = kem::decap(&mut crypto_backend, self.cipher_suite.kem_id, enc, sk_r)?;

        self.key_schedule(
            crypto_backend,
            HpkeMode::Psk,
            shared_secret.as_ref(),
            info,
            psk,
            psk_id,
        )
    }

    /// 5.1.3. Authentication Using an Asymmetric Key
    ///
    /// This variant extends the base mechanism by allowing the recipient to
    /// authenticate that the sender possessed a given KEM private key. This is
    /// because `AuthDecap(enc, skR, pkS)` produces the correct KEM shared
    /// secret only if the encapsulated value `enc` was produced by
    /// `AuthEncap(pkR, skS)`, where `skS` is the private key corresponding
    /// to `pkS`. In other words, at most two entities (precisely two, in
    /// the case of DHKEM) could have produced this secret, so if the
    /// recipient is at most one, then the sender is the other with
    /// overwhelming probability.
    ///
    /// The primary difference from the base case is that the calls to `Encap()`
    /// and `Decap()` are replaced with calls to `AuthEncap()` and
    /// `AuthDecap()`, which add the sender public key to their internal
    /// context string. The function parameters `pkR` and `pkS` are public
    /// keys, and `enc` is an encapsulated KEM shared secret.
    ///
    /// Obviously, this variant can only be used with a KEM that provides
    /// `AuthEncap()` and `AuthDecap()` procedures.
    ///
    /// This mechanism authenticates only the key pair of the sender, not any
    /// other identifier. If an application wishes to bind HPKE ciphertexts or
    /// exported secrets to another identity for the sender (e.g., an email
    /// address or domain name), then this identifier should be included in the
    /// info parameter to avoid identity misbinding issues.
    ///
    /// ```no_run
    /// def SetupAuthS(pkR, info, skS):
    ///   shared_secret, enc = AuthEncap(pkR, skS)
    ///   return enc, KeyScheduleS(mode_auth, shared_secret, info,
    ///                            default_psk, default_psk_id)
    /// ```
    ///
    /// See [RFC 9180, Section 5.1.3] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process.
    ///
    /// [RFC 9180, Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
    pub fn setup_auth_s(
        &self,
        mut crypto_backend: C,
        pk_r: HpkePublicKeyRef<'_>,
        info: &[u8],
        sk_s: HpkePrivateKeyRef<'_>,
    ) -> Result<(EncapsulatedSecret, Context<C, Sender>), Error> {
        let (shared_secret, enc) =
            kem::auth_encap(&mut crypto_backend, self.cipher_suite.kem_id, pk_r, sk_s)?;

        let context = self.key_schedule(
            crypto_backend,
            HpkeMode::Auth,
            shared_secret.as_ref(),
            info,
            &[],
            &[],
        )?;

        Ok((enc, context))
    }

    /// 5.1.3. Authentication Using an Asymmetric Key
    ///
    /// This variant extends the base mechanism by allowing the recipient to
    /// authenticate that the sender possessed a given KEM private key. This is
    /// because `AuthDecap(enc, skR, pkS)` produces the correct KEM shared
    /// secret only if the encapsulated value `enc` was produced by
    /// `AuthEncap(pkR, skS)`, where `skS` is the private key corresponding
    /// to `pkS`. In other words, at most two entities (precisely two, in
    /// the case of DHKEM) could have produced this secret, so if the
    /// recipient is at most one, then the sender is the other with
    /// overwhelming probability.
    ///
    /// The primary difference from the base case is that the calls to `Encap()`
    /// and `Decap()` are replaced with calls to `AuthEncap()` and
    /// `AuthDecap()`, which add the sender public key to their internal
    /// context string. The function parameters `pkR` and `pkS` are public
    /// keys, and `enc` is an encapsulated KEM shared secret.
    ///
    /// Obviously, this variant can only be used with a KEM that provides
    /// `AuthEncap()` and `AuthDecap()` procedures.
    ///
    /// This mechanism authenticates only the key pair of the sender, not any
    /// other identifier. If an application wishes to bind HPKE ciphertexts or
    /// exported secrets to another identity for the sender (e.g., an email
    /// address or domain name), then this identifier should be included in the
    /// info parameter to avoid identity misbinding issues.
    ///
    /// ```no_run
    /// def SetupAuthR(enc, skR, info, pkS):
    ///   shared_secret = AuthDecap(enc, skR, pkS)
    ///   return KeyScheduleR(mode_auth, shared_secret, info,
    ///                       default_psk, default_psk_id)
    /// ```
    ///
    /// See [RFC 9180, Section 5.1.3] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process.
    ///
    /// [RFC 9180, Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
    pub fn setup_auth_r(
        &self,
        mut crypto_backend: C,
        enc: EncapsulatedSecretRef<'_>,
        sk_r: HpkePrivateKeyRef<'_>,
        info: &[u8],
        pk_s: HpkePublicKeyRef<'_>,
    ) -> Result<Context<C, Recipient>, Error> {
        let shared_secret = kem::auth_decap(
            &mut crypto_backend,
            self.cipher_suite.kem_id,
            enc,
            sk_r,
            pk_s,
        )?;

        self.key_schedule(
            crypto_backend,
            HpkeMode::Auth,
            shared_secret.as_ref(),
            info,
            &[],
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// 5.1.4. Authentication Using Both a PSK and an Asymmetric Key
    ///
    /// This mode is a straightforward combination of the PSK and authenticated
    /// modes. Like the PSK mode, a PSK is provided as input to the key
    /// schedule, and like the authenticated mode, authenticated KEM variants
    /// are used.
    ///
    /// ```no_run
    /// def SetupAuthPSKS(pkR, info, psk, psk_id, skS):
    ///   shared_secret, enc = AuthEncap(pkR, skS)
    ///   return enc, KeyScheduleS(mode_auth_psk, shared_secret, info,
    ///                            psk, psk_id)
    /// ```
    ///
    /// The PSK MUST have at least 32 bytes of entropy and SHOULD be of length
    /// `Nh` bytes or longer. See [RFC 9180, Section 9.5] for a more detailed
    /// discussion.
    ///
    /// See [RFC 9180, Section 5.1.4] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process, or if the provided PSK does not meet security requirements.
    ///
    /// [RFC 9180, Section 5.1.4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4
    /// [RFC 9180, Section 9.5]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.5
    pub fn setup_auth_psk_s(
        &self,
        mut crypto_backend: C,
        pk_r: HpkePublicKeyRef<'_>,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sk_s: HpkePrivateKeyRef<'_>,
    ) -> Result<(EncapsulatedSecret, Context<C, Sender>), Error> {
        let (shared_secret, enc) =
            kem::auth_encap(&mut crypto_backend, self.cipher_suite.kem_id, pk_r, sk_s)?;

        let context = self.key_schedule(
            crypto_backend,
            HpkeMode::AuthPsk,
            shared_secret.as_ref(),
            info,
            psk,
            psk_id,
        )?;

        Ok((enc, context))
    }

    #[allow(clippy::too_many_arguments)]
    /// 5.1.4. Authentication Using Both a PSK and an Asymmetric Key
    ///
    /// This mode is a straightforward combination of the PSK and authenticated
    /// modes. Like the PSK mode, a PSK is provided as input to the key
    /// schedule, and like the authenticated mode, authenticated KEM variants
    /// are used.
    ///
    /// ```no_run
    /// def SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS):
    ///   shared_secret = AuthDecap(enc, skR, pkS)
    ///   return KeyScheduleR(mode_auth_psk, shared_secret, info,
    ///                       psk, psk_id)
    /// ```
    ///
    /// The PSK MUST have at least 32 bytes of entropy and SHOULD be of length
    /// `Nh` bytes or longer. See [RFC 9180, Section 9.5] for a more detailed
    /// discussion.
    ///
    /// See [RFC 9180, Section 5.1.4] for details.
    ///
    /// # Errors
    ///
    /// Various errors may occur during the key encapsulation or decapsulation
    /// process, or if the provided PSK does not meet security requirements.
    ///
    /// [RFC 9180, Section 5.1.4]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4
    /// [RFC 9180, Section 9.5]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.5
    pub fn setup_auth_psk_r(
        &self,
        mut crypto_backend: C,
        enc: EncapsulatedSecretRef<'_>,
        sk_r: HpkePrivateKeyRef<'_>,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pk_s: HpkePublicKeyRef<'_>,
    ) -> Result<Context<C, Recipient>, Error> {
        let shared_secret = kem::auth_decap(
            &mut crypto_backend,
            self.cipher_suite.kem_id,
            enc,
            sk_r,
            pk_s,
        )?;

        self.key_schedule(
            crypto_backend,
            HpkeMode::AuthPsk,
            shared_secret.as_ref(),
            info,
            psk,
            psk_id,
        )
    }

    #[inline]
    /// ```text
    /// def VerifyPSKInputs(mode, psk, psk_id):
    ///   got_psk = (psk != default_psk)
    ///   got_psk_id = (psk_id != default_psk_id)
    ///   if got_psk != got_psk_id:
    ///     raise Exception("Inconsistent PSK inputs")
    ///
    ///   if got_psk and (mode in [mode_base, mode_auth]):
    ///     raise Exception("PSK input provided when not needed")
    ///   if (not got_psk) and (mode in [mode_psk, mode_auth_psk]):
    ///     raise Exception("Missing required PSK input")
    /// ```
    const fn verify_psk_inputs(mode: HpkeMode, psk: &[u8], psk_id: &[u8]) -> Result<(), Error> {
        let got_psk = !psk.is_empty();
        let got_psk_id = !psk_id.is_empty();

        if got_psk != got_psk_id {
            return Err(Error::InconsistentPsk);
        }

        if got_psk && matches!(mode, HpkeMode::Base | HpkeMode::Auth) {
            return Err(Error::UnnecessaryPsk);
        }

        if !got_psk && matches!(mode, HpkeMode::Psk | HpkeMode::AuthPsk) {
            return Err(Error::MissingPsk);
        }

        // Here different from RFC 9180's definition of `VerifyPSKInputs()`, we
        // also check the PSK length requirement: the PSK MUST have at least 32 bytes of
        // entropy and SHOULD be of length `Nh` bytes or longer. See [RFC 9180,
        // Section 9.5] for a more detailed discussion.
        if matches!(mode, HpkeMode::Psk | HpkeMode::AuthPsk) && psk.len() < 32 {
            return Err(Error::InsecurePsk);
        }

        Ok(())
    }

    /// ```text
    /// def KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id):
    ///   // ...
    ///
    ///   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    ///   info_hash = LabeledExtract("", "info_hash", info)
    ///   key_schedule_context = concat(mode, psk_id_hash, info_hash)
    ///
    ///   // ...
    /// ```
    ///
    /// (Split out mainly for testing purposes.)
    fn key_schedule_context(
        &self,
        crypto_backend: &C,
        mode: HpkeMode,
        info: &[u8],
        psk_id: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
        let psk_id_hash = kdf::labeled_extract(
            crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            &[0],
            "psk_id_hash",
            IkmRef::from(psk_id),
        )?;

        // info_hash = LabeledExtract("", "info_hash", info)
        let info_hash = kdf::labeled_extract(
            crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            &[0],
            "info_hash",
            IkmRef::from(info),
        )?;

        // key_schedule_context = concat(mode, psk_id_hash, info_hash)
        Ok([&[mode as u8], &*psk_id_hash, &*info_hash].concat())
    }

    #[allow(clippy::needless_pass_by_value)]
    /// ```text
    /// def KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id):
    ///   // ...
    ///
    ///   secret = LabeledExtract(shared_secret, "secret", psk)
    ///
    ///   // ...
    /// ```
    ///
    /// (Split out mainly for testing purposes.)
    fn key_schedule_secret(
        &self,
        crypto_backend: &C,
        shared_secret: SharedSecretRef<'_>,
        psk: &[u8],
    ) -> Result<Prk, Error> {
        // secret = LabeledExtract(shared_secret, "secret", psk)
        kdf::labeled_extract(
            crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            &shared_secret,
            "secret",
            IkmRef::from(psk),
        )
        .map_err(Into::into)
    }

    /// ```text
    /// def KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id):
    ///   VerifyPSKInputs(mode, psk, psk_id)
    ///
    ///   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    ///   info_hash = LabeledExtract("", "info_hash", info)
    ///   key_schedule_context = concat(mode, psk_id_hash, info_hash)
    ///
    ///   secret = LabeledExtract(shared_secret, "secret", psk)
    ///
    ///   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    ///   base_nonce = LabeledExpand(secret, "base_nonce",
    ///                              key_schedule_context, Nn)
    ///   exporter_secret = LabeledExpand(secret, "exp",
    ///                                   key_schedule_context, Nh)
    ///
    ///   return Context<ROLE>(key, base_nonce, 0, exporter_secret)
    /// ```
    fn key_schedule<'a, Role>(
        &self,
        crypto_backend: C,
        mode: HpkeMode,
        shared_secret: impl Into<SharedSecretRef<'a>>,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Context<C, Role>, Error> {
        Self::verify_psk_inputs(mode, psk, psk_id)?;

        // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
        // info_hash = LabeledExtract("", "info_hash", info)
        // key_schedule_context = concat(mode, psk_id_hash, info_hash)
        let key_schedule_context =
            self.key_schedule_context(&crypto_backend, mode, info, psk_id)?;

        // secret = LabeledExtract(shared_secret, "secret", psk)
        let secret = self.key_schedule_secret(&crypto_backend, shared_secret.into(), psk)?;

        // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
        let key = kdf::labeled_expand(
            &crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            PrkRef::from(&secret),
            "key",
            &key_schedule_context,
            self.cipher_suite.aead_id.n_key(),
        )?;
        // base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
        let base_nonce = kdf::labeled_expand(
            &crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            PrkRef::from(&secret),
            "base_nonce",
            &key_schedule_context,
            self.cipher_suite.aead_id.n_nonce(),
        )?;
        // exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
        let exporter_secret = kdf::labeled_expand(
            &crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            PrkRef::from(&secret),
            "exp",
            &key_schedule_context,
            self.cipher_suite.kdf_id.n_hash(),
        )?;

        Ok(Context {
            cipher_suite: self.cipher_suite,
            aead: self
                .cipher_suite
                .aead_id
                .new_crypto_info(&key, &base_nonce)
                .expect("Must have valid key and nonce lengths"),
            seq: 0,
            exporter_secret: exporter_secret.to_vec(),
            crypto_backend,
            _role: PhantomData,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The HPKE mode.
///
/// | Mode | Value |
/// |:-:|:-:|
/// | base | 0x00 |
/// | psk  | 0x01 |
/// | auth | 0x02 |
/// | auth_psk | 0x03 |
pub enum HpkeMode {
    /// Base mode.
    Base = 0x00,

    /// PSK mode.
    Psk = 0x01,

    /// Authenticated mode.
    Auth = 0x02,

    /// Authenticated PSK mode.
    AuthPsk = 0x03,
}

impl HpkeMode {
    #[inline]
    /// Try to convert a `u8` into an `HpkeMode`.
    ///
    /// # Errors
    ///
    /// [`UnknownHpkeMode`] if the value does not correspond to a known mode.
    pub const fn try_from(value: u8) -> Result<Self, UnknownHpkeMode> {
        match value {
            v if v == Self::Base as u8 => Ok(Self::Base),
            v if v == Self::Psk as u8 => Ok(Self::Psk),
            v if v == Self::Auth as u8 => Ok(Self::Auth),
            v if v == Self::AuthPsk as u8 => Ok(Self::AuthPsk),
            other => Err(UnknownHpkeMode(other)),
        }
    }
}

impl TryFrom<u8> for HpkeMode {
    type Error = UnknownHpkeMode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from(value)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for HpkeMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for HpkeMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        HpkeMode::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Error indicating an unknown HPKE mode.
pub struct UnknownHpkeMode(pub u8);

impl core::error::Error for UnknownHpkeMode {}

impl fmt::Display for UnknownHpkeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown HPKE mode: {}", self.0)
    }
}

#[derive(Debug)]
/// Marker type for [`Context`] that indicates the `sender` role.
pub struct Sender;

#[derive(Debug)]
/// Marker type for [`Context`] that indicates the `recipient` role.
pub struct Recipient;

/// The HPKE cryptographic context.
///
/// HPKE allows multiple encryption operations to be done based on a given
/// setup transaction. Since the public key operations involved in setup are
/// typically more expensive than symmetric encryption or decryption, this
/// allows applications to amortize the cost of the public key operations,
/// reducing the overall overhead.
///
/// In order to avoid nonce reuse, however, this encryption must be stateful.
/// Each of the setup procedures above produces a role-specific context object
/// that stores the AEAD and secret export parameters. The AEAD parameters
/// consist of:
///
/// - The AEAD algorithm in use
/// - A secret `key`
/// - A base nonce `base_nonce`
/// - A sequence number (initially 0)
///
/// The secret export parameters consist of:
///
/// - The HPKE ciphersuite in use and
/// - An `exporter_secret` used for the secret export interface (see [RFC 9180,
///   Section 5.3])
///
/// Note that the RFC currently doesn't define this.
/// Also see <https://github.com/cfrg/draft-irtf-cfrg-hpke/issues/161>.
///
/// TODO: need pub?
///
/// [RFC 9180, Section 5.3]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3
pub struct Context<C, Role> {
    /// The HPKE `ciphersuite` in use.
    cipher_suite: HpkeCipherSuite,

    /// The AEAD algorithm, secret `key` and `base_nonce`.
    ///
    /// The only way to get `None` here is to use an export-only AEAD,
    aead: Option<HpkeAead>,

    /// The sequence number.
    seq: u32,

    /// The exporter secret.
    exporter_secret: Vec<u8>,

    /// The crypto backend.
    crypto_backend: C,

    /// The role marker.
    _role: PhantomData<Role>,
}

impl<C: Crypto> Context<C, Sender> {
    /// See [`seal_in_place`](Self::seal_in_place).
    ///
    /// # Errors
    ///
    /// See [`seal_in_place`](Self::seal_in_place).
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
        let mut in_out = pt.to_vec();

        self.seal_in_place(aad, &mut in_out)?;

        Ok(in_out)
    }

    /// 5.2. Encryption and Decryption
    ///
    /// Encryption is unidirectional from sender to recipient. The sender's
    /// context can encrypt a plaintext `pt` with associated data `aad` as
    /// follows:
    ///
    /// ```text
    /// def Context.Seal(aad, pt):
    ///   ct = Seal(self.key, self.ComputeNonce(self.seq), aad, pt)
    ///   self.IncrementSeq()
    ///   return ct
    /// ```
    ///
    /// See [RFC 9180, Section 5.2] for details.
    ///
    /// # Errors
    ///
    /// [`CryptoError`], or message limit reached.
    ///
    /// [RFC 9180, Section 5.2]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
    pub fn seal_in_place(&mut self, aad: &[u8], in_out: &mut Vec<u8>) -> Result<(), Error> {
        self.crypto_backend.aead_seal_in_place(
            &self
                .aead
                .as_ref()
                .ok_or(Error::InvalidInput("Export-only AEAD"))?
                .copied_updating_nonce(|base_nonce| {
                    Self::compute_nonce(base_nonce, self.seq);
                }),
            aad,
            in_out,
        )?;

        self.increment_seq()?;

        Ok(())
    }
}

impl<C: Crypto> Context<C, Recipient> {
    /// See [`open_in_place`](Self::open_in_place).
    ///
    /// # Errors
    ///
    /// See [`open_in_place`](Self::open_in_place).
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
        let mut in_out = ct.to_vec();

        self.open_in_place(aad, &mut in_out)?;

        Ok(in_out)
    }

    /// 5.2. Encryption and Decryption
    ///
    /// The recipient's context can decrypt a ciphertext `ct` with associated
    /// data `aad` as follows:
    ///
    /// ```no_run
    /// def Context.Open(aad, ct):
    ///   pt = Open(self.key, self.ComputeNonce(self.seq), aad, ct)
    ///   if pt == OpenError:
    ///     raise OpenError
    ///   self.IncrementSeq()
    ///   return pt
    /// ```
    ///
    /// See [RFC 9180, Section 5.2] for details.
    ///
    /// # Errors
    ///
    /// [`CryptoError`], or message limit reached.
    ///
    /// [RFC 9180, Section 5.2]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
    pub fn open_in_place(&mut self, aad: &[u8], in_out: &mut Vec<u8>) -> Result<(), Error> {
        self.crypto_backend.aead_open_in_place(
            &self
                .aead
                .as_ref()
                .ok_or(Error::InvalidInput("Export-only AEAD"))?
                .copied_updating_nonce(|base_nonce| {
                    Self::compute_nonce(base_nonce, self.seq);
                }),
            aad,
            in_out,
        )?;

        self.increment_seq()?;

        Ok(())
    }
}

impl<C: Crypto, Role> Context<C, Role> {
    /// 5.3. Secret Export
    ///
    /// Takes a serialised exporter context as byte slice and a length for the
    /// output secret and returns an exporter secret as byte vector.
    ///
    /// ```no_run
    /// def Context.Export(exporter_context, L):
    ///   return LabeledExpand(self.exporter_secret, "sec", exporter_context, L)
    /// ```
    ///
    /// See [RFC 9180, Section 5.3] for details.
    ///
    /// # Errors
    ///
    /// See [`kdf::labeled_expand`].
    ///
    /// [RFC 9180, Section 5.3]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Okm, Error> {
        kdf::labeled_expand(
            &self.crypto_backend,
            self.cipher_suite.kdf_id,
            &self.cipher_suite.suite_id(),
            PrkRef::from(self.exporter_secret.as_slice()),
            "sec",
            exporter_context,
            length,
        )
        .map_err(Into::into)
    }

    #[inline]
    /// ```no_run
    /// def Context<ROLE>.ComputeNonce(seq):
    ///   seq_bytes = I2OSP(seq, Nn)
    ///   return xor(self.base_nonce, seq_bytes)
    /// ```
    fn compute_nonce(base_nonce: &mut [u8], seq: u32) {
        // I2OSP: `to_be_bytes` then left padded with zeros to length `Nn`
        // We just XOR the bytes from right to left.
        for (o, i) in base_nonce
            .iter_mut()
            .rev()
            .zip(seq.to_be_bytes().into_iter().rev())
        {
            *o ^= i;
        }
    }

    #[inline]
    /// ```no_run
    /// def Context<ROLE>.IncrementSeq():
    ///   if self.seq >= (1 << (8*Nn)) - 1:
    ///     raise MessageLimitReached
    ///   self.seq += 1
    /// ```
    const fn increment_seq(&mut self) -> Result<(), Error> {
        let nn = self.cipher_suite.aead_id.n_nonce() as u128;

        if self.seq as u128 >= (1 << (8 * nn)) - 1 {
            return Err(Error::MessageLimitReached);
        }

        self.seq += 1;

        Ok(())
    }
}

#[cfg(feature = "test-vectors")]
#[allow(missing_docs)]
pub static HPKE_TEST_VECTORS: std::sync::LazyLock<Vec<HpkeTestVector>> =
    std::sync::LazyLock::new(|| {
        let data = include_str!("../tests/test-vectors.json");

        serde_json::from_str(data).expect("Failed to parse HPKE test vectors")
    });

#[cfg(feature = "test-vectors")]
#[allow(missing_docs)]
#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HpkeTestVector {
    pub mode: HpkeMode,
    pub kem_id: HpkeKemId,
    pub kdf_id: HpkeKdfId,
    pub aead_id: HpkeAeadId,
    pub info: HexString,
    #[serde(rename = "ikmR")]
    pub ikm_r: HexString,
    #[serde(rename = "ikmS")]
    pub ikm_s: Option<HexString>,
    #[serde(rename = "ikmE")]
    pub ikm_e: HexString,
    #[serde(rename = "skRm")]
    pub sk_rm: HexString,
    #[serde(default)]
    #[serde(rename = "skSm")]
    pub sk_sm: Option<HexString>,
    #[serde(rename = "skEm")]
    pub sk_em: HexString,
    pub psk: Option<HexString>,
    pub psk_id: Option<HexString>,
    #[serde(rename = "pkRm")]
    pub pk_rm: HexString,
    #[serde(rename = "pkSm")]
    pub pk_sm: Option<HexString>,
    #[serde(rename = "pkEm")]
    pub pk_em: HexString,
    pub enc: HexString,
    pub shared_secret: HexString,
    pub key_schedule_context: HexString,
    pub secret: HexString,
    pub key: HexString,
    pub base_nonce: HexString,
    pub exporter_secret: HexString,
    pub encryptions: Vec<HpkeTestVectorEncryption>,
    pub exports: Vec<HpkeTestVectorExport>,
}

#[cfg(feature = "test-vectors")]
#[allow(missing_docs)]
#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HpkeTestVectorEncryption {
    pub aad: HexString,
    pub ct: HexString,
    pub nonce: HexString,
    pub pt: HexString,
}

#[cfg(feature = "test-vectors")]
#[allow(missing_docs)]
#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HpkeTestVectorExport {
    pub exporter_context: HexString,
    #[serde(rename = "L")]
    pub l: usize,
    pub exported_value: HexString,
}

#[cfg(feature = "test-vectors")]
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct HexString {
    pub bytes: Vec<u8>,
}

#[cfg(feature = "test-vectors")]
impl serde::Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&const_hex::encode(&self.bytes))
    }
}

#[cfg(feature = "test-vectors")]
impl<'de> serde::Deserialize<'de> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = <&str>::deserialize(deserializer)?;
        let bytes = const_hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        Ok(HexString { bytes })
    }
}

#[cfg(feature = "test-vectors")]
impl core::ops::Deref for HexString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[cfg(test)]
mod kat_tests {
    use alloc::format;
    use alloc::vec::Vec;
    use core::panic::UnwindSafe;
    use std::panic::catch_unwind;
    use std::println;

    use super::*;

    #[test_case::test_matrix(
        [
            hpke_crypto::backend::HpkeCryptoAwsLcRs::new,
            hpke_crypto::backend::HpkeCryptoGraviola::new,
            hpke_crypto::backend::HpkeCryptoRing::new,
            hpke_crypto::backend::HpkeCryptoRustCrypto::new
        ]
    )]
    fn test_setup<C, F>(crypto_backend: F)
    where
        C: Crypto + Send + Sync + UnwindSafe,
        F: Fn() -> Result<C, CryptoError> + UnwindSafe + Copy,
    {
        let mut rets = Vec::new();

        for (idx, test_case) in HPKE_TEST_VECTORS.iter().enumerate() {
            let ret = catch_unwind(move || {
                test_setup_each(
                    crypto_backend,
                    idx,
                    Hpke::prepare(HpkeCipherSuite {
                        kem_id: test_case.kem_id,
                        kdf_id: test_case.kdf_id,
                        aead_id: test_case.aead_id,
                    }),
                    test_case.mode,
                    &test_case.pk_rm,
                    &test_case.info,
                    test_case.psk.as_deref(),
                    test_case.psk_id.as_deref(),
                    test_case.sk_sm.as_deref(),
                    &test_case.sk_rm,
                    test_case.pk_sm.as_deref(),
                );
            });

            rets.push((format!("{}({})", test_case.kdf_id, idx), ret));
        }

        let errors: Vec<_> = rets
            .iter()
            .filter(|(_, ret)| ret.is_err())
            .collect();

        if !errors.is_empty() {
            for (name, err) in &errors {
                println!("[FAILED] {name}: {err:?}");
            }

            panic!("{} test cases failed", errors.len());
        } else {
            println!("[OK] all {} test cases passed", rets.len());
        }
    }

    fn test_setup_each<C: Crypto, F: Fn() -> Result<C, CryptoError>>(
        crypto_backend_f: F,
        idx: usize,
        hpke: Hpke<C>,
        mode: HpkeMode,
        pk_r: &[u8],
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        sk_s: Option<&[u8]>,
        sk_r: &[u8],
        pk_s: Option<&[u8]>,
    ) {
        let crypto_backend = crypto_backend_f().unwrap();

        if !crypto_backend.is_kem_supported(&hpke.cipher_suite.kem_id) {
            // Skip unsupported KEMs.
            println!(
                "[{name}][{idx}] Skipping, unsupported KEM {alg:?}",
                name = core::any::type_name::<C>(),
                alg = hpke.cipher_suite.kem_id
            );
            return;
        }

        if !crypto_backend.is_kdf_supported(&hpke.cipher_suite.kdf_id) {
            // Skip unsupported KDFs.
            println!(
                "[{name}][{idx}] Skipping, unsupported KDF {alg:?}",
                name = core::any::type_name::<C>(),
                alg = hpke.cipher_suite.kdf_id
            );
            return;
        }

        let (enc_s, ctx_s) = hpke
            .setup_s(
                crypto_backend,
                mode,
                HpkePublicKeyRef::from(pk_r),
                info,
                psk,
                psk_id,
                sk_s.map(HpkePrivateKeyRef::from),
            )
            .unwrap_or_else(|e| {
                panic!("Failed to setup sender context: {e:?}, idx={idx}");
            });

        let crypto_backend = crypto_backend_f().unwrap();

        let ctx_r = hpke
            .setup_r(
                crypto_backend,
                mode,
                EncapsulatedSecretRef::from(&enc_s),
                HpkePrivateKeyRef::from(sk_r),
                info,
                psk,
                psk_id,
                pk_s.map(HpkePublicKeyRef::from),
            )
            .unwrap_or_else(|e| {
                panic!("Failed to setup recipient context: {e:?}, idx={idx}");
            });

        assert_eq!(
            ctx_s.exporter_secret, ctx_r.exporter_secret,
            "Exporter secret mismatch"
        );
    }

    #[test_case::test_matrix(
        [
            hpke_crypto::backend::HpkeCryptoAwsLcRs::new,
            hpke_crypto::backend::HpkeCryptoGraviola::new,
            hpke_crypto::backend::HpkeCryptoRing::new,
            hpke_crypto::backend::HpkeCryptoRustCrypto::new
        ]
    )]
    fn test_key_schedule<C: Crypto + Send + Sync + UnwindSafe, F>(crypto_backend: F)
    where
        F: Fn() -> Result<C, CryptoError>,
    {
        let mut rets = Vec::new();

        for (idx, test_case) in HPKE_TEST_VECTORS.iter().enumerate() {
            let crypto_backend = crypto_backend().unwrap();

            let ret = catch_unwind(move || {
                test_key_schedule_each(
                    crypto_backend,
                    idx,
                    "GENERIC",
                    Hpke::prepare(HpkeCipherSuite {
                        kem_id: test_case.kem_id,
                        kdf_id: test_case.kdf_id,
                        aead_id: test_case.aead_id,
                    }),
                    test_case.mode,
                    &test_case.info,
                    test_case
                        .psk
                        .as_deref()
                        .unwrap_or_default(),
                    test_case
                        .psk_id
                        .as_deref()
                        .unwrap_or_default(),
                    &test_case.shared_secret,
                    test_case.aead_id,
                    &test_case.key_schedule_context,
                    &test_case.secret,
                    &test_case.key,
                    &test_case.base_nonce,
                    &test_case.exporter_secret,
                );
            });

            rets.push((format!("{}({})", test_case.kdf_id, idx), ret));
        }

        let errors: Vec<_> = rets
            .iter()
            .filter(|(_, ret)| ret.is_err())
            .collect();

        if !errors.is_empty() {
            for (name, err) in &errors {
                println!("[FAILED] {name}: {err:?}");
            }

            panic!("{} test cases failed", errors.len());
        } else {
            println!("[OK] all {} test cases passed", rets.len());
        }
    }

    fn test_key_schedule_each<C: Crypto>(
        crypto_backend: C,
        idx: usize,
        role: &'static str,
        hpke: Hpke<C>,
        mode: HpkeMode,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        shared_secret: &[u8],
        aead_id: HpkeAeadId,
        expected_key_schedule_context: &[u8],
        expected_secret: &[u8],
        expected_key: &[u8],
        expected_base_nonce: &[u8],
        expected_exporter_secret: &[u8],
    ) {
        if !crypto_backend.is_kdf_supported(&hpke.cipher_suite.kdf_id) {
            // Skip unsupported KDFs.
            println!(
                "[{name}][{idx}][{role}] Skipping, unsupported KDF {alg:?}",
                name = core::any::type_name::<C>(),
                alg = hpke.cipher_suite.kdf_id
            );
            return;
        }

        // Testing key schedule context manually here.
        {
            let key_schedule_context = hpke
                .key_schedule_context(&crypto_backend, mode, info, psk_id)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to create key schedule context: {e:?}, mode={mode:?}, \
                         info={info:?}, psk_id={psk_id:?}",
                    );
                });

            assert_eq!(
                key_schedule_context, expected_key_schedule_context,
                "Key schedule context mismatch"
            );
        }

        // Testing key schedule secret manually here.
        {
            let secret = hpke
                .key_schedule_secret(&crypto_backend, SharedSecretRef::from(&shared_secret), psk)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to create key schedule secret: {e:?}, mode={mode:?}, \
                         shared_secret={shared_secret:?}, psk={psk:?}",
                    );
                });

            assert_eq!(&*secret, expected_secret, "Key schedule secret mismatch");
        }

        // Testing key schedule here.
        {
            let context = hpke
                .key_schedule::<Sender>(
                    crypto_backend,
                    mode,
                    SharedSecretRef::from(shared_secret),
                    &info,
                    psk,
                    psk_id,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to create context: {e:?}, mode={mode:?}, \
                         shared_secret={shared_secret:?}, \
                         key_schedule_context:{expected_key_schedule_context:?}, info={info:?}, \
                         psk={psk:?}, psk_id={psk_id:?}",
                    );
                });

            // Note that key and nonce are empty for exporter only key derivation.
            if matches!(aead_id, HpkeAeadId::EXPORT_ONLY) {
                assert!(
                    context.aead.is_none(),
                    "AEAD key / nonce should be None for EXPORT_ONLY"
                );
            } else {
                assert_eq!(
                    context.aead.as_ref().unwrap().key(),
                    expected_key,
                    "AEAD key mismatch"
                );
                assert_eq!(
                    context.aead.as_ref().unwrap().nonce(),
                    expected_base_nonce,
                    "AEAD base nonce mismatch"
                );
            }
            assert_eq!(
                context.seq, 0,
                "Initial sequence number must be 0 when initialized"
            );
            assert_eq!(
                context.exporter_secret, expected_exporter_secret,
                "Exporter secret mismatch"
            );
        };
    }

    #[test_case::test_matrix(
        [
            hpke_crypto::backend::HpkeCryptoAwsLcRs::new,
            hpke_crypto::backend::HpkeCryptoGraviola::new,
            hpke_crypto::backend::HpkeCryptoRing::new,
            hpke_crypto::backend::HpkeCryptoRustCrypto::new
        ]
    )]
    fn test_encryption<C: Crypto + Send + Sync + UnwindSafe, F>(crypto_backend: F)
    where
        F: Fn() -> Result<C, CryptoError>,
    {
        let mut rets = Vec::new();

        for (idx, test_case) in HPKE_TEST_VECTORS.iter().enumerate() {
            for (enc_idx, enc) in test_case.encryptions.iter().enumerate() {
                let crypto_backend = crypto_backend().unwrap();

                let context = Context {
                    cipher_suite: HpkeCipherSuite {
                        kem_id: test_case.kem_id,
                        kdf_id: test_case.kdf_id,
                        aead_id: test_case.aead_id,
                    },
                    aead: test_case
                        .aead_id
                        .new_crypto_info(&test_case.key, &test_case.base_nonce)
                        .expect("Must have valid key and nonce lengths"),
                    seq: 0,
                    exporter_secret: test_case.exporter_secret.bytes.clone(),
                    crypto_backend,
                    _role: PhantomData,
                };

                let ret = catch_unwind(move || {
                    test_encryption_each(context, enc_idx as u32, &enc.aad, &enc.pt, &enc.ct);
                });

                rets.push((format!("{}({})[{}]", test_case.kdf_id, idx, enc_idx), ret));
            }
        }

        let errors: Vec<_> = rets
            .iter()
            .filter(|(_, ret)| ret.is_err())
            .collect();

        if !errors.is_empty() {
            for (name, err) in &errors {
                println!("[FAILED] {name}: {err:?}");
            }

            panic!("{} test cases failed", errors.len());
        } else {
            println!("[OK] all {} test cases passed", rets.len());
        }
    }

    fn test_encryption_each<C: Crypto>(
        mut context: Context<C, Sender>,
        seq: u32,
        aad: &[u8],
        pt: &[u8],
        expected_ct: &[u8],
    ) {
        context.seq = seq;

        let ct = context
            .seal(aad, pt)
            .unwrap_or_else(|e| {
                panic!("Failed to encrypt: {e:?}, seq={seq}, aad={aad:?}, pt={pt:?}",);
            });

        assert_eq!(ct, expected_ct, "Ciphertext mismatch");

        // Decrypt and verify.
        let mut context = Context {
            cipher_suite: context.cipher_suite,
            aead: context.aead,
            seq,
            exporter_secret: context.exporter_secret,
            crypto_backend: context.crypto_backend,
            _role: PhantomData::<Recipient>,
        };

        let pt2 = context
            .open(aad, &ct)
            .unwrap_or_else(|e| {
                panic!("Failed to decrypt: {e:?}, seq={seq}, aad={aad:?}, ct={ct:?}");
            });

        assert_eq!(pt2, pt, "Decrypted plaintext mismatch");
    }

    #[test_case::test_matrix(
        [
            hpke_crypto::backend::HpkeCryptoAwsLcRs::new,
            hpke_crypto::backend::HpkeCryptoGraviola::new,
            hpke_crypto::backend::HpkeCryptoRing::new,
            hpke_crypto::backend::HpkeCryptoRustCrypto::new
        ]
    )]
    fn test_exported_values<C: Crypto + Send + Sync + UnwindSafe, F>(crypto_backend: F)
    where
        F: Fn() -> Result<C, CryptoError>,
    {
        let mut rets = Vec::new();

        for (idx, test_case) in HPKE_TEST_VECTORS.iter().enumerate() {
            for (enc_idx, enc) in test_case.exports.iter().enumerate() {
                let crypto_backend = crypto_backend().unwrap();

                let context = Context {
                    cipher_suite: HpkeCipherSuite {
                        kem_id: test_case.kem_id,
                        kdf_id: test_case.kdf_id,
                        aead_id: test_case.aead_id,
                    },
                    aead: None,
                    seq: 0,
                    exporter_secret: test_case.exporter_secret.bytes.clone(),
                    crypto_backend,
                    _role: PhantomData,
                };

                let ret = catch_unwind(move || {
                    test_exported_values_each(
                        context,
                        &enc.exporter_context,
                        enc.l,
                        &enc.exported_value,
                    );
                });

                rets.push((format!("{}({})[{}]", test_case.kdf_id, idx, enc_idx), ret));
            }
        }

        let errors: Vec<_> = rets
            .iter()
            .filter(|(_, ret)| ret.is_err())
            .collect();

        if !errors.is_empty() {
            for (name, err) in &errors {
                println!("[FAILED] {name}: {err:?}");
            }

            panic!("{} test cases failed", errors.len());
        } else {
            println!("[OK] all {} test cases passed", rets.len());
        }
    }

    fn test_exported_values_each<C: Crypto>(
        context: Context<C, Sender>,
        exporter_context: &[u8],
        l: usize,
        expected_exported_value: &[u8],
    ) {
        let exported_value = context
            .export(exporter_context, l)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to export secret: {e:?}, exporter_context={exporter_context:?}, l={l}",
                );
            });

        assert_eq!(
            &*exported_value, expected_exported_value,
            "Exported value mismatch"
        );
    }
}
