//! Implementations of [`Crypto`].

#[cfg(feature = "backend-aws-lc-rs")]
pub mod aws_lc_rs;
#[cfg(feature = "backend-graviola")]
pub mod graviola;
#[cfg(feature = "backend-ring")]
pub mod ring;
#[cfg(feature = "backend-rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "backend-aws-lc-rs")]
pub use self::aws_lc_rs::HpkeCrypto as HpkeCryptoAwsLcRs;
#[cfg(feature = "backend-graviola")]
pub use self::graviola::HpkeCrypto as HpkeCryptoGraviola;
#[cfg(feature = "backend-ring")]
pub use self::ring::HpkeCrypto as HpkeCryptoRing;
#[cfg(feature = "backend-rustcrypto")]
pub use self::rustcrypto::HpkeCrypto as HpkeCryptoRustCrypto;
