//! [`Crypto`] primitives implementation using [`aws_lc_rs`].
//!
//! Requires the `backend-aws-lc-rs` feature.
//!
//! # Supported
//!
//! | KEM | Supported |
//! |:-:|:-:|
//! | DHKEM_P256_HKDF_SHA256 | ⚠️ |
//! | DHKEM_P384_HKDF_SHA384 | ⚠️ |
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

use aws_lc_rs::{self as ring_like};

include!("ring_like.rs");
