# HPKE

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL%202.0-blue.svg)](LICENSE-MPL)

This is originally a fork of [hpke-rs](https://crates.io/crates/hpke-rs) and heavily modified.

- `hpke-core`: HPKE core functionality.

  [![Crates.io](https://img.shields.io/crates/v/hpke-core)](https://crates.io/crates/hpke-core)
  [![Docs.rs](https://docs.rs/hpke-core/badge.svg)](https://docs.rs/hpke-core)

- `hpke-crypto`: cryptographic backend implementations for HPKE.

  [![Crates.io](https://img.shields.io/crates/v/hpke-crypto)](https://crates.io/crates/hpke-crypto)
  [![Docs.rs](https://docs.rs/hpke-crypto/badge.svg)](https://docs.rs/hpke-crypto)

  Currently supports the following:

  - `backend-ring`: uses [ring](https://crates.io/crates/ring) as the cryptographic backend.
  - `backend-aws-lc-rs`: uses [aws-lc-rs](https://crates.io/crates/aws-lc-rs) as the cryptographic backend.
  - `backend-graviola`: uses [graviola](https://crates.io/crates/graviola) as the cryptographic backend.
  - `backend-rustcrypto`: uses crates from `RustCrypto` as the cryptographic backend.

## License

Licensed under [MPL-2.0](./LICENSE-MPL) license.
