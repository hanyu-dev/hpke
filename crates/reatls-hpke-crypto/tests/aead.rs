//! Testing AEAD_* implementations
//!
//! TODO: fuzz these tests

use reatls_hpke_crypto::{Crypto, HpkeAead};

const AES_128_KEY: [u8; 16] = [
    0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9,
];
const AES_256_KEY: [u8; 32] = [
    0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9,
    0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9,
];
const CHACHA20_POLY1305_KEY: [u8; 32] = [
    0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9,
    0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9,
];
const NONCE: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

#[test_case::test_matrix(
    [
        reatls_hpke_crypto::backend::HpkeCryptoAwsLcRs::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoRing::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap()
    ],
    [
        reatls_hpke_crypto::backend::HpkeCryptoAwsLcRs::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoRing::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap()
    ],
    [
        HpkeAead::Aes128Gcm { key: AES_128_KEY, nonce: NONCE },
        HpkeAead::Aes256Gcm { key: AES_256_KEY, nonce: NONCE },
        HpkeAead::ChaCha20Poly1305 { key: CHACHA20_POLY1305_KEY, nonce: NONCE },
    ]
)]
fn test_aead(backend_1: impl Crypto, backend_2: impl Crypto, crypto_info: HpkeAead) {
    let aad = [0x03, 0x04, 0x05];
    let plaintext = b"test message";

    let backend_1_ct = backend_1
        .aead_seal(&crypto_info, &aad, plaintext)
        .unwrap();

    let backend_2_ct = backend_2
        .aead_seal(&crypto_info, &aad, plaintext)
        .unwrap();

    assert_eq!(backend_1_ct, backend_2_ct);

    assert_eq!(
        &backend_1
            .aead_open(&crypto_info, &aad, &backend_1_ct)
            .unwrap(),
        plaintext
    );

    assert_eq!(
        &backend_2
            .aead_open(&crypto_info, &aad, &backend_2_ct)
            .unwrap(),
        plaintext
    );
}
