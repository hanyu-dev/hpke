//! Testing secure_random_fill implementations

use reatls_hpke_crypto::Crypto;

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
    ]
)]
fn test_secure_random_fill(mut backend_1: impl Crypto, mut backend_2: impl Crypto) {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    backend_1
        .secure_random_fill(&mut buf1)
        .unwrap();
    backend_2
        .secure_random_fill(&mut buf2)
        .unwrap();

    // It's possible (though extremely unlikely) that the two buffers are equal.
    assert_ne!(buf1, buf2);
}
