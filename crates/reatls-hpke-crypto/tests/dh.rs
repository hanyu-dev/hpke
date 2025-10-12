//! Testing DH implementations
//!
//! TODO: fuzz these tests

use reatls_hpke_crypto::{Crypto, HpkeKemId};

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
    [HpkeKemId::DHKEM_X25519_HKDF_SHA256]
)]
#[test_case::test_matrix(
    [
        reatls_hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap(),
    ],
    [
        reatls_hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        reatls_hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap(),
    ],
    [HpkeKemId::DHKEM_P256_HKDF_SHA256, HpkeKemId::DHKEM_P384_HKDF_SHA384]
)]
fn test_dh(mut backend_1: impl Crypto, mut backend_2: impl Crypto, alg: HpkeKemId) {
    let key_pair_1 = backend_1
        .kem_generate_key_pair(alg)
        .unwrap();
    let key_pair_2 = backend_2
        .kem_generate_key_pair(alg)
        .unwrap();

    let dh1 = backend_1
        .dh(alg, key_pair_1.sk(), key_pair_2.pk())
        .unwrap();
    let dh2 = backend_2
        .dh(alg, key_pair_2.sk(), key_pair_1.pk())
        .unwrap();

    assert_eq!(dh1, dh2);
}
