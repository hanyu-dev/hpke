//! Testing KEM_* implementations

use hpke_crypto::{Crypto, HpkeKemId};

#[test_case::test_matrix(
    [
        hpke_crypto::backend::HpkeCryptoAwsLcRs::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRing::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap()
    ],
    [
        hpke_crypto::backend::HpkeCryptoAwsLcRs::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRing::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap()
    ],
    [HpkeKemId::DHKEM_X25519_HKDF_SHA256]
)]
#[test_case::test_matrix(
    [
        hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap()
    ],
    [
        hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap(),
    ],
    [HpkeKemId::DHKEM_P256_HKDF_SHA256, HpkeKemId::DHKEM_P384_HKDF_SHA384]
)]
fn test_kem_generate_key_pair(
    mut backend_1: impl Crypto,
    mut backend_2: impl Crypto,
    alg: HpkeKemId,
) {
    let key_pair_1 = backend_1
        .kem_generate_key_pair(alg)
        .unwrap();
    let derived_pk = backend_2
        .pk(alg, key_pair_1.sk())
        .unwrap();
    assert_eq!(key_pair_1.pk().as_ref(), &derived_pk[..]);

    let key_pair_2 = backend_2
        .kem_generate_key_pair(alg)
        .unwrap();
    let derived_pk = backend_1
        .pk(alg, key_pair_2.sk())
        .unwrap();
    assert_eq!(key_pair_2.pk().as_ref(), &derived_pk[..]);
}
