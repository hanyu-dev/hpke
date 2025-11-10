//! Testing KDF_* implementations

use hpke_crypto::{Crypto, HpkeKdfId, IkmRef};

#[test_case::test_matrix(
    [
        hpke_crypto::backend::HpkeCryptoAwsLcRs::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRing::new().unwrap(),
        hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap()
    ],
    [
        HpkeKdfId::HKDF_SHA256,
    ]
)]
fn test_labeled_kdf(backend: impl Crypto, alg: HpkeKdfId) {
    let ikm = b"this is a test ikm";
    let salt = b"this is a test salt";

    const EXTRACTED: [u8; 32] = [
        51, 90, 124, 250, 223, 212, 90, 155, 82, 26, 65, 30, 3, 210, 229, 102, 163, 106, 106, 121,
        231, 231, 56, 188, 39, 100, 37, 209, 70, 228, 83, 250,
    ];

    let suite_id = [72, 80, 75, 69, 0, 16, 0, 1, 0, 3];

    let prk = hpke_crypto::kdf::labeled_extract(
        &backend,
        alg,
        &suite_id,
        salt,
        "test",
        IkmRef::from(ikm),
    )
    .unwrap();

    assert_eq!(&*prk, &EXTRACTED);

    let info = b"this is a test info";

    const EXPANDED: [u8; 32] = [
        63, 207, 115, 124, 12, 164, 30, 132, 185, 94, 137, 158, 214, 7, 90, 86, 149, 155, 221, 250,
        124, 84, 206, 239, 213, 34, 141, 43, 157, 156, 197, 224,
    ];

    let okm = hpke_crypto::kdf::labeled_expand(
        &backend,
        alg,
        &suite_id,
        prk.as_ref(),
        "test",
        info,
        32,
    )
    .unwrap();

    assert_eq!(&*okm, &EXPANDED);
}

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
    [
        HpkeKdfId::HKDF_SHA256,
        HpkeKdfId::HKDF_SHA384,
        HpkeKdfId::HKDF_SHA512,
    ]
)]
fn test_kdf_cross(mut backend_1: impl Crypto, mut backend_2: impl Crypto, alg: HpkeKdfId) {
    let mut salt = [0; 32];
    backend_1
        .secure_random_fill(&mut salt[..16])
        .unwrap();
    backend_2
        .secure_random_fill(&mut salt[16..])
        .unwrap();

    let mut ikm = [0; 128];
    backend_1
        .secure_random_fill(&mut ikm[..64])
        .unwrap();
    backend_2
        .secure_random_fill(&mut ikm[64..])
        .unwrap();

    let prk_1 = backend_1
        .kdf_extract(alg, &salt, IkmRef::from(&ikm))
        .unwrap();

    let prk_2 = backend_1
        .kdf_extract_concated(alg, &salt, &[IkmRef::from(&ikm)])
        .unwrap();

    let prk_3 = backend_1
        .kdf_extract_concated(
            alg,
            &salt,
            &[IkmRef::from(&ikm[..32]), IkmRef::from(&ikm[32..])],
        )
        .unwrap();

    let prk_4 = backend_2
        .kdf_extract(alg, &salt, IkmRef::from(&ikm))
        .unwrap();

    let prk_5 = backend_2
        .kdf_extract_concated(alg, &salt, &[IkmRef::from(&ikm)])
        .unwrap();

    let prk_6 = backend_2
        .kdf_extract_concated(
            alg,
            &salt,
            &[IkmRef::from(&ikm[..32]), IkmRef::from(&ikm[32..])],
        )
        .unwrap();

    assert_eq!(prk_1, prk_2);
    assert_eq!(prk_1, prk_3);
    assert_eq!(prk_1, prk_4);
    assert_eq!(prk_1, prk_5);
    assert_eq!(prk_1, prk_6);

    {
        let mut info = [0; 32];
        backend_1
            .secure_random_fill(&mut info[..16])
            .unwrap();
        backend_2
            .secure_random_fill(&mut info[16..])
            .unwrap();

        let okm_1 = backend_1
            .kdf_expand(alg, (&prk_1).into(), &info, alg.n_hash())
            .unwrap();
        let okm_2 = backend_2
            .kdf_expand(alg, (&prk_2).into(), &info, alg.n_hash())
            .unwrap();

        assert_eq!(okm_1, okm_2);
    }

    {
        let mut info = [0; 64];
        backend_1
            .secure_random_fill(&mut info[..32])
            .unwrap();
        backend_2
            .secure_random_fill(&mut info[32..])
            .unwrap();

        let okm_1 = backend_1
            .kdf_expand_multi_info(
                alg,
                (&prk_1).into(),
                &[&info[..16], &info[16..]],
                alg.n_hash(),
            )
            .unwrap();
        let okm_2 = backend_2
            .kdf_expand_multi_info(
                alg,
                (&prk_2).into(),
                &[&info[..16], &info[16..]],
                alg.n_hash(),
            )
            .unwrap();

        assert_eq!(okm_1, okm_2);
    }
}

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
    [
        HpkeKdfId::HKDF_SHA256,
        HpkeKdfId::HKDF_SHA384,
        HpkeKdfId::HKDF_SHA512,
    ]
)]
fn test_labeled_kdf_cross(mut backend_1: impl Crypto, mut backend_2: impl Crypto, alg: HpkeKdfId) {
    let mut salt = [0; 32];
    backend_1
        .secure_random_fill(&mut salt[..16])
        .unwrap();
    backend_2
        .secure_random_fill(&mut salt[16..])
        .unwrap();

    let mut ikm = [0; 128];
    backend_1
        .secure_random_fill(&mut ikm[..64])
        .unwrap();
    backend_2
        .secure_random_fill(&mut ikm[64..])
        .unwrap();

    let suite_id = "test suite".as_bytes();

    let prk_1 = hpke_crypto::kdf::labeled_extract(
        &backend_1,
        alg,
        &suite_id,
        &salt,
        "test",
        IkmRef::from(&ikm),
    )
    .unwrap();

    let prk_2 = hpke_crypto::kdf::labeled_extract(
        &backend_1,
        alg,
        &suite_id,
        &salt,
        "test",
        IkmRef::from(&ikm),
    )
    .unwrap();

    let prk_3 = hpke_crypto::kdf::labeled_extract(
        &backend_2,
        alg,
        &suite_id,
        &salt,
        "test",
        IkmRef::from(&ikm),
    )
    .unwrap();

    assert_eq!(prk_1, prk_2);
    assert_eq!(prk_1, prk_3);

    {
        let mut info = [0; 32];
        backend_1
            .secure_random_fill(&mut info[..16])
            .unwrap();
        backend_2
            .secure_random_fill(&mut info[16..])
            .unwrap();

        let okm_1 = hpke_crypto::kdf::labeled_expand(
            &backend_1,
            alg,
            &suite_id,
            prk_1.as_ref(),
            "test",
            &info,
            alg.n_hash(),
        )
        .unwrap();
        let okm_2 = hpke_crypto::kdf::labeled_expand(
            &backend_2,
            alg,
            &suite_id,
            prk_2.as_ref(),
            "test",
            &info,
            alg.n_hash(),
        )
        .unwrap();

        assert_eq!(okm_1, okm_2);
    }
}
