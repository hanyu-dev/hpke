//! Smoke tests for reatls-hpke crate

#![allow(non_snake_case)]

use reatls_hpke::*;

#[test_case::test_matrix(
    [
        reatls_hpke_crypto::backend::HpkeCryptoAwsLcRs::new,
        reatls_hpke_crypto::backend::HpkeCryptoGraviola::new,
        reatls_hpke_crypto::backend::HpkeCryptoRing::new,
        reatls_hpke_crypto::backend::HpkeCryptoRustCrypto::new
    ],
    [
        HpkeMode::Base,
        HpkeMode::Auth,
        HpkeMode::Psk,
        HpkeMode::AuthPsk
    ],
    [
        HpkeKemId::DHKEM_P256_HKDF_SHA256,
        HpkeKemId::DHKEM_P384_HKDF_SHA384,
        HpkeKemId::DHKEM_P521_HKDF_SHA512,
        HpkeKemId::DHKEM_X25519_HKDF_SHA256,
        HpkeKemId::DHKEM_X448_HKDF_SHA512
    ],
    [
        HpkeKdfId::HKDF_SHA256,
        HpkeKdfId::HKDF_SHA384,
        HpkeKdfId::HKDF_SHA512,
    ],
    [
        HpkeAeadId::AES_128_GCM,
        HpkeAeadId::AES_256_GCM,
        HpkeAeadId::CHACHA20_POLY1305
    ]
)]
fn smoking<C, F>(
    crypto_backend_f: F,
    mode: HpkeMode,
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
) where
    C: Crypto,
    F: Fn() -> Result<C, CryptoError> + Copy,
{
    let hpke = Hpke::<C>::prepare(HpkeCipherSuite {
        kem_id,
        kdf_id,
        aead_id,
    });

    let mut crypto_backend_general = crypto_backend_f().unwrap();
    let mut crypto_backend_s = crypto_backend_f().unwrap();
    let mut crypto_backend_r = crypto_backend_f().unwrap();

    if !crypto_backend_general.is_kem_supported(&kem_id) {
        eprintln!(
            "skipping unsupported cipher suite: mode={mode:?}, kem={kem_id:?}, kdf={kdf_id:?}, \
             aead={aead_id:?}"
        );
        return;
    }

    let (sk_r, pk_r) = kem::generate_key_pair(&mut crypto_backend_r, kem_id).unwrap();
    let (sk_s, pk_s) = kem::generate_key_pair(&mut crypto_backend_s, kem_id).unwrap();
    let mut psk = [0u8; 32];
    crypto_backend_general
        .secure_random_fill(&mut psk)
        .expect("RNG failure");
    let mut psk_id = [0u8; 32];
    crypto_backend_general
        .secure_random_fill(&mut psk_id)
        .expect("RNG failure");

    if !crypto_backend_general.is_kdf_supported(&kdf_id) {
        eprintln!(
            "skipping unsupported cipher suite: mode={mode:?}, kem={kem_id:?}, kdf={kdf_id:?}, \
             aead={aead_id:?}"
        );
        return;
    }

    let info = b"HPKE self test info";
    let (mut ctx_s, mut ctx_r) = match mode {
        HpkeMode::Base => {
            let (enc, ctx_s) = hpke
                .setup_base_s(crypto_backend_s, (&pk_r).into(), info)
                .expect("setup_base_s failure");
            let ctx_r = hpke
                .setup_base_r(crypto_backend_r, (&enc).into(), (&sk_r).into(), info)
                .expect("setup_base_r failure");

            (ctx_s, ctx_r)
        }
        HpkeMode::Psk => {
            let (enc, ctx_s) = hpke
                .setup_psk_s(crypto_backend_s, (&pk_r).into(), info, &psk, &psk_id)
                .expect("setup_psk_s failure");
            let ctx_r = hpke
                .setup_psk_r(
                    crypto_backend_r,
                    (&enc).into(),
                    (&sk_r).into(),
                    info,
                    &psk,
                    &psk_id,
                )
                .expect("setup_psk_r failure");

            (ctx_s, ctx_r)
        }
        HpkeMode::Auth => {
            let (enc, ctx_s) = hpke
                .setup_auth_s(crypto_backend_s, (&pk_r).into(), info, (&sk_s).into())
                .expect("setup_auth_s failure");
            let ctx_r = hpke
                .setup_auth_r(
                    crypto_backend_r,
                    (&enc).into(),
                    (&sk_r).into(),
                    info,
                    (&pk_s).into(),
                )
                .expect("setup_auth_r failure");

            (ctx_s, ctx_r)
        }
        HpkeMode::AuthPsk => {
            let (enc, ctx_s) = hpke
                .setup_auth_psk_s(
                    crypto_backend_s,
                    (&pk_r).into(),
                    info,
                    &psk,
                    &psk_id,
                    (&sk_s).into(),
                )
                .expect("setup_auth_psk_s failure");
            let ctx_r = hpke
                .setup_auth_psk_r(
                    crypto_backend_r,
                    (&enc).into(),
                    (&sk_r).into(),
                    info,
                    &psk,
                    &psk_id,
                    (&pk_s).into(),
                )
                .expect("setup_auth_psk_r failure");

            (ctx_s, ctx_r)
        }
    };

    if !crypto_backend_general.is_aead_supported(&aead_id) {
        eprintln!(
            "skipping unsupported cipher suite: mode={mode:?}, kem={kem_id:?}, kdf={kdf_id:?}, \
             aead={aead_id:?}"
        );
        return;
    }

    if !matches!(aead_id, HpkeAeadId::EXPORT_ONLY) {
        let aad = b"HPKE self test aad";
        let pt = b"HPKE self test plain text";

        let ct = ctx_s
            .seal(aad, pt)
            .expect("seal failure");

        let pt_decrypted = ctx_r
            .open(aad, &ct)
            .expect("open failure");

        assert_eq!(pt_decrypted, pt);
    }

    let exporter_context = b"HPKE self test exporter context";
    assert_eq!(
        ctx_s
            .export(exporter_context, 32)
            .expect("ctx_s export failure"),
        ctx_r
            .export(exporter_context, 32)
            .expect("ctx_r export failure"),
        "export failure, ctx_s and ctx_r exports different values"
    );
}
