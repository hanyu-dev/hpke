use std::hint::black_box;
use std::sync::LazyLock;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use quanta::Instant;
use reatls_hpke_crypto::{Crypto, HpkeAead};

static BACKEND_AWS_LC_RS: LazyLock<reatls_hpke_crypto::backend::HpkeCryptoAwsLcRs> =
    LazyLock::new(|| reatls_hpke_crypto::backend::HpkeCryptoAwsLcRs::new().unwrap());
static BACKEND_GRAVIOLA: LazyLock<reatls_hpke_crypto::backend::HpkeCryptoGraviola> =
    LazyLock::new(|| reatls_hpke_crypto::backend::HpkeCryptoGraviola::new().unwrap());
static BACKEND_RING: LazyLock<reatls_hpke_crypto::backend::HpkeCryptoRing> =
    LazyLock::new(|| reatls_hpke_crypto::backend::HpkeCryptoRing::new().unwrap());
static BACKEND_RUSTCRYPTO: LazyLock<reatls_hpke_crypto::backend::HpkeCryptoRustCrypto> =
    LazyLock::new(|| reatls_hpke_crypto::backend::HpkeCryptoRustCrypto::new().unwrap());

macro_rules! bench {
    (Enc => $fn_name:ident, $alg:ident, $name:expr, $key_len:expr) => {
        fn $fn_name(c: &mut Criterion) {
            let key = [0u8; $key_len];
            let nonce = [0u8; 12];
            let aad = [0u8; 32];

            let mut group = c.benchmark_group($name);

            for (size, size_name) in [(32, "32B"), (2048, "2KB"), (8192, "8KB"), (16384, "16KB")] {
                let input = vec![0u8; size];

                group.throughput(Throughput::Bytes(size as u64));

                {
                    bench!(
                        Enc =>
                        group,
                        "aws-lc-rs",
                        size_name,
                        input,
                        &*BACKEND_AWS_LC_RS,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }

                {
                    bench!(
                        Enc =>
                        group,
                        "graviola",
                        size_name,
                        input,
                        &*BACKEND_GRAVIOLA,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }

                {
                    bench!(
                        Enc =>
                        group,
                        "ring",
                        size_name,
                        input,
                        &*BACKEND_RING,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }

                {
                    bench!(
                        Enc =>
                        group,
                        "rustcrypto",
                        size_name,
                        input,
                        &*BACKEND_RUSTCRYPTO,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }
            }
        }
    };
    (Dec => $fn_name:ident, $alg:ident, $name:expr, $key_len:expr) => {
        fn $fn_name(c: &mut Criterion) {
            let key = [0u8; $key_len];
            let nonce = [0u8; 12];
            let aad = [0u8; 32];

            let mut group = c.benchmark_group($name);

            for (size, size_name) in [(32, "32B"), (2048, "2KB"), (8192, "8KB"), (16384, "16KB")] {
                let mut input = vec![0u8; size];

                BACKEND_RING
                    .aead_seal_in_place(&HpkeAead::$alg { key, nonce }, &aad, &mut input)
                    .unwrap();

                group.throughput(Throughput::Bytes(size as u64));

                {
                    bench!(
                        Dec =>
                        group,
                        "aws-lc-rs",
                        size_name,
                        input,
                        &*BACKEND_AWS_LC_RS,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }

                {
                    bench!(
                        Dec =>
                        group,
                        "graviola",
                        size_name,
                        input,
                        &*BACKEND_GRAVIOLA,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }

                {
                    bench!(
                        Dec =>
                        group,
                        "ring",
                        size_name,
                        input,
                        &*BACKEND_RING,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }

                {
                    bench!(
                        Dec =>
                        group,
                        "rustcrypto",
                        size_name,
                        input,
                        &*BACKEND_RUSTCRYPTO,
                        $alg,
                        key,
                        nonce,
                        &aad
                    );
                }
            }
        }
    };
    (
        Enc =>
        $group:expr,
        $bench_name:expr,
        $size_name:expr,
        $input:expr,
        $backend:expr,
        $alg:ident,
        $key:expr,
        $nonce:expr,
        $aad:expr
    ) => {
        $group.bench_function(BenchmarkId::new($bench_name, $size_name), |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        let mut input = $input.clone();

                        let now = Instant::now();

                        $backend
                            .aead_seal_in_place(
                                black_box(&HpkeAead::$alg { key: $key, nonce: $nonce }),
                                black_box($aad),
                                black_box(&mut input),
                            )
                            .unwrap();

                        now.elapsed()
                    })
                    .sum()
            });
        });
    };
    (
        Dec =>
        $group:expr,
        $bench_name:expr,
        $size_name:expr,
        $input:expr,
        $backend:expr,
        $alg:ident,
        $key:expr,
        $nonce:expr,
        $aad:expr
    ) => {
        $group.bench_function(BenchmarkId::new($bench_name, $size_name), |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        let mut input = $input.clone();

                        let now = Instant::now();

                        $backend
                            .aead_open_in_place(
                                black_box(&HpkeAead::$alg { key: $key, nonce: $nonce }),
                                black_box($aad),
                                black_box(&mut input),
                            )
                            .unwrap();

                        now.elapsed()
                    })
                    .sum()
            });
        });
    };
}

bench!(
    Enc =>
    aes_128_gcm_encryption,
    Aes128Gcm,
    "aes-128-gcm/encryption",
    16
);

bench!(
    Dec =>
    aes_128_gcm_decryption,
    Aes128Gcm,
    "aes-128-gcm/decryption",
    16
);

bench!(
    Enc =>
    aes_256_gcm_encryption,
    Aes256Gcm,
    "aes-256-gcm/encryption",
    32
);

bench!(
    Dec =>
    aes_256_gcm_decryption,
    Aes256Gcm,
    "aes-256-gcm/decryption",
    32
);

bench!(
    Enc =>
    chacha20_poly1305_encryption,
    ChaCha20Poly1305,
    "chacha20-poly1305/encryption",
    32
);

bench!(
    Dec =>
    chacha20_poly1305_decryption,
    ChaCha20Poly1305,
    "chacha20-poly1305/decryption",
    32
);

criterion_group!(
    benches,
    aes_128_gcm_encryption,
    aes_128_gcm_decryption,
    aes_256_gcm_encryption,
    aes_256_gcm_decryption,
    chacha20_poly1305_encryption,
    chacha20_poly1305_decryption,
);
criterion_main!(benches);
