# just manual: https://github.com/casey/just#readme

_default:
	just --list

# Run all tests with nextest
ci-test *args:
	#!/bin/bash -eux
	cargo nextest run --package hpke-core --package hpke-crypto {{args}} --locked

# =========== LOCAL COMMANDS ===========

build *args:
	cargo build {{args}} --locked

b *args:
	just build {{args}}

# Show coverage locally
cov *args:
	#!/bin/bash -eux
	cargo llvm-cov nextest --package hpke-core --package hpke-crypto {{args}} --locked --hide-instantiations --html --output-dir coverage

check *args:
    cargo check {{args}} --locked --all-features

c *args:
	just check {{args}}

clippy *args:
	cargo clippy {{args}} --locked --all-features -- -Dclippy::all -Dclippy::pedantic

example *args:
	cargo run --example {{args}}

e *args:
	just example {{args}}

msrv *args:
	cargo +1.91.0 clippy {{args}} --locked --all-features -- -Dclippy::all -Dclippy::pedantic

t *args:
	just test {{args}}

test *args:
	#!/bin/bash -eux
	export RUST_BACKTRACE=1
	cargo nextest run --package hpke-tests {{args}} --locked --all-features
