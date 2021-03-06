<!--
CREDIT: http://patorjk.com/software/taag
.______    __  ___   ___  _______  __
|   _  \  |  | \  \ /  / |   ____||  |
|  |_)  | |  |  \  V  /  |  |__   |  |
|   ___/  |  |   >   <   |   __|  |  |
|  |      |  |  /  .  \  |  |____ |  `----.
| _|      |__| /__/ \__\ |_______||_______|
-->


# Pixel signature scheme

[![Build Status](https://travis-ci.com/algorand/pixel.svg?token=cs332z4omsgc9ykLW8pu&branch=master)](https://travis-ci.com/algorand/pixel)

This is Algorand's implementation of Pixel signature, over the BLS12-381 curve.
Useful links:

* [Paper](https://eprint.iacr.org/2019/514)
* [Spec](https://github.com/algorand/pixel/blob/master/spec.md)
* Rust code: this repo
* [Python code](https://github.com/hoeteck/pixel/)
* [Another python code](https://github.com/algorand/pixel/tree/master/pixel-python) <- This code is only for generating test
vectors and cross comparing with Rust's output. It should not be used for any
other purpose.

## Dependencies
* Pairing-plus library: [Github](https://github.com/algorand/pairing-plus), [Crate.io](https://crates.io/crates/pairing-plus)
  * A fork of zkcrypto's pairing library; with additional functions such as `hash to groups`
  and `membership testing`, etc.
  * We rely heavily on this library for underlying arithmetics.
* Pixel_param: [Github](https://github.com/algorand/pixel_param)
  * We use the default parameters generated from this crate.
* BLS_SIG: [Github](https://github.com/algorand/bls_sigs_ref), [Crate.io](https://crates.io/crates/bls_sigs_ref)
  * This library is only used for generating and verifying proof of possession.

## Code status

* Version Alpha.
* This code has __NOT__ been deployed in production.
* This code has been externally audited by two consulting firms.

## Build options

* `cargo build` builds a debug version;
* `cargo build --release` builds the release version;

## Test options
* `cargo test [--release]` runs basic tests;
* `cargo test -- --ignored [--release]` runs long tests;
* `cargo bench` runs benchmarks.

## Cross comparison with python code
* `test_vector` calls this rust library to generate a list of test vectors.
* `pixel-python/test_vector.py` is a python script that generates a list of test vectors.
* `test_vector.py` also compares the binary outputs of Rust and python match.

## Quality control
Following the guidelines from [Facebook's libra source code](https://developers.libra.org/docs/community/coding-guidelines) and
[Rust API Guidelines](https://rust-lang-nursery.github.io/api-guidelines/about.html).
* `cargo fmt` for coding style
* `cargo clippy --all-targets --all-features -- -D warnings` for [lint](https://github.com/rust-lang/rust-clippy/blob/master/README.md)
* `cargo doc` for documentation.

Exceptions:
* [Facebooks guidelines](https://developers.libra.org/docs/community/coding-guidelines)
suggests to have a test file along with the source code.
Pixel has a separate test folder that contains all test codes.

## Crypto Hygiene
* Variables that storing secret data are named with a suffix `_sec`. Always ensure primitive types get cleaned with `Zeroize` crate;
or get passed to the caller. Secret key related structures implements `zeroing` on drop.
* Avoiding using `clone()` function on secret data as possible - this will create two copies of the data. If `clone()`
is used, always clean it after use.

## Interfaces documentation
* Run `cargo doc --open`
* See `target/doc/pixel/index.html`

## Wrapper
* Generated with [cbindgen](https://github.com/eqrion/cbindgen/blob/master/docs.md)
* See [c_wrapper](https://github.com/algorand/pixel/tree/master/c_wrapper)
