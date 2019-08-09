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
* [Pairing-fork library](https://github.com/algorand/pairing-fork)
  * A fork of zkcrypto's pairing library; with additional functions such as `hash to groups`
  and `membership testing`, etc.
  * We rely heavily on this library for underlying arithmetics.
* [Pixel_param](https://github.com/algorand/pixel_param)
  * We use the default parameters generated from this crate.
* [BLS_SIG-fork](https://github.com/algorand/bls_sigs_ref-fork)
  * This library is only used for generating and verifying proof of possession.

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

## Handling secret data
* Variables that storing secret data are named with a suffix `_sec`; always ensure this data get cleaned with `ClearOnDrop` crate;
or get passed to the caller.
* Avoiding using `clone()` function on secret data as possible - this will create two copies of the data. If `clone()`
is used, always clean it after use.
* Some data type, i.e., `[u8;64]` cannot be cleared with `ClearOnDrop` since the `Default` trait is
not implemented for it. We manually clear it by writing trivial data to it.

## Interfaces
* Run `cargo doc --open`
* See `target/doc/pixel/index.html`

## Wrapper
* Generated with [cbindgen](https://rust-lang.github.io/rust-bindgen/)
* See [c_wrapper](https://github.com/algorand/pixel/tree/master/c_wrapper)
