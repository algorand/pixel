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
* [Pairing library](https://github.com/algorand/pairing-fork)
* [Pixel_param](https://github.com/algorand/pixel_param)
* [BLS_SIG-fork](https://github.com/algorand/bls_sigs_ref-fork) To be removed.

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
Following the guidelines from [Facebook's libra source code](https://developers.libra.org/docs/community/coding-guidelines)
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

<!--

* `fn pixel_param_gen(seed: &[u8]) -> Result<PubParam, String>`
  * Input: a byte string as the seed.
  * Output: the public parameters.
  * Error: if the seed is less than 32 bytes
  * Option: `[use_rand_generators]`; unset by default

* `fn pixel_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PublicKey, SecretKey), String>`  
  * Input: a seed, a public parameter
  * Output: a pair of keys
  * Error: if the seed is less than 32 bytes


* `fn pixel_get_pk(kp: &KeyPair) -> PublicKey`
  * Input: a key pair
  * Output: its public key

* `fn pixel_get_sk(kp: &KeyPair) -> SecretKey`
  * Input: a key pair
  * Output: its secret key


* `fn pixel_sk_update(sk: &mut SecretKey, tar_time: TimeStamp, pp: &PubParam) -> Result<(), String>`
  * Input: a secret key,  a target time stamp, the public parameter
  * Output: secret key is mutated to the new secret key
  * Error: target time is invalid

* `fn pixel_sign(sk: &mut SecretKey, tar_time: TimeStamp, pp: &PubParam, msg: &[u8]) -> Result<Signature, String>`
  * Input: a secret key, a target time stamp, the public parameter, the message
  * Output: a signature
  * Error: target time is invalid

* `fn pixel_verify( pk: &PublicKey, tar_time: TimeStamp, pp: &PubParam, msg: &[u8], sig: Signature) -> bool`
  * Input: a secret key, a target time stamp, the public parameter, the message, and the signature
  * Output: if the verification passes
  -->
