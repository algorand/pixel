# Pixel signature scheme

## Build options

* `cargo build` builds a debug version; with time depth parameter = 4;
* `cargo build --release` builds the release version; with time depth parameter = 30
* `cargo build --features=pk_in_g2` builds a version where the public key lies in `G2` or `bls12-381` curve; it is turned off by default.
* `cargo build --features=use_rand_generators` uses randomized generators rather than the generator from `bls12-381` curve;

## Test options
* `cargo test [--features=[pk_in_g2],[use_rand_generators]] [--release]` runs basic tests;
* `cargo test -- --ignored [--features=[pk_in_g2],[use_rand_generators]] [--release]` runs long tests;
* `cargo bench [--features=[pk_in_g2],[use_rand_generators]] [--release]` runs benchmarks (TODO).
* `cargo test --features=pk_in_g2 test_det` runs a deterministic test and compare the intermediate values against python implementation.

## Document
* `cargo doc --open` to view the public traits and functions.


## Quality control
Following the guidelines from [Facebooks source code](https://developers.libra.org/docs/community/coding-guidelines)
* `cargo fmt` for coding style
* `cargo clippy --all-targets --all-features -- -D warnings` for [lint](https://github.com/rust-lang/rust-clippy/blob/master/README.md)
* `cargo fuzz` for [fuzzing](https://rust-fuzz.github.io/book/introduction.html) (TODO)

## Interfaces


* `fn pixel_param_gen(seed: &[u8]) -> Result<PubParam, String>`
  * Input: a byte string as the seed.
  * Output: the public parameters.
  * Error: if the seed is less than 32 bytes
  * Option: `[use_rand_generators]`; unset by default

* `fn pixel_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PublicKey, SecretKey), String>`  
  * Input: a seed, a public parameter
  * Output: a pair of keys
  * Error: if the seed is less than 32 bytes

<!--
* `fn pixel_get_pk(kp: &KeyPair) -> PublicKey`
  * Input: a key pair
  * Output: its public key

* `fn pixel_get_sk(kp: &KeyPair) -> SecretKey`
  * Input: a key pair
  * Output: its secret key
 -->

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
