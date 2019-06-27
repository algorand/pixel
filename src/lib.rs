extern crate bigint;
extern crate ff;
extern crate pairing;
extern crate sha2;

mod keys;
mod param;
mod pixel;
mod sig;
mod subkeys;
mod time;
mod util;

/// This file contains deterministic tests, with pre-fixed parameters,
/// and with determinstic, small random numbers, e.g., 1, 2, 3, 4...
/// This test module is only avaliable when public key lies in G2.
#[cfg(test)]
#[cfg(debug_assertions)]
#[cfg(feature = "pk_in_g2")]
mod det_test;

// by default the groups are switched so that
// the public key lies in G2
// this yields smaller public keys
// in the case where public key lies in G1,
// we need to unswitch the groups
// to enable this feature, set `features=pk_in_g2` flag

//  additional comments for cargo doc
/// The pixel G1 group is mapped to G1 over BLS12-381 curve.
/// Note that `features=pk_in_g2` flag is set.
#[cfg(feature = "pk_in_g2")]
type PixelG1 = pairing::bls12_381::G1;
//  additional comments for cargo doc
/// The pixel G2 group is mapped to G2 over BLS12-381 curve.
/// Note that `features=pk_in_g2` flag is set.
#[cfg(feature = "pk_in_g2")]
type PixelG2 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G2.
/// This means pixel G1 group is mapped to G2 over BLS12-381 curve.
#[cfg(not(feature = "pk_in_g2"))]
type PixelG1 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G2.
/// This means pixel G2 group is mapped to G1 over BLS12-381 curve.
#[cfg(not(feature = "pk_in_g2"))]
type PixelG2 = pairing::bls12_381::G1;

pub use keys::{KeyPair, PublicKey, SecretKey, SubSecretKey};
pub use param::PubParam;
pub use sig::Signature;
pub use time::TimeStamp;

/// Pixel is an abstract structure that holds related functionalities
/// of pixel signature algorithms.
pub struct Pixel;

/// This struct implenents the public API's that will can be accessed by external.
pub trait PixelSign {
    /// Input a byte string as the seed. The seed needs to be at least
    /// 32 bytes long. Output the public parameters.
    /// Check `use_rand_generators` flags for randomized generators.
    /// Returns an error if seed is not long enough.
    fn pixel_param_gen(seed: &[u8]) -> Result<PubParam, String>;

    /// Input a byte string as the seed, and the public parameters.
    /// The seed needs to be at least
    /// 32 bytes long. Output the key pair.
    /// Returns an error if seed is not long enough.
    fn pixel_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PublicKey, SecretKey), String>;

    // /// Input a key pair, output its public key.
    // fn pixel_get_pk(kp: &KeyPair) -> PublicKey;
    //
    // /// Input a key pair, output its secret key.
    // fn pixel_get_sk(kp: &KeyPair) -> SecretKey;

    /// Input a secret key, the public parameter and a time stamp,
    /// update the key to that time stamp.
    /// Returns an error if the target time is invalid.
    fn pixel_sk_update(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
    ) -> Result<(), String>;

    /// Input a secret key, a time stamp (that is no less than secret key's time stamp),
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature. If the time stamp is greater than that of the secret key,
    /// the key will be updated to the new time stamp.
    fn pixel_sign(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Signature, String>;

    /// Input a public key, a time stamp, the public parameter, a message in the form of a byte string,
    /// and a signature, output true if signature is valid w.r.t. the inputs.
    fn pixel_verify(
        pk: &PublicKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        sig: Signature,
    ) -> bool;

    /// Convert a parameter set into bytes
    fn pixel_param_to_bytes(pp: &PubParam) -> &[u8];

    /// Convert bytes into parameters
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_param(blob: &[u8]) -> Result<PubParam, String>;

    /// Convert a public key into bytes
    fn pixel_pk_to_bytes(pk: &SecretKey) -> &[u8];

    /// Convert bytes into a public key
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_pk(blob: &[u8]) -> Result<PublicKey, String>;

    /// Convert a secret key into bytes
    fn pixel_sk_to_bytes(sk: &SecretKey) -> &[u8];

    /// Convert bytes into secret keys
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_sk(blob: &[u8]) -> Result<SecretKey, String>;

    /// Convert a signature into bytes
    fn pixel_sig_to_bytes(sig: &Signature) -> &[u8];

    /// Convert bytes into signatures.
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_sig(blob: &[u8]) -> Result<Signature, String>;
}

// a simple test to ensure that we have pixel groups mapped to the
// right groups over the BLS12-381 curve
// the code will generate a compiler error if we are in a wrong group
#[test]
fn test_group_is_correct() {
    use pairing::CurveProjective;
    let a = PixelG1::one();
    #[cfg(not(feature = "pk_in_g2"))]
    assert_eq!(a, pairing::bls12_381::G2::one());
    #[cfg(feature = "pk_in_g2")]
    assert_eq!(a, pairing::bls12_381::G1::one());
}
