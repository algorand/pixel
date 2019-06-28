extern crate bigint;
extern crate bls_sigs_ref_rs;
extern crate ff;
extern crate pairing;
extern crate sha2;

mod keys;
mod param;
mod pixel_err;
mod sig;
mod subkeys;
mod time;

/// This file contains deterministic tests, with pre-fixed parameters,
/// and with determinstic, small random numbers, e.g., 1, 2, 3, 4...
/// This test module is only avaliable when public key lies in G2.
#[cfg(test)]
#[cfg(debug_assertions)]
#[cfg(feature = "pk_in_g2")]
mod det_test;

#[cfg(test)]
mod pixel_test;

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
impl Pixel {
    /// Input a byte string as the seed, and a ciphersuite identifier.
    /// The seed needs to be at least
    /// 32 bytes long. Output the public parameters.
    /// Check `use_rand_generators` flags for randomized generators.
    /// Returns an error if seed is not long enough.
    pub fn pixel_param_gen(seed: &[u8], ciphersuite: u8) -> Result<PubParam, String> {
        PubParam::init(seed, ciphersuite)
    }

    /// Input a byte string as the seed, and the public parameters.
    /// The seed needs to be at least
    /// 32 bytes long. Output the key pair.
    /// Returns an error is seed is not long enough.
    pub fn pixel_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PublicKey, SecretKey), String> {
        let kp = match KeyPair::keygen(seed, &pp) {
            Err(e) => return Err(e),
            Ok(p) => p,
        };
        Ok((kp.get_pk(), kp.get_sk()))
    }

    // /// Input a key pair, output its public key.
    // fn pixel_get_pk(kp: &KeyPair) -> PublicKey {
    //     kp.get_pk()
    // }
    //
    // /// Input a key pair, output its public key.
    // fn pixel_get_sk(kp: &KeyPair) -> SecretKey {
    //     kp.get_sk()
    // }

    /// Input a secret key, the public parameter and a time stamp,
    /// update the key to that time stamp.
    pub fn pixel_sk_update(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
    ) -> Result<(), String> {
        sk.update(&pp, tar_time)
    }

    /// Input a secret key, a time stamp (that is no less than secret key's time stamp),
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature. If the time stamp is greater than that of the secret key,
    /// the key will be updated to the new time stamp.
    pub fn pixel_sign(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Signature, String> {
        Signature::sign(sk, tar_time, &pp, msg)
    }

    /// Input a secret key, a time stamp that matches the timestamp of the secret key,
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature. If the time stamp is not the same as the secret key,
    /// returns an error
    pub fn pixel_sign_present(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Signature, String> {
        // TODO
        Signature::sign(sk, tar_time, &pp, msg)
    }

    /// Input a secret key, a time stamp that matches the timestamp of the secret key,
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature, and advance to time stamp +1.
    /// This feature may be useful to enforce one time signature for each time stamp.
    /// If the time stamp is not the same as the secret key,
    /// returns an error
    pub fn pixel_sign_then_update(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Signature, String> {
        // TODO
        Signature::sign(sk, tar_time, &pp, msg)
    }

    /// Input a public key, a time stamp, the public parameter, a message in the form of a byte string,
    /// and a signature, outputs true if signature is valid w.r.t. the inputs.
    pub fn pixel_verify(
        pk: &PublicKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        sig: Signature,
    ) -> bool {
        sig.verify_bytes(pk, tar_time, &pp, msg)
    }

    /// Convert a parameter set into bytes
    pub fn pixel_param_to_bytes(_pp: &PubParam) -> &[u8] {
        // TODO place holder
        &[0; 0]
    }

    /// Convert bytes into parameters
    /// Returns an error if the decoding failed.
    pub fn pixel_bytes_to_param(_blob: &[u8]) -> Result<PubParam, String> {
        Err("this is a place holder. function not implemented yet".to_owned())
    }

    /// Convert a public key into bytes
    pub fn pixel_pk_to_bytes(_pk: &SecretKey) -> &[u8] {
        // TODO place holder
        //    let t = pk.into_affine();

        &[0; 0]
    }

    /// Convert bytes into a public key
    /// Returns an error if the decoding failed.
    pub fn pixel_bytes_to_pk(_blob: &[u8]) -> Result<PublicKey, String> {
        // TODO place holder
        Err("this is a place holder. function not implemented yet".to_owned())
    }

    /// Convert a secret key into bytes
    pub fn pixel_sk_to_bytes(_sk: &SecretKey) -> &[u8] {
        // TODO place holder
        &[0; 0]
    }

    /// Convert bytes into secret keys
    /// Returns an error if the decoding failed.
    pub fn pixel_bytes_to_sk(_blob: &[u8]) -> Result<SecretKey, String> {
        Err("this is a place holder. function not implemented yet".to_owned())
    }

    /// Convert a signature into bytes
    pub fn pixel_sig_to_bytes(_sig: &Signature) -> &[u8] {
        // TODO place holder
        &[0; 0]
    }

    /// Convert bytes into signatures
    /// Returns an error if the decoding failed.
    pub fn pixel_bytes_to_sig(_blob: &[u8]) -> Result<Signature, String> {
        Err("this is a place holder. function not implemented yet".to_owned())
    }
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
