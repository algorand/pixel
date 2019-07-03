// CREDIT: http://patorjk.com/software/taag
// .______    __  ___   ___  _______  __
// |   _  \  |  | \  \ /  / |   ____||  |
// |  |_)  | |  |  \  V  /  |  |__   |  |
// |   ___/  |  |   >   <   |   __|  |  |
// |  |      |  |  /  .  \  |  |____ |  `----.
// | _|      |__| /__/ \__\ |_______||_______|

#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! This crate implements the Pixel signature scheme.
//! * Use `pk_in_g2` flag to identify which which group we would like to have public keys lie in.
//! By default the groups are switched so that
//! the public key lies in `G2` over BLS12-381 curve.
//! This yields smaller public keys.
//! * The depth is set to 30 by default. This gives 170 years of life time for the secret keys,
//! assuming each key lasts for 5 second. This parameter is defined by `CONST_D`.
//! * The current implementaion only supports ciphersuite id  = `0x00` and `0x01`. The exact
//! mapping between ids and parameters is yet to be specified.

extern crate bigint;
extern crate bls_sigs_ref_rs;
extern crate ff;
extern crate pairing;
extern crate sha2;

mod domain_sep;
mod keys;
mod membership;
mod param;
mod pixel_err;
mod serdes;
mod sig;
mod subkeys;
mod time;

#[cfg(test)]
mod test;

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
pub type PixelG1 = pairing::bls12_381::G1;
//  additional comments for cargo doc
/// The pixel G2 group is mapped to G2 over BLS12-381 curve.
/// Note that `features=pk_in_g2` flag is set.
#[cfg(feature = "pk_in_g2")]
pub type PixelG2 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G2.
/// This means pixel G1 group is mapped to G2 over BLS12-381 curve.
#[cfg(not(feature = "pk_in_g2"))]
pub type PixelG1 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G2.
/// This means pixel G2 group is mapped to G1 over BLS12-381 curve.
#[cfg(not(feature = "pk_in_g2"))]
pub type PixelG2 = pairing::bls12_381::G1;

/// The size of pk is 49 when PK is in G1. 1 byte for ciphersuite ID
/// and 48 byte for group element.
#[cfg(not(feature = "pk_in_g2"))]
pub const PK_LEN: usize = 49;

/// The size of pk is 97 when PK is in G2. 1 byte for ciphersuite ID
/// and 96 byte for group element.
#[cfg(feature = "pk_in_g2")]
pub const PK_LEN: usize = 97;

/// The Signature size is always 145. 1 byte for ciphersuite ID,
/// 48+96 for two group elements.
pub const SIG_LEN: usize = 145;

/// The size of public param is ...
/// * 1 byte for ciphersuite ID
/// * 1 byte for depth
/// * 144 for g2 and h
/// * |PIXELG2| *(d+1) for hlist
#[cfg(not(debug_assertions))]
#[cfg(not(feature = "pk_in_g2"))]
pub const PP_LEN: usize = 3314;

/// The size of public param is  when PK is in G1...
/// * 1 byte for ciphersuite ID
/// * 1 byte for depth
/// * 144 for g2 and h
/// * |PIXELG2| *(d+1) for hlist
#[cfg(not(debug_assertions))]
#[cfg(feature = "pk_in_g2")]
pub const PP_LEN: usize = 1730;

/// The size of public param is  when PK is in G1...
/// * 1 byte for ciphersuite ID
/// * 1 byte for depth
/// * 144 for g2 and h
/// * |PIXELG2| *(d+1) for hlist
#[cfg(debug_assertions)]
#[cfg(not(feature = "pk_in_g2"))]
pub const PP_LEN: usize = 626;

/// The size of public param is  when PK is in G1...
/// * 1 byte for ciphersuite ID
/// * 1 byte for depth
/// * 144 for g2 and h
/// * |PIXELG2| *(d+1) for hlist
#[cfg(debug_assertions)]
#[cfg(feature = "pk_in_g2")]
pub const PP_LEN: usize = 386;

// Expose this constant.
pub use param::CONST_D;

// expose the submodules of this crate for debug versions
//#[cfg(debug_assertions)]
pub use keys::{PublicKey, SecretKey};
//#[cfg(debug_assertions)]
pub use param::PubParam;
//#[cfg(debug_assertions)]
pub use sig::Signature;
//#[cfg(debug_assertions)]
pub use time::TimeStamp;

// // hide the submodules of this crate for release versions
// #[cfg(not(debug_assertions))]
// use keys::{PublicKey, SecretKey};
// #[cfg(not(debug_assertions))]
// use param::PubParam;
// #[cfg(not(debug_assertions))]
// use sig::Signature;
// #[cfg(not(debug_assertions))]
// use time::TimeStamp;

/// Pixel is a trait that implements the algorithms within the pixel signature scheme.
pub trait PixelSignature {
    /// Input a byte string as the seed, and a ciphersuite identifier.
    /// The seed needs to be at least
    /// 32 bytes long. Output the public parameters.
    /// Check `use_rand_generators` flags for randomized generators.
    /// Returns an error if seed is not long enough.
    fn param_gen<Blob: AsRef<[u8]>>(seed: Blob, ciphersuite: u8) -> Result<PubParam, String> {
        PubParam::init(seed.as_ref(), ciphersuite)
    }

    /// Input a byte string as the seed, and the public parameters.
    /// The seed needs to be at least
    /// 32 bytes long. Output the key pair.
    /// Returns an error is seed is not long enough.
    fn key_gen<Blob: AsRef<[u8]>>(
        seed: Blob,
        pp: &PubParam,
    ) -> Result<(PublicKey, SecretKey), String> {
        use keys::KeyPair;
        let kp = KeyPair::keygen(seed.as_ref(), &pp)?;
        Ok((kp.get_pk(), kp.get_sk()))
    }

    /// Input a secret key, the public parameter and a time stamp,
    /// update the key to that time stamp.
    fn sk_update(sk: &mut SecretKey, tar_time: TimeStamp, pp: &PubParam) -> Result<(), String> {
        sk.update(&pp, tar_time)
    }

    /// Input a secret key, a time stamp (that is no less than secret key's time stamp),
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature. If the time stamp is greater than that of the secret key,
    /// the key will be updated to the new time stamp.
    fn sign<Blob: AsRef<[u8]>>(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Blob,
    ) -> Result<Signature, String> {
        // TODO: change this
        let seed = "this is a very long seed for testing.";
        Signature::sign(sk, tar_time, &pp, msg.as_ref(), seed.as_ref())
    }

    /// Input a secret key, a time stamp that matches the timestamp of the secret key,
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature. If the time stamp is not the same as the secret key,
    /// returns an error
    fn sign_present<Blob: AsRef<[u8]>>(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Blob,
    ) -> Result<Signature, String> {
        // TODO: change this
        let seed = "this is a very long seed for testing.";
        Signature::sign_present(sk, tar_time, &pp, msg.as_ref(), seed.as_ref())
    }

    /// Input a secret key, a time stamp that matches the timestamp of the secret key,
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature, and advance to time stamp +1.
    /// This feature may be useful to enforce one time signature for each time stamp.
    /// If the time stamp is not the same as the secret key,
    /// returns an error
    fn sign_then_update<Blob: AsRef<[u8]>>(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Blob,
    ) -> Result<Signature, String> {
        // TODO: change this
        let seed = "this is a very long seed for testing.";
        Signature::sign_then_update(sk, tar_time, &pp, msg.as_ref(), seed.as_ref())
    }

    /// Input a public key, a time stamp, the public parameter, a message in the form of a byte string,
    /// and a signature, outputs true if signature is valid w.r.t. the inputs.
    fn verify<Blob: AsRef<[u8]>>(
        pk: &PublicKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Blob,
        sig: &Signature,
    ) -> bool {
        sig.verify_bytes(pk, tar_time, &pp, msg.as_ref())
    }
}

/// Pixel is an abstract structure that holds related functionalities
/// of pixel signature algorithms.
#[derive(Debug)]
pub struct Pixel;

/// Pixel uses default implementaions from PixelSignature trait.
impl PixelSignature for Pixel {}
