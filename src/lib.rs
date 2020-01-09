// CREDIT: http://patorjk.com/software/taag
// .______    __  ___   ___  _______  __
// |   _  \  |  | \  \ /  / |   ____||  |
// |  |_)  | |  |  \  V  /  |  |__   |  |
// |   ___/  |  |   >   <   |   __|  |  |
// |  |      |  |  /  .  \  |  |____ |  `----.
// | _|      |__| /__/ \__\ |_______||_______|

#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::missing_safety_doc))]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! This crate implements the Pixel signature scheme.
//! * By default the groups are switched so that
//! the public key lies in `G1` over BLS12-381 curve.
//! This yields smaller public keys.
//! * The depth is set to 32 by default. This gives 700 years of life time for the secret keys,
//! assuming each key lasts for 5 second. This parameter is defined by `CONST_D` in pixel_param.
//! * The current implementaion only supports ciphersuite id  = `0x00` and `0x01`. The exact
//! mapping between ids and parameters is yet to be specified.

extern crate bigint;
extern crate bls_sigs_ref;
// extern crate clear_on_drop;
extern crate ff;
extern crate hkdf;
extern crate libc;
extern crate pairing_plus as pairing;
extern crate pixel_param as param;
extern crate sha2;
// #[macro_use]
extern crate zeroize;
// extern crate secrecy;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

/// Domain separators are defined here.
mod domain_sep;
/// Error messages are defined here.
mod pixel_err;

mod prng;
mod serdes;
mod sig;
mod subkeys;
#[cfg(test)]
mod test;
mod time;

mod key_pair;
mod pop;
mod public_key;
mod secret_key;

//mod pixel_zeroize;

/// This module defines interfaces to C.
pub mod ffi;

/// The size of pk is 49 when PK is in G1. 1 byte for ciphersuite ID
/// and 48 byte for group element.
pub const PK_LEN: usize = 49;

/// The Signature size is 149.
/// 1 byte for ciphersuite ID, 4 bytes for time stamp,
/// 48+96 bytes for two group elements.
pub const SIG_LEN: usize = 149;

/// The size of pop is 97: 1 byte for ciphersuite ID
/// and 96 byte for bls signature in G2.
pub const POP_LEN: usize = 97;

// Expose this constant.
pub use param::{PixelG1, PixelG2, PubParam, SerDes, CONST_D, VALID_CIPHERSUITE};
pub use pop::ProofOfPossession;
pub use public_key::PublicKey;
pub use secret_key::SecretKey;
pub use sig::Signature;
pub use subkeys::SubSecretKey;
pub use time::{TimeStamp, TimeVec};

/// Pixel is a trait that implements the algorithms within the pixel signature scheme.
pub trait PixelSignature {
    /// Input a byte string as the seed, and a ciphersuite identifier.
    /// The seed needs to be at least
    /// 32 bytes long. Output the public parameters.
    /// Returns an error if seed is not long enough.
    fn param_gen<Blob: AsRef<[u8]>>(seed: Blob, ciphersuite: u8) -> Result<PubParam, String> {
        PubParam::init(seed.as_ref(), ciphersuite)
    }

    /// Return the default, pre-computed parameter set.
    fn param_default() -> PubParam {
        PubParam::default()
    }

    /// Input a byte string as the seed, and the public parameters.
    /// The seed needs to be at least
    /// 32 bytes long. Output the key pair.
    /// Generate a pair of public keys and secret keys,
    /// and a proof of possession of the public key.
    /// This function does NOT return the master secret
    /// therefore this is the only method that generates POP.
    /// Returns an error is seed is not long enough.
    fn key_gen<Blob: AsRef<[u8]>>(
        seed: Blob,
        pp: &PubParam,
    ) -> Result<(PublicKey, SecretKey, ProofOfPossession), String> {
        use key_pair::KeyPair;
        let kp = KeyPair::keygen(seed.as_ref(), &pp)?;
        Ok(kp)
    }

    /// Input a secret key, the public parameter and a time stamp,
    /// update the key to that time stamp.
    fn sk_update<Blob: AsRef<[u8]>>(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        seed: Blob,
    ) -> Result<(), String> {
        sk.update(&pp, tar_time, seed.as_ref())
    }

    /// Input a secret key, a time stamp (that is no less than secret key's time stamp),
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature. If the time stamp is greater than that of the secret key,
    /// the key will be updated to the new time stamp.
    /// Note: the seed is for sk updates, it is not for randomness generation for signing;
    /// the seed will not be used if the sign algorithm actually signs for the
    /// present -- the sk is not updated in this case. For this use case, we should
    /// implicitly use `sign_present` function.
    fn sign<Blob: AsRef<[u8]>>(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Blob,
        seed: Blob,
    ) -> Result<Signature, String> {
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
        Signature::sign_present(sk, tar_time, &pp, msg.as_ref())
    }

    /// Input a secret key, a time stamp that matches the timestamp of the secret key,
    /// the public parameter, and a message in the form of a byte string,
    /// output a signature, and advance to time stamp +1.
    /// Note: the seed is for sk updates, it is not for randomness generation for signing.
    /// This feature may be useful to enforce one time signature for each time stamp.
    /// If the time stamp is not the same as the secret key,
    /// returns an error
    fn sign_then_update<Blob: AsRef<[u8]>>(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Blob,
        seed: Blob,
    ) -> Result<Signature, String> {
        Signature::sign_then_update(sk, tar_time, &pp, msg.as_ref(), seed.as_ref())
    }

    /// Input a public key, the public parameter, a message in the form of a byte string,
    /// and a signature, outputs true if signature is valid w.r.t. the inputs.
    fn verify<Blob: AsRef<[u8]>>(
        pk: &PublicKey,
        pp: &PubParam,
        msg: Blob,
        sig: &Signature,
    ) -> bool {
        sig.verify_bytes(pk, &pp, msg.as_ref())
    }

    /// This function aggregates the signatures without checking if a signature is valid or not.
    /// It does check that all the signatures are for the same time stamp.
    /// It returns an error if ciphersuite fails or time stamp is not consistent.
    fn aggregate_without_validate(sig_list: &[Signature]) -> Result<Signature, String> {
        Signature::aggregate_without_validate(sig_list)
    }

    /// Input an aggregated signature, a list of public keys, a public parameter, and a
    /// message, output true if the signatures verifies.
    /// Signatures verified through this way may be vulnerable to rogue key attacks,
    /// unless a proof of possession of the public key is presented -- this should be
    /// handled by the upper layer.
    fn verify_aggregated<Blob: AsRef<[u8]>>(
        pk_list: &[PublicKey],
        pp: &PubParam,
        msg: Blob,
        sig: &Signature,
    ) -> bool {
        sig.verify_bytes_aggregated(pk_list, pp, msg.as_ref())
    }

    /// Input a public key and a Pop, verify the pop use BLS signature scheme.
    fn verify_pop(pk: &PublicKey, pop: &ProofOfPossession) -> bool {
        pk.validate(pop)
    }
}

/// Pixel is an abstract structure that holds related functionalities
/// of pixel signature algorithms.
#[derive(Debug)]
pub struct Pixel;

/// Pixel uses default implementaions from PixelSignature trait.
impl PixelSignature for Pixel {}
