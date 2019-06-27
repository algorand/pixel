// this file implements the core operations in Pixel signature scheme

use keys::{KeyPair, PublicKey, SecretKey};
use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use param::PubParam;
use sig::Signature;
use time::TimeStamp;
use Pixel;
use PixelSign;

/// This module defines the public API's that will be exposed to external.
impl PixelSign for Pixel {
    /// Input a byte string as the seed. The seed needs to be at least
    /// 32 bytes long. Output the public parameters.
    /// Check `use_rand_generators` flags for randomized generators.
    /// Returns an error if seed is not long enough.
    fn pixel_param_gen(seed: &[u8]) -> Result<PubParam, String> {
        PubParam::init(seed)
    }

    /// Input a byte string as the seed, and the public parameters.
    /// The seed needs to be at least
    /// 32 bytes long. Output the key pair.
    /// Returns an error is seed is not long enough.
    fn pixel_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PublicKey, SecretKey), String> {
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
    fn pixel_sk_update(
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
    fn pixel_sign(
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
    fn pixel_sign_present(
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
    fn pixel_sign_then_update(
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
    fn pixel_verify(
        pk: &PublicKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        sig: Signature,
    ) -> bool {
        sig.verify_bytes(pk, tar_time, &pp, msg)
    }

    /// Convert a parameter set into bytes
    fn pixel_param_to_bytes(_pp: &PubParam) -> &[u8] {
        // TODO place holder
        &[0; 0]
    }

    /// Convert bytes into parameters
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_param(_blob: &[u8]) -> Result<PubParam, String> {
        Err("this is a place holder. function not implemented yet".to_owned())
    }

    /// Convert a public key into bytes
    fn pixel_pk_to_bytes(pk: &SecretKey) -> &[u8] {
        // TODO place holder
        //    let t = pk.into_affine();

        &[0; 0]
    }

    /// Convert bytes into a public key
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_pk(_blob: &[u8]) -> Result<PublicKey, String> {
        // TODO place holder
        Err("this is a place holder. function not implemented yet".to_owned())
    }

    /// Convert a secret key into bytes
    fn pixel_sk_to_bytes(_sk: &SecretKey) -> &[u8] {
        // TODO place holder
        &[0; 0]
    }

    /// Convert bytes into secret keys
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_sk(_blob: &[u8]) -> Result<SecretKey, String> {
        Err("this is a place holder. function not implemented yet".to_owned())
    }

    /// Convert a signature into bytes
    fn pixel_sig_to_bytes(_sig: &Signature) -> &[u8] {
        // TODO place holder
        &[0; 0]
    }

    /// Convert bytes into signatures
    /// Returns an error if the decoding failed.
    fn pixel_bytes_to_sig(_blob: &[u8]) -> Result<Signature, String> {
        Err("this is a place holder. function not implemented yet".to_owned())
    }
}

/// This is a short and simple test on pixel's core APIs
#[test]
fn test_pixel_api() {
    use pixel::Pixel;

    let res = Pixel::pixel_param_gen(b"this is a very very long seed for parameter testing");
    assert!(res.is_ok(), "pixel param gen failed");
    let pp = res.unwrap();

    let res = Pixel::pixel_key_gen(b"this is a very very long seed for key gen testing", &pp);
    assert!(res.is_ok(), "pixel key gen failed");
    let (pk, mut sk) = res.unwrap();

    let sk2 = sk.clone();

    // testing basic signings
    let msg = b"message to sign";
    let res = Pixel::pixel_sign(&mut sk, 1, &pp, msg);
    assert!(res.is_ok(), "error in signing algorithm");
    let sig = res.unwrap();
    assert!(
        Pixel::pixel_verify(&pk, 1, &pp, msg, sig),
        "verification failed"
    );
    // testing update-then-sign for present
    for j in 2..16 {
        let res = Pixel::pixel_sk_update(&mut sk, j, &pp);
        assert!(res.is_ok(), "error in key updating");
        let res = Pixel::pixel_sign(&mut sk, j, &pp, msg);
        assert!(res.is_ok(), "error in signing algorithm");
        let sig = res.unwrap();
        assert!(
            Pixel::pixel_verify(&pk, j, &pp, msg, sig),
            "verification failed"
        );
    }
    // testing signing for future
    for j in 2..16 {
        let mut sk3 = sk2.clone();
        let res = Pixel::pixel_sign(&mut sk3, j, &pp, msg);
        assert!(res.is_ok(), "error in signing algorithm");
        let sig = res.unwrap();
        assert!(
            Pixel::pixel_verify(&pk, j, &pp, msg, sig),
            "verification failed"
        );
    }
}
