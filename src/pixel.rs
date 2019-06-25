use keys::{KeyPair, PublicKey, SecretKey};
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
    fn pixel_key_gen(seed: &[u8], pp: &PubParam) -> Result<KeyPair, String> {
        KeyPair::keygen(seed, &pp)
    }

    /// Input a key pair, output its public key.
    fn pixel_get_pk(kp: &KeyPair) -> PublicKey {
        kp.get_pk()
    }

    /// Input a key pair, output its public key.
    fn pixel_get_sk(kp: &KeyPair) -> SecretKey {
        kp.get_sk()
    }

    /// Input a secret key, the public parameter and a time stamp,
    /// update the key to that time stamp.
    fn pixel_sk_update(
        sk: &mut SecretKey,
        pp: &PubParam,
        tar_time: TimeStamp,
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
    let keypair = res.unwrap();

    let pk = Pixel::pixel_get_pk(&keypair);
    let mut sk = Pixel::pixel_get_sk(&keypair);
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
        let res = Pixel::pixel_sk_update(&mut sk, &pp, j);
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
