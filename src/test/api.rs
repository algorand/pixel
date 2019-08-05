// this file implements tests on the core operations of Pixel signature scheme

use Pixel;
use PixelSignature;

// this function tests key generation, key updating, signing and verification APIs.
#[test]
fn test_pixel_api() {
    let res = Pixel::param_gen("this is a very very long seed for parameter testing", 0);
    assert!(res.is_ok(), "pixel param gen failed");
    let pp = res.unwrap();

    let res = Pixel::key_gen("this is a very very long seed for key gen testing", &pp);
    assert!(res.is_ok(), "pixel key gen failed");
    let (pk, mut sk, pop) = res.unwrap();
    assert!(Pixel::verify_pop(&pk, &pop), "pop verification failed");

    let sk2 = sk.clone();

    // testing basic signings
    let msg = "message to sign";
    let seed = "";
    let res = Pixel::sign(&mut sk, 1, &pp, msg, seed);
    assert!(res.is_ok(), "error in signing algorithm");
    let sig = res.unwrap();
    assert!(Pixel::verify(&pk, &pp, msg, &sig), "verification failed");
    // testing update-then-sign for present
    for j in 2..16 {
        let res = Pixel::sk_update(&mut sk, j, &pp, seed);
        assert!(res.is_ok(), "error in key updating");
        let res = Pixel::sign(&mut sk, j, &pp, msg, seed);
        assert!(res.is_ok(), "error in signing algorithm");
        let sig = res.unwrap();
        assert!(Pixel::verify(&pk, &pp, msg, &sig), "verification failed");
    }
    // testing signing for future
    for j in 2..16 {
        let mut sk3 = sk2.clone();
        let res = Pixel::sign(&mut sk3, j, &pp, msg, seed);
        assert!(res.is_ok(), "error in signing algorithm");
        let sig = res.unwrap();
        assert!(Pixel::verify(&pk, &pp, msg, &sig), "verification failed");
    }
}

// a simple test to ensure that we have pixel groups mapped to the
// right groups over the BLS12-381 curve
// the code will generate a compiler error if we are in a wrong group
#[test]
fn test_group_is_correct() {
    use pairing::CurveProjective;
    use PixelG1;
    let a = PixelG1::one();
    assert_eq!(a, pairing::bls12_381::G2::one());
}
