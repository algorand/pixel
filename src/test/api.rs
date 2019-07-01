// this file implements tests on the core operations of Pixel signature scheme

use Pixel;
use PixelSignature;

// #[test]
// fn test_pixel_api() {
//     let res = Pixel::pixel_param_gen(b"this is a very very long seed for parameter testing", 0);
//     assert!(res.is_ok(), "pixel param gen failed");
//     let pp = res.unwrap();
//
//     let res = Pixel::pixel_key_gen(b"this is a very very long seed for key gen testing", &pp);
//     assert!(res.is_ok(), "pixel key gen failed");
//     let (pk, mut sk) = res.unwrap();
//
//     let sk2 = sk.clone();
//
//     // testing basic signings
//     let msg = b"message to sign";
//     let res = Pixel::pixel_sign(&mut sk, 1, &pp, msg);
//     assert!(res.is_ok(), "error in signing algorithm");
//     let sig = res.unwrap();
//     assert!(
//         Pixel::pixel_verify(&pk, 1, &pp, msg, sig),
//         "verification failed"
//     );
//     // testing update-then-sign for present
//     for j in 2..16 {
//         let res = Pixel::pixel_sk_update(&mut sk, j, &pp);
//         assert!(res.is_ok(), "error in key updating");
//         let res = Pixel::pixel_sign(&mut sk, j, &pp, msg);
//         assert!(res.is_ok(), "error in signing algorithm");
//         let sig = res.unwrap();
//         assert!(
//             Pixel::pixel_verify(&pk, j, &pp, msg, sig),
//             "verification failed"
//         );
//     }
//     // testing signing for future
//     for j in 2..16 {
//         let mut sk3 = sk2.clone();
//         let res = Pixel::pixel_sign(&mut sk3, j, &pp, msg);
//         assert!(res.is_ok(), "error in signing algorithm");
//         let sig = res.unwrap();
//         assert!(
//             Pixel::pixel_verify(&pk, j, &pp, msg, sig),
//             "verification failed"
//         );
//     }
// }

#[test]
fn test_pixel_api() {
    let res = Pixel::param_gen("this is a very very long seed for parameter testing", 0);
    assert!(res.is_ok(), "pixel param gen failed");
    let pp = res.unwrap();

    let res = Pixel::key_gen("this is a very very long seed for key gen testing", &pp);
    assert!(res.is_ok(), "pixel key gen failed");
    let (pk, mut sk) = res.unwrap();

    let sk2 = sk.clone();

    // testing basic signings
    let msg = "message to sign";
    let res = Pixel::sign(&mut sk, 1, &pp, msg);
    assert!(res.is_ok(), "error in signing algorithm");
    let sig = res.unwrap();
    assert!(Pixel::verify(&pk, 1, &pp, msg, sig), "verification failed");
    // testing update-then-sign for present
    for j in 2..16 {
        let res = Pixel::sk_update(&mut sk, j, &pp);
        assert!(res.is_ok(), "error in key updating");
        let res = Pixel::sign(&mut sk, j, &pp, msg);
        assert!(res.is_ok(), "error in signing algorithm");
        let sig = res.unwrap();
        assert!(Pixel::verify(&pk, j, &pp, msg, sig), "verification failed");
    }
    // testing signing for future
    for j in 2..16 {
        let mut sk3 = sk2.clone();
        let res = Pixel::sign(&mut sk3, j, &pp, msg);
        assert!(res.is_ok(), "error in signing algorithm");
        let sig = res.unwrap();
        assert!(Pixel::verify(&pk, j, &pp, msg, sig), "verification failed");
    }
}
