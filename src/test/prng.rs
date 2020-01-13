use ff::PrimeField;
use pairing::bls12_381::Fr;
use prng::{os2ip_mod_p, PRNG};

// examples from
// https://crypto.stackexchange.com/questions/37537/what-are-i2osp-os2ip-in-rsa-pkcs1
//  0  ->  00:00
//  1  ->  00:01
// 255  ->  00:FF
// 256  ->  01:00
// 65535  ->  FF:FF
// additional example
//  2^128
//  2^256 % p
//  2^384 % p
#[test]
fn test_os2ip() {
    assert_eq!(Fr::from_str("0").unwrap(), os2ip_mod_p(&[0u8, 0u8]));
    assert_eq!(Fr::from_str("1").unwrap(), os2ip_mod_p(&[0u8, 1u8]));
    assert_eq!(Fr::from_str("255").unwrap(), os2ip_mod_p(&[0u8, 0xffu8]));
    assert_eq!(Fr::from_str("256").unwrap(), os2ip_mod_p(&[1u8, 0u8]));
    assert_eq!(
        Fr::from_str("65535").unwrap(),
        os2ip_mod_p(&[0xffu8, 0xffu8])
    );
    // 2^128
    assert_eq!(
        Fr::from_str("340282366920938463463374607431768211456").unwrap(),
        // 1 followed by 128/8 = 16 zeros
        os2ip_mod_p(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    // 2^256 % p
    assert_eq!(
        Fr::from_str(
            "10920338887063814464675503992315976177888879664585288394250266608035967270910"
        )
        .unwrap(),
        os2ip_mod_p(&[
            // 1 followed by 256/8 = 32 zeros
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0
        ])
    );
    // 2^384 % p
    assert_eq!(
        Fr::from_str(
            "20690987792304517493546419304065979215229097455316523017309531943206242971949"
        )
        .unwrap(),
        os2ip_mod_p(&[
            // 1 followed by 384/8 = 48 zeros
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ])
    );
}

// the examples in this test are cross compared with python prng code
#[test]
fn test_prng() {
    // prng default
    assert_eq!(PRNG::default(), PRNG::new([0u8; 64]));

    // test sample then update function
    let mut prng = PRNG::init("seed", "salt");
    println!("unit test: prng debug {:?}", prng);
    assert_eq!(
        prng.seed().as_ref(),
        [
            0xde, 0x8, 0xde, 0xe9, 0xf2, 0x71, 0xa6, 0xa0, 0x61, 0xf0, 0xc7, 0x6b, 0x10, 0xb0,
            0xe4, 0xa7, 0x10, 0x7d, 0xa1, 0xeb, 0x84, 0x9f, 0x7e, 0x46, 0xd4, 0x80, 0xf3, 0xab,
            0x93, 0x5b, 0xd5, 0x63, 0x29, 0x75, 0x16, 0x34, 0x8f, 0x3a, 0x4, 0x43, 0x7e, 0x99,
            0x84, 0x80, 0x8a, 0xde, 0xab, 0xc5, 0x40, 0x8f, 0x78, 0xc0, 0x66, 0x7d, 0xd0, 0x15,
            0x7c, 0x6e, 0xcb, 0xf7, 0xa7, 0x4b, 0x69, 0xb7,
        ]
        .as_ref()
    );

    let r = prng.sample_then_update("info");
    assert_eq!(
        prng.seed().as_ref(),
        [
            0x41, 0xfa, 0x66, 0x27, 0x76, 0xb3, 0xff, 0x97, 0x54, 0x1f, 0xda, 0xf8, 0xb1, 0xfa,
            0xda, 0xef, 0x55, 0x15, 0x31, 0xcb, 0xb6, 0x2b, 0x23, 0x28, 0x1e, 0xed, 0xc0, 0x37,
            0xa7, 0x77, 0x76, 0xb2, 0xec, 0x3f, 0xe2, 0xa3, 0x3a, 0xde, 0x72, 0x21, 0x76, 0x96,
            0x2b, 0x9c, 0x4f, 0x31, 0x3c, 0xb5, 0xe6, 0xcd, 0x17, 0x7f, 0x33, 0x40, 0xa4, 0xf,
            0x58, 0x7c, 0x12, 0x1d, 0x7, 0xfe, 0x57, 0x69,
        ]
        .as_ref()
    );
    assert_eq!(
        Fr::from_str(
            "43319743699496810973708981086850604276149960407194162211265932872777355818354"
        )
        .unwrap(),
        r
    );

    // test sample function
    let r1 = prng.sample("info");
    let r2 = prng.sample("info");
    assert_eq!(r1, r2);
    assert_eq!(
        Fr::from_str(
            "22074932395097706468768456200905687926580984780754047608537081666156889203804"
        )
        .unwrap(),
        r1
    );

    // test re-rerandomize function
    prng.rerandomize("seed", "info");
    let r3 = prng.sample_then_update("info");
    assert_eq!(
        Fr::from_str(
            "48069835158087822550484484210577332719983619747502722069618962092332582181716"
        )
        .unwrap(),
        r3
    );
    assert_eq!(
        prng.seed().as_ref(),
        [
            0x1a, 0x70, 0xb7, 0x82, 0xdd, 0x2a, 0x33, 0x4a, 0xca, 0xae, 0xa1, 0x4f, 0x5, 0x2, 0x96,
            0x39, 0x2b, 0x21, 0x2a, 0x99, 0xbc, 0x23, 0xf, 0x6b, 0x6b, 0x5f, 0xfe, 0xec, 0xee,
            0xeb, 0x4b, 0x23, 0x26, 0x4f, 0x9, 0xa0, 0xea, 0xc1, 0xfd, 0x18, 0x39, 0x54, 0x9, 0x98,
            0xe6, 0xb2, 0xc6, 0x54, 0x92, 0x51, 0x70, 0xe7, 0x70, 0x62, 0x2a, 0x54, 0xcb, 0x6d,
            0xfc, 0xec, 0x28, 0x9a, 0x9, 0x84,
        ]
        .as_ref()
    );
}
