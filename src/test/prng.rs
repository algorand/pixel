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
    // test sample then update function
    let mut prng = PRNG::init("seed", "salt");
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
            "32890402084710667245046597308402496366454088307637968550797980643842065899032"
        )
        .unwrap(),
        r3
    );
    assert_eq!(
        prng.seed().as_ref(),
        [
            0x4d, 0x9a, 0xfd, 0x66, 0x33, 0x1d, 0x74, 0xba, 0x5f, 0xa8, 0x36, 0x65, 0xfe, 0xb1,
            0xf8, 0x42, 0x2f, 0xb1, 0x62, 0xc1, 0x8a, 0x5c, 0xf1, 0xe9, 0x24, 0xed, 0x13, 0xee,
            0x52, 0xdc, 0x4a, 0xca, 0xd5, 0x36, 0x9f, 0xd2, 0x8d, 0x2e, 0xc5, 0x75, 0x5f, 0x23,
            0xa9, 0x3e, 0x81, 0x9f, 0x1, 0x5a, 0xad, 0xcf, 0xf8, 0xcc, 0x84, 0x23, 0x9c, 0x72,
            0xad, 0xca, 0x33, 0x75, 0x15, 0x79, 0x20, 0x73,
        ]
        .as_ref()
    );
}
