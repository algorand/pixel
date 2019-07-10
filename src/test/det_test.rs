/// This module contains deterministic tests, with pre-fixed parameters,
/// and with determinstic, small random numbers, e.g., 1, 2, 3, 4...
/// This test module is only avaliable when public key lies in G2.
use ff::PrimeField;
use keys::{PublicKey, SecretKey};
use pairing::{bls12_381::*, CurveProjective, EncodedPoint};
use param::PubParam;
use sig;

#[test]
fn test_det() {
    let pp = PubParam::det_param_gen();
    println!("param: {:?}", pp);

    let msk = Fr::from_str("3").unwrap();
    let mut pke = pp.get_g2();
    pke.mul_assign(msk);
    let pk = PublicKey::init(&pp, pke).unwrap();

    let mut alpha = pp.get_h();
    alpha.mul_assign(msk);

    let r = Fr::from_str("2").unwrap();
    let sk = SecretKey::init_det(&pp, alpha, r, &[0; 32]);

    let msg = Fr::from_str("1").unwrap();

    let sig = match sig::Signature::sign_fr(&sk, 1, &pp, msg, r) {
        Err(e) => panic!("failed to sign the message {}", e),
        Ok(p) => p,
    };

    // we check if the secret key matches known other implementations
    // by checking the first two elements in the first sub secret key
    let ssk = match sk.get_first_ssk() {
        Err(e) => panic!("failed to get the 1-st ssk {}", e),
        Ok(p) => p,
    };
    // secret key
    // 0-th element
    //         x0 = 0x1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053
    //         x1 = 0x0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577
    //         y0 = 0x0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899
    //         y1 = 0x0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3
    let g2r_kat: [u8; 96] = [
        0xaa, 0x4e, 0xde, 0xf9, 0xc1, 0xed, 0x7f, 0x72, 0x9f, 0x52, 0x0e, 0x47, 0x73, 0x0a, 0x12,
        0x4f, 0xd7, 0x06, 0x62, 0xa9, 0x04, 0xba, 0x10, 0x74, 0x72, 0x81, 0x14, 0xd1, 0x03, 0x1e,
        0x15, 0x72, 0xc6, 0xc8, 0x86, 0xf6, 0xb5, 0x7e, 0xc7, 0x2a, 0x61, 0x78, 0x28, 0x8c, 0x47,
        0xc3, 0x35, 0x77, 0x16, 0x38, 0x53, 0x39, 0x57, 0xd5, 0x40, 0xa9, 0xd2, 0x37, 0x0f, 0x17,
        0xcc, 0x7e, 0xd5, 0x86, 0x3b, 0xc0, 0xb9, 0x95, 0xb8, 0x82, 0x5e, 0x0e, 0xe1, 0xea, 0x1e,
        0x1e, 0x4d, 0x00, 0xdb, 0xae, 0x81, 0xf1, 0x4b, 0x0b, 0xf3, 0x61, 0x1b, 0x78, 0xc9, 0x52,
        0xaa, 0xca, 0xb8, 0x27, 0xa0, 0x53,
    ];
    // 1-th element
    //          x = 0x10e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc
    //          y = 0x16ba437edcc6551e30c10512367494bfb6b01cc6681e8a4c3cd2501832ab5c4abc40b4578b85cbaffbf0bcd70d67c6e2
    let hpoly_kat: [u8; 48] = [
        0xb0, 0xe7, 0x79, 0x1f, 0xb9, 0x72, 0xfe, 0x01, 0x41, 0x59, 0xaa, 0x33, 0xa9, 0x86, 0x22,
        0xda, 0x3c, 0xdc, 0x98, 0xff, 0x70, 0x79, 0x65, 0xe5, 0x36, 0xd8, 0x63, 0x6b, 0x5f, 0xcc,
        0x5a, 0xc7, 0xa9, 0x1a, 0x8c, 0x46, 0xe5, 0x9a, 0x00, 0xdc, 0xa5, 0x75, 0xaf, 0x0f, 0x18,
        0xfb, 0x13, 0xdc,
    ];

    // intermidiate elemetns are omited here since we do not have public API to read
    // elements in an ssk::h_vector other than the last elements

    // 5-th element
    //         x = 0x0f81da25ecf1c84b577fefbedd61077a81dc43b00304015b2b596ab67f00e41c86bb00ebd0f90d4b125eb0539891aeed
    //         y = 0x11af629591ec86916d6ce37877b743fe209a3af61147996c1df7fd1c47b03181cd806fd31c3071b739e4deb234bd9e19
    let hvlast_kat: [u8; 48] = [
        0xaf, 0x81, 0xda, 0x25, 0xec, 0xf1, 0xc8, 0x4b, 0x57, 0x7f, 0xef, 0xbe, 0xdd, 0x61, 0x07,
        0x7a, 0x81, 0xdc, 0x43, 0xb0, 0x03, 0x04, 0x01, 0x5b, 0x2b, 0x59, 0x6a, 0xb6, 0x7f, 0x00,
        0xe4, 0x1c, 0x86, 0xbb, 0x00, 0xeb, 0xd0, 0xf9, 0x0d, 0x4b, 0x12, 0x5e, 0xb0, 0x53, 0x98,
        0x91, 0xae, 0xed,
    ];

    // compare g2r
    let g2r = ssk.get_g2r();
    let g2r_str = G2Compressed::from_affine(g2r.into_affine());

    assert_eq!(
        g2r_str.as_ref(),
        g2r_kat.as_ref(),
        "incorret g2r in secret key"
    );

    // compare hpoly
    let hpoly = ssk.get_hpoly();
    let hpoly_str = G1Compressed::from_affine(hpoly.into_affine());
    assert_eq!(
        hpoly_str.as_ref(),
        hpoly_kat.as_ref(),
        "incorret hpoly in secret key"
    );

    // compare last element in secert key
    let hvlast = match ssk.get_last_hvector_coeff() {
        Err(e) => panic!("failed to get the last elemet from hv {}", e),
        Ok(p) => p,
    };
    let hvlast_str = G1Compressed::from_affine(hvlast.into_affine());
    assert_eq!(
        hvlast_str.as_ref(),
        hvlast_kat.as_ref(),
        "incorret hpoly in secret key"
    );

    // make sure the signature can be verified
    assert!(sig.verify_fr(&pk, &pp, msg), "Verification failed");
    //    assert_eq!(1, 2)
}
