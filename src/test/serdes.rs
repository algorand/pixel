//use bls_sigs_ref_rs::SerDes;
use ff::PrimeField;
use key_pair::KeyPair;
use pairing::{bls12_381::*, CurveProjective};
use param::PubParam;
use sig::Signature;
use subkeys::SubSecretKey;
use PixelG1;
use PixelG2;
use PixelSerDes;
use PublicKey;
use SecretKey;

#[test]
fn test_ssk_serialization() {
    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();
    let pp = PubParam::init_without_seed();
    // a random master secret key
    let mut alpha = pp.get_h();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    // generate a sub secret key
    let t = SubSecretKey::init(&pp, alpha, r);
    let bufsize = t.get_size();

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serializae a ssk into buffer
    assert!(t.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), bufsize, "length of blob is incorrect");
    // deserialize a buffer into ssk
    let s = SubSecretKey::deserialize(&mut buf[..].as_ref()).unwrap();

    // makes sure that the keys match
    assert_eq!(t, s);
}

#[test]
fn test_sk_serialization() {
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(
        res.is_ok(),
        "key gen failed\n\
         error message {:?}",
        res.err()
    );
    let (pk, sk, pop) = res.unwrap();
    assert!(pk.validate(&pop));

    let bufsize = sk.get_size();
    let estsize = SecretKey::estimate_size(1, pp.get_d());
    assert_eq!(
        bufsize,
        estsize.unwrap(),
        "estimated size doesn't match the actual size"
    );

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serializae a ssk into buffer
    assert!(sk.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), bufsize, "length of blob is incorrect");
    // deserialize a buffer into ssk
    let sk_recover = SecretKey::deserialize(&mut buf[..].as_ref()).unwrap();
    // makes sure that the keys match
    assert_eq!(sk, sk_recover);

    // perform the same serialization/deserialization for the
    // keys from updating
    let seed = "";
    for j in 2..16 {
        // update keys
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j, seed.as_ref());
        assert!(
            res.is_ok(),
            "update failed\n\
             error message {:?}",
            res.err()
        );
        assert!(sk2.validate(&pk, &pp), "invalid sk");

        // serialize the updated key
        let bufsize = sk2.get_size();
        let estsize = SecretKey::estimate_size(j, pp.get_d());
        assert_eq!(
            bufsize,
            estsize.unwrap(),
            "estimated size doesn't match the actual size"
        );

        // buffer space
        let mut buf: Vec<u8> = vec![];
        assert!(sk2.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), bufsize, "length of blob is incorrect");
        // deserialize a buffer into ssk
        let sk_recover = SecretKey::deserialize(&mut buf[..].as_ref()).unwrap();
        assert_eq!(sk_recover, sk2);
    }
}

#[test]
fn test_pk_serialization() {
    use PK_LEN;

    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(
        res.is_ok(),
        "key gen failed\n\
         error message {:?}",
        res.err()
    );
    let (pk, _sk, pop) = res.unwrap();
    assert!(pk.validate(&pop));

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serializae a ssk into buffer
    assert!(pk.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), PK_LEN, "length of blob is incorrect");

    // deserialize a buffer into ssk
    let pk_recover = PublicKey::deserialize(&mut buf[..].as_ref()).unwrap();
    // makes sure that the keys match
    assert_eq!(pk, pk_recover);
}

// #[test]
// fn test_param_serialization() {
//     use PP_LEN;
//     let pp = PubParam::init_without_seed();
//
//     // buffer space
//     let mut buf: Vec<u8> = vec![];
//
//     // serializae a ssk into buffer
//     assert!(pp.serialize(&mut buf, true).is_ok());
//     assert_eq!(buf.len(), PP_LEN, "length of blob is incorrect");
//
//     // deserialize a buffer into ssk
//     let pp_recover = PubParam::deserialize(&mut buf[..].as_ref()).unwrap();
//     // makes sure that the keys match
//     assert_eq!(pp, pp_recover);
// }

#[test]
fn test_signature_serialization() {
    use SIG_LEN;
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "key gen failed");
    let (pk, sk, pop) = res.unwrap();
    assert!(pk.validate(&pop));

    //    let seedr = b"this is also a very very long seed for testing";
    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, &pp, msg), "verification failed");

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serializae a ssk into buffer
    assert!(sig.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), SIG_LEN, "length of blob is incorrect");
    // deserialize a buffer into ssk
    let sig_recover = Signature::deserialize(&mut buf[..].as_ref()).unwrap();
    println!("{:?}", sig_recover);
    // makes sure that the keys match
    assert_eq!(sig, sig_recover);
}

#[test]
fn test_group_serialization() {
    // PixelG1::zero, compressed
    let g1_zero = PixelG1::zero();
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g1_zero.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let g1_zero_recover = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();
    println!("g1: zero {:02x?}", buf);
    assert_eq!(g1_zero, g1_zero_recover);

    // PixelG1::one, compressed
    let g1_one = PixelG1::one();
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g1_one.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let g1_one_recover = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();

    println!("g1: one {:02x?}", buf);
    assert_eq!(g1_one, g1_one_recover);

    // PixelG1::zero, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g1_zero.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 192, "length of blob is incorrect");
    let g1_zero_recover = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();
    println!("g1: zero {:02x?}", buf);
    assert_eq!(g1_zero, g1_zero_recover);

    // PixelG1::one, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g1_one.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 192, "length of blob is incorrect");
    let g1_one_recover = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();

    println!("g1: one {:02x?}", buf);
    assert_eq!(g1_one, g1_one_recover);

    // PixelG2::zero, compressed
    let g2_zero = PixelG2::zero();
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g2_zero.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 48, "length of blob is incorrect");
    let g2_zero_recover = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();
    println!("g2: zero {:02x?}", buf);
    assert_eq!(g2_zero, g2_zero_recover);

    // PixelG2::one, compressed
    let g2_one = PixelG2::one();
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g2_one.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 48, "length of blob is incorrect");
    let g2_one_recover = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();

    println!("g2: one {:02x?}", buf);
    assert_eq!(g2_one, g2_one_recover);

    // PixelG2::zero, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g2_zero.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let g2_zero_recover = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();
    println!("g2: zero {:02x?}", buf);
    assert_eq!(g2_zero, g2_zero_recover);

    // PixelG2::one, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serializae a PixelG1 element into buffer
    assert!(g2_one.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let g2_one_recover = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();

    println!("g2: one {:02x?}", buf);
    assert_eq!(g2_one, g2_one_recover);
}
