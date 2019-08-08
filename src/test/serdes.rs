//use bls_sigs_ref_rs::SerDes;
use ff::PrimeField;
use key_pair::KeyPair;
use pairing::{bls12_381::*, CurveProjective};
use param::PubParam;
use sig::Signature;
use std::io::Cursor;
use subkeys::SubSecretKey;
use PixelG1;
use PixelG2;
use PixelSerDes;
use ProofOfPossession;
use PublicKey;
use SecretKey;
use VALID_CIPHERSUITE;

#[test]
fn test_ssk_serialization_rand() {
    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();
    let pp = PubParam::init_without_seed();
    // a random master secret key
    let mut alpha = pp.h();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    // generate a sub secret key
    let t = SubSecretKey::init(&pp, alpha, r);
    let bufsize = t.size();

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serialize a ssk into buffer
    assert!(t.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), bufsize, "length of blob is incorrect");
    // deserialize a buffer into ssk
    let (s, compressed) = SubSecretKey::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    // makes sure that the keys match
    assert_eq!(t, s);
}

#[test]
fn test_sk_serialization_rand() {
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

    let bufsize = sk.size();
    let estsize = SecretKey::estimate_size(1, pp.depth());
    assert_eq!(
        bufsize,
        estsize.unwrap(),
        "estimated size doesn't match the actual size"
    );

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serialize a ssk into buffer
    assert!(sk.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), bufsize, "length of blob is incorrect");
    // deserialize a buffer into ssk
    let (sk_recover, compressed) = SecretKey::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
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
        let bufsize = sk2.size();
        let estsize = SecretKey::estimate_size(j, pp.depth());
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
        let (sk_recover, compressed) = SecretKey::deserialize(&mut buf[..].as_ref()).unwrap();
        assert_eq!(compressed, true);
        assert_eq!(sk_recover, sk2);
    }
}

#[test]
fn test_pk_serialization_rand() {
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
    // serialize a ssk into buffer
    assert!(pk.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), PK_LEN, "length of blob is incorrect");

    // deserialize a buffer into ssk
    let (pk_recover, compressed) = PublicKey::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    // makes sure that the keys match
    assert_eq!(pk, pk_recover);
}

#[test]
fn test_signature_serialization_rand() {
    use SIG_LEN;
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "key gen failed");
    let (pk, sk, pop) = res.unwrap();
    assert!(pk.validate(&pop));

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, &pp, msg), "verification failed");

    // buffer space
    let mut buf: Vec<u8> = vec![];
    // serialize a ssk into buffer
    assert!(sig.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), SIG_LEN, "length of blob is incorrect");
    // deserialize a buffer into ssk
    let (sig_recover, compressed) = Signature::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    // makes sure that the keys match
    assert_eq!(sig, sig_recover);
}

#[test]
fn test_g1_serialization_rand() {
    // PixelG1::zero, compressed
    let g1_zero = PixelG1::zero();
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG1 element into buffer
    assert!(g1_zero.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let (g1_zero_recover, compressed) = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    assert_eq!(g1_zero, g1_zero_recover);

    // PixelG1::one, compressed
    let g1_one = PixelG1::one();
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG1 element into buffer
    assert!(g1_one.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let (g1_one_recover, compressed) = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    assert_eq!(g1_one, g1_one_recover);

    // PixelG1::zero, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG1 element into buffer
    assert!(g1_zero.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 192, "length of blob is incorrect");
    let (g1_zero_recover, compressed) = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, false);
    assert_eq!(g1_zero, g1_zero_recover);

    // PixelG1::one, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG1 element into buffer
    assert!(g1_one.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 192, "length of blob is incorrect");
    let (g1_one_recover, compressed) = PixelG1::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, false);
    assert_eq!(g1_one, g1_one_recover);
}

#[test]
fn test_g2_serialization_rand() {
    // PixelG2::zero, compressed
    let g2_zero = PixelG2::zero();
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG2 element into buffer
    assert!(g2_zero.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 48, "length of blob is incorrect");
    let (g2_zero_recover, compressed) = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    assert_eq!(g2_zero, g2_zero_recover);

    // PixelG2::one, compressed
    let g2_one = PixelG2::one();
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG2 element into buffer
    assert!(g2_one.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), 48, "length of blob is incorrect");
    let (g2_one_recover, compressed) = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, true);
    assert_eq!(g2_one, g2_one_recover);

    // PixelG2::zero, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG2 element into buffer
    assert!(g2_zero.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let (g2_zero_recover, compressed) = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();
    assert_eq!(compressed, false);
    assert_eq!(g2_zero, g2_zero_recover);

    // PixelG2::one, uncompressed
    let mut buf: Vec<u8> = vec![];
    // serialize a PixelG2 element into buffer
    assert!(g2_one.serialize(&mut buf, false).is_ok());
    assert_eq!(buf.len(), 96, "length of blob is incorrect");
    let (g2_one_recover, compressed) = PixelG2::deserialize(&mut buf[..].as_ref()).unwrap();

    assert_eq!(compressed, false);
    assert_eq!(g2_one, g2_one_recover);
}

// the encoding of a 0 element in G1 in compressed mode
#[cfg(test)]
const VALID_G1_ZERO_COM: &[u8] = &hex!(
    "c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the encoding of a 0 element in G1 in uncompressed mode
#[cfg(test)]
const VALID_G1_ZERO_UNCOM: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the encoding of a random element in G1 in compressed mode
#[cfg(test)]
const VALID_G1_COM: &[u8] = &hex!(
    "b8 d2 c4 1d 7a e7 d3 53 9d 81 52 82 85 28 50 60
    5c a3 cc 01 d6 93 9b 0e 2a 13 2b d0 3a 5a af cb
    d7 92 b5 e1 85 b4 be 72 e9 ad d9 e5 77 c1 76 66"
);

#[cfg(test)]
const VALID_G1_POINTS: [&[u8]; 3] = [VALID_G1_ZERO_COM, VALID_G1_COM, VALID_G1_ZERO_UNCOM];

// the 2-nd byte is changed
#[cfg(test)]
const INVALID_G1_ZERO_DATA_1: &[u8] = &hex!(
    "c0 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the 5-th byte is modified
#[cfg(test)]
const INVALID_G1_ZERO_DATA_2: &[u8] = &hex!(
    "40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the compressed flag is unset
#[cfg(test)]
const INVALID_G1_ZERO_COM: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the length is not correct
#[cfg(test)]
const INVALID_G1_ZERO_COM_LEN: &[u8] = &hex!(
    "c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the length is not correct
#[cfg(test)]
const INVALID_G1_ZERO_UNCOM_LEN: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// modified one byte
#[cfg(test)]
const INVALID_G1_DATA: &[u8] = &hex!(
    "b8 d2 c4 1d 7a e7 d3 53 9d 81 52 82 85 28 50 60
    5c a4 cc 01 d6 93 9b 0e 2a 13 2b d0 3a 5a af cb
    d7 92 b5 e1 85 b4 be 72 e9 ad d9 e5 77 c1 76 66"
);

// the length is not correct
#[cfg(test)]
const INVALID_G1_LEN: &[u8] = &hex!(
    "b8 d2 c4 1d 7a e7 d3 53 9d 81 52 82 85 28 50 60
    5c a3 cc 01 d6 93 9b 0e 2a 13 2b d0 3a 5a af cb
    d7 92 b5 e1 85 b4 be 72 e9 ad d9 e5 77 c1 76"
);

// the compressed flag is unset
#[cfg(test)]
const INVALID_G1_COM: &[u8] = &hex!(
    "28 d2 c4 1d 7a e7 d3 53 9d 81 52 82 85 28 50 60
    5c a3 cc 01 d6 93 9b 0e 2a 13 2b d0 3a 5a af cb
    d7 92 b5 e1 85 b4 be 72 e9 ad d9 e5 77 c1 76 66"
);

#[cfg(test)]
const INVALID_G1_POINTS: [&[u8]; 8] = [
    INVALID_G1_ZERO_DATA_1,
    INVALID_G1_ZERO_DATA_2,
    INVALID_G1_ZERO_COM,
    INVALID_G1_ZERO_COM_LEN,
    INVALID_G1_ZERO_UNCOM_LEN,
    INVALID_G1_DATA,
    INVALID_G1_LEN,
    INVALID_G1_COM,
];

#[cfg(test)]
const INVALID_CIPHERSUITE: [u8; 2] = [0x0f, 0xff];

#[test]
fn test_pk_serialization_kat() {
    // correct format of pks
    for &val in &VALID_G1_POINTS[..] {
        for &csid in &VALID_CIPHERSUITE {
            let tmp = [[csid].as_ref(), val].concat();
            let res = PublicKey::deserialize(&mut Cursor::new(tmp));
            assert!(res.is_ok(), "expected Ok, got Err: {:?}", res.err());
        }
    }

    // incorrect format
    for &inval in &INVALID_G1_POINTS[..] {
        for &csid in &VALID_CIPHERSUITE {
            let tmp = [[csid].as_ref(), inval].concat();
            let res = PublicKey::deserialize(&mut Cursor::new(tmp));
            assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
        }
    }

    // incorrect CSIDs
    for &val in &VALID_G1_POINTS[..] {
        for &csid in &INVALID_CIPHERSUITE {
            let tmp = [[csid].as_ref(), val].concat();
            let res = PublicKey::deserialize(&mut Cursor::new(tmp));
            assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
        }
    }
}

// the encoding of a 0 element in G2 in compressed mode
#[cfg(test)]
const VALID_G2_ZERO_COM: &[u8] = &hex!(
    "c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);
// the encoding of a 0 element in G2 in uncompressed mode
#[cfg(test)]
const VALID_G2_ZERO_UNCOM: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the encoding of a random element in G2 in compressed mode
#[cfg(test)]
const VALID_G2_COM: &[u8] = &hex!(
    "90 9c d3 34 a9 d0 cc 8e 7b 30 04 98 2b 92 8a ce
    41 07 fb 7e f5 21 05 74 26 6d 5a 84 35 5a e7 64
    7d 49 1a 1a cc 5e 3a d3 3a 8c ce 4f 47 09 b7 f6
    0e 7f d9 b1 cd 92 d8 9d 96 31 1f 4c 48 6c 35 d0
    e7 26 17 d9 16 06 1e a7 ae d7 cd 48 82 96 9e e5
    dc ae 56 8b 7f 1a 55 41 1b da 7b 2e 4b 66 b3 8d"
);

#[cfg(test)]
const VALID_G2_POINTS: [&[u8]; 3] = [VALID_G2_ZERO_COM, VALID_G2_COM, VALID_G2_ZERO_UNCOM];

// the 2-nd byte is modified
#[cfg(test)]
const INVALID_G2_ZERO_DATA_1: &[u8] = &hex!(
    "c0 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the 55-th byte is modified
#[cfg(test)]
const INVALID_G2_ZERO_DATA_2: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the compressed flag is unset
#[cfg(test)]
const INVALID_G2_ZERO_COM: &[u8] = &hex!(
    "40 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the length is not correct
#[cfg(test)]
const INVALID_G2_ZERO_COM_LEN: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// the length is not correct
#[cfg(test)]
const INVALID_G2_ZERO_UNCOM_LEN: &[u8] = &hex!(
    "40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
);

// one byte is altered
#[cfg(test)]
const INVALID_G2_DATA: &[u8] = &hex!(
    "90 9c d3 34 a9 d0 cc 8e 7b 30 04 98 2b 92 8a ce
    41 07 fb 7e f5 21 05 74 26 6d 5a 84 35 5a e7 64
    7d 49 1a 1a cc 5e 3a d3 3a 8c ce 4f 47 09 b7 f6
    0e 7f d9 b1 cd 92 d8 9d 96 31 1f 4c 48 6c 35 d0
    e7 26 17 d9 16 06 1e a7 ae d7 cd 48 82 96 9e e5
    dc ae 56 8b 7f 1a 55 41 1b da 7b 2e 4b 66 b3 9d"
);

// the length is not correct
#[cfg(test)]
const INVALID_G2_LEN: &[u8] = &hex!(
    "90 9c d3 34 a9 d0 cc 8e 7b 30 04 98 2b 92 8a ce
    41 07 fb 7e f5 21 05 74 26 6d 5a 84 35 5a e7 64
    7d 49 1a 1a cc 5e 3a d3 3a 8c ce 4f 47 09 b7 f6
    0e 7f d9 b1 cd 92 d8 9d 96 31 1f 4c 48 6c 35 d0
    e7 26 17 d9 16 06 1e a7 ae d7 cd 48 82 96 9e e5
    dc ae 56 8b 7f 1a 55 41 1b da 7b 2e 4b 66 b3"
);

// the compressed flag is unset
#[cfg(test)]
const INVALID_G2_COM: &[u8] = &hex!(
    "10 9c d3 34 a9 d0 cc 8e 7b 30 04 98 2b 92 8a ce
    41 07 fb 7e f5 21 05 74 26 6d 5a 84 35 5a e7 64
    7d 49 1a 1a cc 5e 3a d3 3a 8c ce 4f 47 09 b7 f6
    0e 7f d9 b1 cd 92 d8 9d 96 31 1f 4c 48 6c 35 d0
    e7 26 17 d9 16 06 1e a7 ae d7 cd 48 82 96 9e e5
    dc ae 56 8b 7f 1a 55 41 1b da 7b 2e 4b 66 b3 8d"
);

#[cfg(test)]
const INVALID_G2_POINTS: [&[u8]; 8] = [
    INVALID_G2_ZERO_DATA_1,
    INVALID_G2_ZERO_DATA_2,
    INVALID_G2_ZERO_COM,
    INVALID_G2_ZERO_COM_LEN,
    INVALID_G2_ZERO_UNCOM_LEN,
    INVALID_G2_DATA,
    INVALID_G2_LEN,
    INVALID_G2_COM,
];

#[test]
fn test_pop_serialization_kat() {
    // correct format of pops
    for &val in &VALID_G2_POINTS[0..2] {
        for &csid in &VALID_CIPHERSUITE {
            let tmp = [[csid].as_ref(), val].concat();
            let res = ProofOfPossession::deserialize(&mut Cursor::new(tmp));
            assert!(res.is_ok(), "expected Ok, got Err: {:?}", res.err());
        }
    }

    // incorrect compressness of pops
    for &csid in &VALID_CIPHERSUITE {
        let tmp = [[csid].as_ref(), &VALID_G2_POINTS[2]].concat();
        let res = ProofOfPossession::deserialize(&mut Cursor::new(tmp));
        assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
    }

    // incorrect format
    for &inval in &INVALID_G2_POINTS[..] {
        for &csid in &VALID_CIPHERSUITE {
            let tmp = [[csid].as_ref(), inval].concat();
            let res = ProofOfPossession::deserialize(&mut Cursor::new(tmp));
            assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
        }
    }

    // incorrect CSIDs
    for &val in &VALID_G2_POINTS[..] {
        for &csid in &INVALID_CIPHERSUITE {
            let tmp = [[csid].as_ref(), val].concat();
            let res = ProofOfPossession::deserialize(&mut Cursor::new(tmp));
            assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
        }
    }
}

#[test]
fn test_sig_serialization_kat_valid() {
    // correct format of signatures
    for &val1 in &VALID_G1_POINTS[0..2] {
        for &val2 in &VALID_G2_POINTS[0..2] {
            for &csid in &VALID_CIPHERSUITE {
                let time: [u8; 4] = [1, 2, 3, 4];
                let tmp = [[csid].as_ref(), time.as_ref(), val1, val2].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_ok(), "expected Ok, got Err: {:?}", res.err());
            }
        }
    }
}

#[test]
fn test_sig_serialization_kat_invalid_const() {
    // mix-match the compressness
    for &csid in &VALID_CIPHERSUITE {
        let val1 = VALID_G1_ZERO_COM;
        let val2 = VALID_G2_ZERO_UNCOM;
        let time: [u8; 4] = [1, 2, 3, 4];
        let tmp = [[csid].as_ref(), time.as_ref(), val1, val2].concat();
        let res = Signature::deserialize(&mut Cursor::new(tmp));
        assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
    }
    for &csid in &VALID_CIPHERSUITE {
        let val1 = VALID_G1_ZERO_UNCOM;
        let val2 = VALID_G2_ZERO_COM;
        let time: [u8; 4] = [1, 2, 3, 4];
        let tmp = [[csid].as_ref(), time.as_ref(), val1, val2].concat();
        let res = Signature::deserialize(&mut Cursor::new(tmp));
        assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
    }

    // incorrect csid
    for &val1 in &VALID_G1_POINTS[..] {
        for &val2 in &VALID_G2_POINTS[..] {
            for &csid in &INVALID_CIPHERSUITE {
                let time: [u8; 4] = [1, 2, 3, 4];
                let tmp = [[csid].as_ref(), time.as_ref(), val1, val2].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
            }
        }
    }
    // incorrect time stamp
    for &val1 in &VALID_G1_POINTS[..] {
        for &val2 in &VALID_G2_POINTS[..] {
            for &csid in &VALID_CIPHERSUITE {
                let time: [u8; 4] = [0; 4];
                let tmp = [[csid].as_ref(), time.as_ref(), val1, val2].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok());
            }
        }
    }
}

#[test]
fn test_sig_serialization_kat_invalid_points() {
    // incorrect G1 points
    for &inval1 in &INVALID_G1_POINTS[..] {
        for &val2 in &VALID_G2_POINTS[..] {
            for &csid in &VALID_CIPHERSUITE {
                let time: [u8; 4] = [1, 2, 3, 4];
                let tmp = [[csid].as_ref(), time.as_ref(), inval1, val2].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok())
            }
        }
    }

    // incorrect G2 points
    for &val1 in &VALID_G1_POINTS[..] {
        for &inval2 in &INVALID_G2_POINTS[..] {
            for &csid in &VALID_CIPHERSUITE {
                let time: [u8; 4] = [1, 2, 3, 4];
                let tmp = [[csid].as_ref(), time.as_ref(), val1, inval2].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok())
            }
        }
    }

    // incorrect G1 and G2 points
    for &inval1 in &INVALID_G1_POINTS[..] {
        for &inval2 in &INVALID_G2_POINTS[..] {
            for &csid in &VALID_CIPHERSUITE {
                let time: [u8; 4] = [1, 2, 3, 4];
                let tmp = [[csid].as_ref(), time.as_ref(), inval1, inval2].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok())
            }
        }
    }

    // incorrect order of G1 and G2 points
    for &val1 in &VALID_G1_POINTS[..] {
        for &val2 in &VALID_G2_POINTS[..] {
            for &csid in &VALID_CIPHERSUITE {
                let time: [u8; 4] = [1, 2, 3, 4];
                let tmp = [[csid].as_ref(), time.as_ref(), val2, val1].concat();
                let res = Signature::deserialize(&mut Cursor::new(tmp));
                assert!(res.is_err(), "expected Err, got Ok: {:?}", res.ok())
            }
        }
    }
}
