use bls_sigs_ref_rs::SerDes;
use ff::PrimeField;
use keys::{KeyPair, PublicKey, SecretKey};
use pairing::{bls12_381::*, CurveProjective};
use param::PubParam;
use sig::Signature;
use subkeys::SubSecretKey;

use std::io::Cursor;

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

    // buffer space -- this needs to be adquate for large parameters
    let mut scratch = vec![0u8; bufsize];
    // serializae a ssk into buffer
    let buf = &mut Cursor::new(&mut scratch[..]);
    assert!(t.serialize(buf, true).is_ok());
    // make sure the buf size is the same as sk.get_size()
    assert_eq!(buf.position() as usize, bufsize);

    // deserialize a buffer into ssk
    let buf = &mut Cursor::new(&mut scratch[..]);
    let s = SubSecretKey::deserialize(buf).unwrap();

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
    let keypair = res.unwrap();
    let sk = keypair.get_sk();
    let pk = keypair.get_pk();

    // buffer space -- this needs to be adquate for large parameters
    let bufsize = sk.get_size();
    let mut scratch = vec![0u8; bufsize];
    // serializae a ssk into buffer
    let buf = &mut Cursor::new(&mut scratch[..]);
    assert!(sk.serialize(buf, true).is_ok());
    // make sure the buf size is the same as sk.get_size()
    assert_eq!(buf.position() as usize, bufsize);
    // deserialize a buffer into ssk
    let buf = &mut Cursor::new(&mut scratch[..]);
    let sk_recover = SecretKey::deserialize(buf).unwrap();
    // makes sure that the keys match
    assert_eq!(sk, sk_recover);

    // perform the same serialization/deserialization for the
    // keys from updating
    for j in 2..16 {
        // update keys
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(
            res.is_ok(),
            "update failed\n\
             error message {:?}",
            res.err()
        );
        assert!(sk2.validate(&pk, &pp), "invalid sk");

        // serialize the updated key
        let bufsize = sk2.get_size();
        let mut scratch = vec![0u8; bufsize];
        let buf = &mut Cursor::new(&mut scratch[..]);
        assert!(sk2.serialize(buf, true).is_ok());
        // make sure the buf size is the same as sk.get_size()
        assert_eq!(buf.position() as usize, bufsize);
        // deserialize a buffer into ssk
        let buf = &mut Cursor::new(&mut scratch[..]);
        let sk_recover = SecretKey::deserialize(buf).unwrap();
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
    let keypair = res.unwrap();
    let pk = keypair.get_pk();

    // buffer space -- this needs to be adquate for large parameters
    let mut scratch = [0u8; PK_LEN];
    // serializae a ssk into buffer
    let buf = &mut Cursor::new(&mut scratch[..]);
    assert!(pk.serialize(buf, true).is_ok());

    // deserialize a buffer into ssk
    let buf = &mut Cursor::new(&mut scratch[..]);
    let pk_recover = PublicKey::deserialize(buf).unwrap();
    // makes sure that the keys match
    assert_eq!(pk, pk_recover);
}

#[test]
fn test_param_serialization() {
    use PP_LEN;
    let pp = PubParam::init_without_seed();

    // buffer space -- this needs to be adquate for large parameters
    let mut scratch = [0u8; PP_LEN];
    // serializae a ssk into buffer
    let buf = &mut Cursor::new(&mut scratch[..]);
    assert!(pp.serialize(buf, true).is_ok());
    println!("{} {} {}", buf.position(), PP_LEN, pp.get_size());

    // deserialize a buffer into ssk
    let buf = &mut Cursor::new(&mut scratch[..]);
    let pp_recover = PubParam::deserialize(buf).unwrap();
    // makes sure that the keys match
    assert_eq!(pp, pp_recover);
}

#[test]
fn test_signature_serialization() {
    use SIG_LEN;
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "key gen failed");
    let keypair = res.unwrap();
    let sk = keypair.get_sk();
    let pk = keypair.get_pk();

    let seedr = b"this is also a very very long seed for testing";
    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg, seedr);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, 1, &pp, msg), "verification failed");

    // buffer space -- this needs to be adquate for large parameters
    let mut scratch = [0u8; SIG_LEN];
    // serializae a ssk into buffer
    let buf = &mut Cursor::new(&mut scratch[..]);
    assert!(sig.serialize(buf, true).is_ok());

    // deserialize a buffer into ssk
    let buf = &mut Cursor::new(&mut scratch[..]);
    let sig_recover = Signature::deserialize(buf).unwrap();
    // makes sure that the keys match
    assert_eq!(sig, sig_recover);
}
