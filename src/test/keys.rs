use bls_sigs_ref_rs::SerDes;
use ff::PrimeField;
use keys::{KeyPair, PublicKey};
use pairing::{bls12_381::*, CurveProjective};
use param::PubParam;
use subkeys::SubSecretKey;
#[test]
fn test_keypair() {
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(
        res.is_ok(),
        "key gen failed\n\
         error message {:?}",
        res.err()
    );
    let keypair = res.unwrap();
    println!("{:?}", keypair);
}

#[test]
fn test_quick_key_update() {
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

    // this double loop
    // 1. performs key updates with all possible `start_time` and `finish_time`
    // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(
            res.is_ok(),
            "update failed\n\
             error message {:?}",
            res.err()
        );
        for ssk in sk2.get_ssk_vec() {
            assert!(ssk.validate(&keypair.get_pk(), &pp), "validation failed");
        }
    }
}

/// this test takes quite some time to finish
/// enable this test with `cargo test -- --ignored`
#[ignore]
#[test]
fn test_long_key_update() {
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

    // this double loop
    // 1. performs key updates with all possible `start_time` and `finish_time`
    // 2. for each updated key, checks the validity of its subkeys
    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(
            res.is_ok(),
            "update failed\n\
             error message {:?}",
            res.err()
        );
        for i in j + 1..16 {
            let mut sk3 = sk2.clone();
            let res = sk3.update(&pp, i);
            assert!(
                res.is_ok(),
                "update failed\n\
                 error message {:?}",
                res.err()
            );
            for ssk in sk3.get_ssk_vec() {
                assert!(ssk.validate(&keypair.get_pk(), &pp), "validation failed");
            }
        }
        for ssk in sk2.get_ssk_vec() {
            assert!(ssk.validate(&keypair.get_pk(), &pp), "validation failed");
        }
    }
}

#[test]
fn test_sk_validation() {
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
    assert!(sk.validate(&pk, &pp), "invalid sk");
    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(
            res.is_ok(),
            "update failed\n\
             error message {:?}",
            res.err()
        );
        assert!(sk2.validate(&pk, &pp), "invalid sk");
    }
}

/// this test takes quite some time to finish
/// enable this test with `cargo test -- --ignored`
#[ignore]
#[test]
fn test_long_sk_validation() {
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
    let sk = keypair.get_sk();
    assert!(sk.validate(&pk, &pp), "invalid sk");
    // this double loop
    // 1. performs key updates with all possible `start_time` and `finish_time`
    // 2. for each updated key, checks the validity
    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(
            res.is_ok(),
            "update failed\n\
             error message {:?}",
            res.err()
        );
        assert!(sk2.validate(&pk, &pp), "invalid sk");
        for i in j + 1..16 {
            let mut sk3 = sk2.clone();
            let res = sk3.update(&pp, i);
            assert!(
                res.is_ok(),
                "update failed\n\
                 error message {:?}",
                res.err()
            );
            assert!(sk3.validate(&pk, &pp), "invalid sk");
        }
    }
}

#[test]
fn test_key_gen() {
    use std::io::Cursor;

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

    let t = SubSecretKey::init(&pp, alpha, r);
    let res = SubSecretKey::init_from_randomization(&pp, alpha, r);
    assert!(
        res.is_ok(),
        "ssk initiation from randomization failed\n\
         error message: {:?}",
        res.err()
    );
    let t1 = res.unwrap();
    // make sure the sub secret keys are the same
    assert_eq!(t.get_g2r(), t1.get_g2r(), "g1r incorrect");
    assert_eq!(
        t.get_hpoly().into_affine(),
        t1.get_hpoly().into_affine(),
        "hpoly incorrect"
    );
    // buffer space -- this needs to be adquate for large parameters
    let mut scratch = [0u8; 10000];
    // serializae a ssk into buffer
    let buf = &mut Cursor::new(&mut scratch[..]);
    assert!(t.serialize(buf, true).is_ok());

    // buffer space -- this needs to be adquate for large parameters
    let mut scratch2 = [0u8; 10000];
    // serializae a ssk into buffer
    let buf2 = &mut Cursor::new(&mut scratch2[..]);
    assert!(t1.serialize(buf2, true).is_ok());
    for i in 0..buf.position() as usize {
        assert_eq!(scratch[i], scratch2[i], "ssk's do not match");
    }
}

#[test]
fn test_randomization() {
    use ff::PrimeField;
    let pp = PubParam::init_without_seed();
    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();

    // a random master secret key
    let mut alpha = pp.get_h();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    // a random public key
    let mut pke = pp.get_g2();
    pke.mul_assign(msk);
    let res = PublicKey::init(&pp, pke);
    assert!(
        res.is_ok(),
        "PK initialization failed\n\
         error message {:?}",
        res.err()
    );
    let pk = res.unwrap();

    // initialize a random secret key
    let mut t = SubSecretKey::init(&pp, alpha, r);
    // check if the key is valid or not
    assert!(t.validate(&pk, &pp), "initial key failure for validation");

    // randomize the key
    let r = Fr::from_str("12345").unwrap();
    let res = t.randomization(&pp, r);
    assert!(
        res.is_ok(),
        "randomization failed\n\
         error message: {:?}",
        res.err()
    );

    // check if the key remains valid or not
    assert!(
        t.validate(&pk, &pp),
        "randomized key failure for validation"
    );
}

#[test]
fn test_delegate() {
    let pp = PubParam::init_without_seed();
    let depth = pp.get_d();
    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();

    // a random master secret key
    let mut alpha = pp.get_h();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    // a random public key
    let mut pke = pp.get_g2();
    pke.mul_assign(msk);
    let res = PublicKey::init(&pp, pke);
    assert!(
        res.is_ok(),
        "PK initialization failed\n\
         error message {:?}",
        res.err()
    );
    let pk = res.unwrap();

    // initialize a random secret key
    let mut t = SubSecretKey::init(&pp, alpha, r);
    let t1 = t.clone();

    // check if the key is valid or not
    assert!(t.validate(&pk, &pp), "key validation failed");

    // randomize the key
    let r = Fr::from_str("12345").unwrap();
    let res = t.randomization(&pp, r);
    assert!(
        res.is_ok(),
        "randomization failed during ssk delegation\n\
         error message: {:?}",
        res.err()
    );
    // check if the key remains valid or not
    assert!(
        t.validate(&pk, &pp),
        "randomized key failure for validation"
    );

    // delegate gradually, 1 -> 2 -> 3 -> 4
    for i in 2..5 {
        // delegate the key to the time
        let res = t.delegate(i, depth);
        assert!(res.is_ok(), "delegation failed");
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after delation, \n{:?}",
            i,
            t
        );
        // randomize the key
        let res = t.randomization(&pp, r);
        assert!(
            res.is_ok(),
            "randomization failed during ssk delegation\n\
             error message: {:?}",
            res.err()
        );
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after randomizeation, \n{:?}",
            i,
            t
        );
    }

    // fast delegation, always starts from t = 1
    // 1 -> 2, 1 -> 3, 1 -> 4
    for i in 2..5 {
        let mut t = t1.clone();
        let res = t.delegate(i, depth);
        assert!(
            res.is_ok(),
            "delegation failed\n\
             error message {:?}",
            res.err()
        );
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after delation, \n{:?}",
            i,
            t
        );
        // randomize the key
        let res = t.randomization(&pp, r);
        assert!(
            res.is_ok(),
            "randomization failed during ssk delegation\n\
             error message: {:?}",
            res.err()
        );
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after randomizeation, \n{:?}",
            i,
            t
        );
    }
}