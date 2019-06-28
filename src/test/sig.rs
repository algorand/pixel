use bls_sigs_ref_rs::FromRO;
use keys::KeyPair;
use pairing::bls12_381::Fr;
use param::PubParam;
use sig::Signature;
//    use util;

/// A simple and quick tests on
/// * key generation
/// * key update
/// * sign
/// * verification
#[test]
fn test_quick_signature_tests() {
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "key gen failed");
    let keypair = res.unwrap();
    let sk = keypair.get_sk();
    let pk = keypair.get_pk();
    let r = Fr::from_ro("this is also a very very long seed for testing", 0);

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg, r);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, 1, &pp, msg), "verification failed");

    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(res.is_ok(), "updating failed");
        let r = Fr::from_ro("this is also a very very long seed for testing", j as u8);
        let res = Signature::sign_bytes(&sk2, sk2.get_time(), &pp, msg, r);
        assert!(res.is_ok(), "signing failed");
        let sig = res.unwrap();
        assert!(
            sig.verify_bytes(&pk, sk2.get_time(), &pp, msg),
            "signature verification failed"
        );
    }
}

/// this test takes quite some time to finish
/// enable this test with `cargo test -- --ignored`
#[ignore]
#[test]
fn test_long_signature_tests() {
    let pp = PubParam::init_without_seed();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "key gen failed");
    let keypair = res.unwrap();
    let sk = keypair.get_sk();
    let pk = keypair.get_pk();
    let r = Fr::from_ro("this is also a very very long seed for testing", 0);

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg, r);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, 1, &pp, msg), "verification failed");

    // this double loop
    // 1. performs key updates with all possible `start_time` and `finish_time`
    // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
    // 3. check that the signature generated from dedicated keys can be verified
    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(res.is_ok(), "updating failed");
        assert!(sk2.validate(&pk, &pp), "validation failed");

        for i in j + 1..16 {
            let mut sk3 = sk2.clone();
            let res = sk3.update(&pp, i);
            assert!(res.is_ok(), "updating failed");
            assert!(sk3.validate(&pk, &pp), "validation failed");
            let r = Fr::from_ro(
                "this is also a very very long seed for testing",
                (i * 16 + j) as u8,
            );

            let res = Signature::sign_bytes(&sk3, sk3.get_time(), &pp, msg, r);
            assert!(res.is_ok(), "signing failed");
            let sig = res.unwrap();
            assert!(
                sig.verify_bytes(&pk, sk3.get_time(), &pp, msg),
                "signature verification failed"
            );
        }

        let r = Fr::from_ro("this is also a very very long seed for testing", 255);

        let res = Signature::sign_bytes(&sk2, sk2.get_time(), &pp, msg, r);
        assert!(res.is_ok(), "signing failed");
        let sig = res.unwrap();
        assert!(
            sig.verify_bytes(&pk, sk2.get_time(), &pp, msg),
            "signature verification failed"
        );
    }
}
