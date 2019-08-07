use key_pair::KeyPair;
use param::PubParam;
use pixel_err;
use sig::Signature;
use PublicKey;
use SecretKey;

/// Must fail tests for signatures
#[test]
fn test_must_fails_seed() {
    let res = PubParam::init(b"seed", 0);
    res.expect_err(pixel_err::ERR_SEED_TOO_SHORT);

    let pp = PubParam::default();
    let res = KeyPair::keygen(b"", &pp);
    res.expect_err(pixel_err::ERR_SEED_TOO_SHORT);
}

#[test]
fn test_must_fails_mismatch() {
    let pp1 = PubParam::default();
    let pp2 = pp1.clone();
    let pp3 = PubParam::init(b"this is a very very long seed for testing", 0).unwrap();

    let msg1 = b"message to sign";
    let msg2 = b"anther message to sign";

    let (pk1, sk1, pop1) =
        KeyPair::keygen(b"this is a very very long seed for testing", &pp1).unwrap();

    let (pk2, sk2, pop2) =
        KeyPair::keygen(b"this is another very very long seed for testing", &pp2).unwrap();

    let (pk3, _sk3, pop3) =
        KeyPair::keygen(b"this is a third very very long seed for testing", &pp3).unwrap();

    // use popi to validate pkj with i != j
    assert!(pk1.validate(&pop1));
    assert!(!pk1.validate(&pop2));
    assert!(!pk1.validate(&pop3));
    assert!(pk2.validate(&pop2));
    assert!(!pk2.validate(&pop1));
    assert!(!pk2.validate(&pop3));
    assert!(pk3.validate(&pop3));
    assert!(!pk3.validate(&pop1));
    assert!(!pk3.validate(&pop2));

    // mis-match the pk, sk, msg, pp, verification should fail
    let res = Signature::sign_bytes(&sk1, 1, &pp1, msg1);
    assert!(res.is_ok(), "signing failed");
    let sig11 = res.unwrap();

    let res = Signature::sign_bytes(&sk1, 1, &pp1, msg2);
    assert!(res.is_ok(), "signing failed");
    let sig12 = res.unwrap();

    assert!(sig11.verify_bytes(&pk1, &pp1, msg1));
    assert!(!sig11.verify_bytes(&pk2, &pp1, msg1));
    assert!(!sig11.verify_bytes(&pk1, &pp3, msg1));
    assert!(!sig11.verify_bytes(&pk1, &pp1, msg2));
    assert!(!sig12.verify_bytes(&pk1, &pp1, msg1));

    let res = Signature::sign_bytes(&sk2, 1, &pp1, msg1);
    assert!(res.is_ok(), "signing failed");
    let sig21 = res.unwrap();

    let res = Signature::sign_bytes(&sk2, 1, &pp1, msg2);
    assert!(res.is_ok(), "signing failed");
    let sig22 = res.unwrap();

    assert!(sig21.verify_bytes(&pk2, &pp2, msg1));
    assert!(!sig21.verify_bytes(&pk1, &pp1, msg1));
    assert!(!sig21.verify_bytes(&pk1, &pp3, msg1));
    assert!(!sig21.verify_bytes(&pk1, &pp1, msg2));
    assert!(!sig22.verify_bytes(&pk1, &pp1, msg1));
}

#[test]
fn test_must_fails_time_stamp() {
    let pp = PubParam::default();

    let msg = b"message to sign";

    let (_pk, mut sk, _pop) =
        KeyPair::keygen(b"this is a very very long seed for testing", &pp).unwrap();
    let mut sk2 = sk.clone();

    // sign for an invalid time stamp
    let res = Signature::sign_present(&mut sk, 2, &pp, msg);
    res.expect_err(pixel_err::ERR_TIME_STAMP);

    assert!(sk2.update(&pp, 10, b"").is_ok());

    // sign for present
    let res = Signature::sign_present(&mut sk2, 0, &pp, msg);
    res.expect_err(pixel_err::ERR_TIME_STAMP);

    let res = Signature::sign_present(&mut sk2, 9, &pp, msg);
    res.expect_err(pixel_err::ERR_TIME_STAMP);

    let res = Signature::sign_present(&mut sk2, 11, &pp, msg);
    res.expect_err(pixel_err::ERR_TIME_STAMP);

    // sign for present and future
    let res = Signature::sign(&mut sk2, 0, &pp, msg, b"");
    res.expect_err(pixel_err::ERR_TIME_STAMP);

    let res = Signature::sign(&mut sk2, 9, &pp, msg, b"");
    res.expect_err(pixel_err::ERR_TIME_STAMP);

    let res = Signature::sign(&mut sk2, 10, &pp, msg, b"");
    assert!(res.is_ok());

    // update sk2 to an invalid time stamp
    let res = sk2.update(&pp, 0, b"");
    res.expect_err(pixel_err::ERR_TIME_STAMP);
    let res = sk2.update(&pp, 9, b"");
    res.expect_err(pixel_err::ERR_TIME_STAMP);
    let res = sk2.update(&pp, 10, b"");
    res.expect_err(pixel_err::ERR_TIME_STAMP);
}

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
    let (pk, sk, pop) = res.unwrap();
    assert!(pk.validate(&pop));

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, &pp, msg), "verification failed");

    let seed = "";

    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j, seed.as_ref());
        assert!(res.is_ok(), "updating failed");
        let res = Signature::sign_bytes(&sk2, sk2.time(), &pp, msg);
        assert!(res.is_ok(), "signing failed");
        let sig = res.unwrap();
        assert!(
            sig.verify_bytes(&pk, &pp, msg),
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
    let (pk, sk, pop) = res.unwrap();
    assert!(pk.validate(&pop));

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, &pp, msg), "verification failed");

    let seed = "";
    // this double loop
    // 1. performs key updates with all possible `start_time` and `finish_time`
    // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
    // 3. check that the signature generated from dedicated keys can be verified
    for j in 2..16 {
        println!("delegate to time {}", j);
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j, seed.as_ref());
        assert!(res.is_ok(), "updating failed");
        assert!(sk2.validate(&pk, &pp), "validation failed");

        for i in j + 1..16 {
            println!("from time {} to  time {}", j, i);
            let mut sk3 = sk2.clone();
            let res = sk3.update(&pp, i, seed.as_ref());
            assert!(res.is_ok(), "updating failed");
            assert!(sk3.validate(&pk, &pp), "validation failed");

            let res = Signature::sign_bytes(&sk3, sk3.time(), &pp, msg);
            assert!(res.is_ok(), "signing failed");
            let sig = res.unwrap();
            assert!(
                sig.verify_bytes(&pk, &pp, msg),
                "signature verification failed"
            );
        }
        let res = Signature::sign_bytes(&sk2, sk2.time(), &pp, msg);
        assert!(res.is_ok(), "signing failed");
        let sig = res.unwrap();
        assert!(
            sig.verify_bytes(&pk, &pp, msg),
            "signature verification failed"
        );
    }
}

// A simple and quick tests on
/// * key generation
/// * key update
/// * sign
/// * aggregation
/// * batch verification
#[test]
fn test_quick_aggregated_signature_tests() {
    let pp = PubParam::init_without_seed();

    let mut sklist: Vec<SecretKey> = vec![];
    let mut pklist: Vec<PublicKey> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    for i in 0..10 {
        let key_gen_seed = format!("this is a very very long seed for testing #{}", i);

        let res = KeyPair::keygen(key_gen_seed.as_ref(), &pp);
        assert!(res.is_ok(), "key gen failed");
        let (pk, sk, pop) = res.unwrap();
        assert!(pk.validate(&pop));
        sklist.push(sk);
        pklist.push(pk);
    }

    let msg = b"message to sign";

    // generate 10 signatures on a same message
    for i in 0..10 {
        let res = Signature::sign_bytes(&sklist[i], 1, &pp, msg);
        assert!(res.is_ok(), "signing failed");
        let sig = res.unwrap();
        assert!(
            sig.verify_bytes(&pklist[i], &pp, msg),
            "verification failed"
        );
        siglist.push(sig);
    }

    // aggregate the siganture and then verify it
    let sig_agg = Signature::aggregate_without_validate(&siglist).unwrap();
    let res = sig_agg.verify_bytes_aggregated(&pklist, &pp, msg);

    assert!(res, "verifying aggregates signature failed.");

    let seed = "";
    for j in 2..16 {
        let mut sklist2 = sklist.clone();
        for i in 0..10 {
            let res = sklist2[i].update(&pp, j, seed.as_ref());
            assert!(res.is_ok(), "updating failed");

            let res = Signature::sign_bytes(&sklist2[i], sklist2[i].time(), &pp, msg);
            assert!(res.is_ok(), "signing failed");
            let sig = res.unwrap();
            assert!(
                sig.verify_bytes(&pklist[i], &pp, msg),
                "signature verification failed"
            );
        }
        let sig_agg = Signature::aggregate_without_validate(&siglist).unwrap();
        let res = sig_agg.verify_bytes_aggregated(&pklist, &pp, msg);

        assert!(res, "verifying aggregates signature failed.");
    }
}

// A simple and long tests on
/// * key generation
/// * key update
/// * sign
/// * aggregation
/// * batch verification
#[test]
#[ignore]
fn test_long_aggregated_signature_tests() {
    let pp = PubParam::init_without_seed();

    let mut sklist: Vec<SecretKey> = vec![];
    let mut pklist: Vec<PublicKey> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    for i in 0..10 {
        let key_gen_seed = format!("this is a very very long seed for testing #{}", i);

        let res = KeyPair::keygen(key_gen_seed.as_ref(), &pp);
        assert!(res.is_ok(), "key gen failed");
        let (pk, sk, pop) = res.unwrap();
        assert!(pk.validate(&pop));
        sklist.push(sk);
        pklist.push(pk);
    }

    let msg = b"message to sign";

    // generate 10 signatures on a same message
    for i in 0..10 {
        let res = Signature::sign_bytes(&sklist[i], 1, &pp, msg);
        assert!(res.is_ok(), "signing failed");
        let sig = res.unwrap();
        assert!(
            sig.verify_bytes(&pklist[i], &pp, msg),
            "verification failed"
        );
        siglist.push(sig);
    }

    // aggregate the siganture and then verify it
    let sig_agg = Signature::aggregate_without_validate(&siglist).unwrap();
    let res = sig_agg.verify_bytes_aggregated(&pklist, &pp, msg);

    assert!(res, "verifying aggregates signature failed.");
    let seed = "";
    for j in 2..16 {
        println!("delegate to time {}", j);
        let mut sklist2 = sklist.clone();
        for i in 0..10 {
            let res = sklist2[i].update(&pp, j, seed.as_ref());
            assert!(res.is_ok(), "updating failed");

            let res = Signature::sign_bytes(&sklist2[i], sklist2[i].time(), &pp, msg);
            assert!(res.is_ok(), "signing failed");
            let sig = res.unwrap();
            assert!(
                sig.verify_bytes(&pklist[i], &pp, msg),
                "signature verification failed"
            );
        }
        let sig_agg = Signature::aggregate_without_validate(&siglist).unwrap();
        let res = sig_agg.verify_bytes_aggregated(&pklist, &pp, msg);

        assert!(res, "verifying aggregates signature failed.");
    }
}
