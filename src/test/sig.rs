use keys::{KeyPair, PublicKey, SecretKey};
use param::PubParam;
use sig::Signature;

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
    let seedr = b"this is also a very very long seed for testing";

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg, seedr);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, &pp, msg), "verification failed");

    for j in 2..16 {
        let mut sk2 = sk.clone();
        let res = sk2.update(&pp, j);
        assert!(res.is_ok(), "updating failed");
        let seedr = [
            b"this is also a very very long seed for testing",
            [j as u8].as_ref(),
        ]
        .concat();
        let res = Signature::sign_bytes(&sk2, sk2.get_time(), &pp, msg, seedr.as_ref());
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
    let seedr = b"this is also a very very long seed for testing";

    let msg = b"message to sign";
    let res = Signature::sign_bytes(&sk, 1, &pp, msg, seedr);
    assert!(res.is_ok(), "signing failed");
    let sig = res.unwrap();
    assert!(sig.verify_bytes(&pk, &pp, msg), "verification failed");

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
            let seedr = [
                b"this is also a very very long seed for testing",
                [(i * 16 + j) as u8].as_ref(),
            ]
            .concat();

            let res = Signature::sign_bytes(&sk3, sk3.get_time(), &pp, msg, seedr.as_ref());
            assert!(res.is_ok(), "signing failed");
            let sig = res.unwrap();
            assert!(
                sig.verify_bytes(&pk, &pp, msg),
                "signature verification failed"
            );
        }

        let seedr = [
            b"this is also a very very long seed for testing",
            [255u8].as_ref(),
        ]
        .concat();
        let res = Signature::sign_bytes(&sk2, sk2.get_time(), &pp, msg, seedr.as_ref());
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

    let seedr = b"this is also a very very long seed for testing";
    let msg = b"message to sign";

    // generate 10 signatures on a same message
    for i in 0..10 {
        let res = Signature::sign_bytes(&sklist[i], 1, &pp, msg, seedr);
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

    for j in 2..16 {
        let seedr = [
            b"this is also a very very long seed for testing",
            [j as u8].as_ref(),
        ]
        .concat();
        let mut sklist2 = sklist.clone();
        for i in 0..10 {
            let res = sklist2[i].update(&pp, j);
            assert!(res.is_ok(), "updating failed");

            let res =
                Signature::sign_bytes(&sklist2[i], sklist2[i].get_time(), &pp, msg, seedr.as_ref());
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
