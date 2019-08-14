use super::pixel::Pixel;
use super::pixel::PixelSignature;
use super::pixel::SerDes;
use super::pixel::{PublicKey, SecretKey, Signature};
use super::rand::Rng;
use criterion::Criterion;
use std::fs::File;

/// benchmark aggregation and batch verification
#[allow(dead_code)]
fn bench_aggregation(c: &mut Criterion) {
    const SAMPLES: usize = 3000;

    // this benchmark uses the default parameter
    let param = Pixel::param_default();

    // get a list of public keys
    let mut pklist: Vec<PublicKey> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let msg = "the message to be signed in benchmarking";
    let rngseed = "";
    // sign at time 1 for all signatures, for fast benchmarking
    // let max_time = (1 << param.depth()) - 1;
    // let time = rand::thread_rng().gen_range(0u64, max_time - 2);
    let time = 1;
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (pk, mut sk, _pop) = Pixel::key_gen(&seed, &param).unwrap();

        let res = Pixel::sign(&mut sk, time, &param, msg, rngseed);
        assert!(res.is_ok(), res.err());
        // pack the signature, time, and public key
        pklist.push(pk);
        siglist.push(res.unwrap());
    }

    // benchmarking aggregation
    let siglist_clone = siglist.clone();
    c.bench_function("benchmark aggregation", move |b| {
        b.iter(|| {
            let res = Pixel::aggregate_without_validate(&siglist_clone);
            assert!(res.is_ok(), "aggregation failed");
        })
    });

    // benchmarking verification
    let sig = Pixel::aggregate_without_validate(&siglist).unwrap();
    c.bench_function("verifying aggregated signature", move |b| {
        b.iter(|| {
            let res = Pixel::verify_aggregated(&pklist, &param, msg, &sig);
            assert!(res, "verification failed");
        })
    });
}

/// benchmark aggregation and batch verification
#[allow(dead_code)]
fn bench_aggregation_pre_key(c: &mut Criterion) {
    const SAMPLES1: usize = 1500;
    const SAMPLES2: usize = 3000;
    const SAMPLES3: usize = 10000;

    // this benchmark uses the default parameter
    let param = Pixel::param_default();

    let mut pklist_1500: Vec<PublicKey> = vec![];
    let mut siglist_1500: Vec<Signature> = vec![];

    let msg = "the message to be signed in benchmarking";
    let rngseed = "";
    let time = 1;

    // ================== 1500 samples =======================

    for i in 0..SAMPLES1 {
        // load the pre-generated keys
        let mut file = File::open(format!("benches/pre-keys/data/pk_bin_{:04?}.txt", i)).unwrap();
        let (pk, _) = PublicKey::deserialize(&mut file).unwrap();

        let mut file = File::open(format!("benches/pre-keys/data/sk_bin_{:04?}.txt", i)).unwrap();
        let (mut sk, _) = SecretKey::deserialize(&mut file).unwrap();

        let res = Pixel::sign(&mut sk, time, &param, msg, rngseed);
        assert!(res.is_ok(), res.err());
        // pack the signature, time, and public key
        pklist_1500.push(pk);
        siglist_1500.push(res.unwrap());
    }
    // benchmarking aggregation
    let siglist_clone = siglist_1500.clone();
    c.bench_function("benchmark aggregation of 1500 signatures", move |b| {
        b.iter(|| {
            let res = Pixel::aggregate_without_validate(&siglist_clone);
            assert!(res.is_ok(), "aggregation failed");
        })
    });

    // benchmarking verification
    let siglist_clone = siglist_1500.clone();
    let pklist_clone = pklist_1500.clone();
    let param_clone = param.clone();
    let sig = Pixel::aggregate_without_validate(&siglist_clone).unwrap();
    c.bench_function(
        "verifying aggregated signature of 1500 signatures",
        move |b| {
            b.iter(|| {
                let res = Pixel::verify_aggregated(&pklist_clone, &param_clone, msg, &sig);
                assert!(res, "verification failed");
            })
        },
    );

    // ================== 3000 samples =======================

    let mut pklist_3000 = pklist_1500.clone();
    let mut siglist_3000 = siglist_1500.clone();

    for i in SAMPLES1..SAMPLES2 {
        // load the pre-generated keys
        let mut file = File::open(format!("benches/pre-keys/data/pk_bin_{:04?}.txt", i)).unwrap();
        let (pk, _) = PublicKey::deserialize(&mut file).unwrap();

        let mut file = File::open(format!("benches/pre-keys/data/sk_bin_{:04?}.txt", i)).unwrap();
        let (mut sk, _) = SecretKey::deserialize(&mut file).unwrap();

        let res = Pixel::sign(&mut sk, time, &param, msg, rngseed);
        assert!(res.is_ok(), res.err());
        // pack the signature, time, and public key
        pklist_3000.push(pk);
        siglist_3000.push(res.unwrap());
    }

    // benchmarking aggregation
    let siglist_clone = siglist_3000.clone();
    c.bench_function("benchmark aggregation of 3000 signatures", move |b| {
        b.iter(|| {
            let res = Pixel::aggregate_without_validate(&siglist_clone);
            assert!(res.is_ok(), "aggregation failed");
        })
    });

    // benchmarking verification
    let siglist_clone = siglist_3000.clone();
    let pklist_clone = pklist_3000.clone();
    let param_clone = param.clone();
    let sig = Pixel::aggregate_without_validate(&siglist_clone).unwrap();
    c.bench_function(
        "verifying aggregated signature of 3000 signatures",
        move |b| {
            b.iter(|| {
                let res = Pixel::verify_aggregated(&pklist_clone, &param_clone, msg, &sig);
                assert!(res, "verification failed");
            })
        },
    );

    // ================== 10000 samples =======================

    let mut pklist_10000 = pklist_3000.clone();
    let mut siglist_10000 = siglist_3000.clone();

    for i in SAMPLES2..SAMPLES3 {
        // load the pre-generated keys
        let mut file = File::open(format!("benches/pre-keys/data/pk_bin_{:04?}.txt", i)).unwrap();
        let (pk, _) = PublicKey::deserialize(&mut file).unwrap();

        let mut file = File::open(format!("benches/pre-keys/data/sk_bin_{:04?}.txt", i)).unwrap();
        let (mut sk, _) = SecretKey::deserialize(&mut file).unwrap();

        let res = Pixel::sign(&mut sk, time, &param, msg, rngseed);
        assert!(res.is_ok(), res.err());
        // pack the signature, time, and public key
        pklist_10000.push(pk);
        siglist_10000.push(res.unwrap());
    }

    // benchmarking aggregation
    let siglist_clone = siglist_10000.clone();
    c.bench_function("benchmark aggregation of 10000 signatures", move |b| {
        b.iter(|| {
            let res = Pixel::aggregate_without_validate(&siglist_clone);
            assert!(res.is_ok(), "aggregation failed");
        })
    });

    // benchmarking verification
    let siglist_clone = siglist_10000.clone();
    let pklist_clone = pklist_10000.clone();
    let param_clone = param.clone();
    let sig = Pixel::aggregate_without_validate(&siglist_clone).unwrap();
    c.bench_function(
        "verifying aggregated signature of 10000 signatures",
        move |b| {
            b.iter(|| {
                let res = Pixel::verify_aggregated(&pklist_clone, &param_clone, msg, &sig);
                assert!(res, "verification failed");
            })
        },
    );
}

criterion_group!(aggregation_a_little_faster, bench_aggregation_pre_key);
criterion_group!(aggregation_really_really_slow, bench_aggregation,);
