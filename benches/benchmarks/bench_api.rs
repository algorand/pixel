use super::pixel::Pixel;
use super::pixel::PixelSignature;
use super::pixel::{ProofOfPossession, PublicKey, SecretKey, Signature};
use super::rand::Rng;
use criterion::Criterion;

/// benchmark parameter generation
#[allow(dead_code)]
fn bench_param(c: &mut Criterion) {
    // benchmarking
    c.bench_function("param generation", move |b| {
        b.iter(|| {
            // get a new of seeds for parameter gen
            let seed = rand::thread_rng()
                .gen_ascii_chars()
                .take(32)
                .collect::<String>();
            let res = Pixel::param_gen(&seed, 0);
            assert!(res.is_ok(), res.err());
        })
    });
}

/// benchmark key generation
#[allow(dead_code)]
fn bench_keygen(c: &mut Criterion) {
    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // benchmarking
    c.bench_function("key generation", move |b| {
        b.iter(|| {
            // a new seed for each new key gen
            let seed = rand::thread_rng()
                .gen_ascii_chars()
                .take(32)
                .collect::<String>();
            let res = Pixel::key_gen(&seed, &param);
            assert!(res.is_ok(), res.err());
        })
    });
}

/// benchmark key update: update to the next time stamp
#[allow(dead_code)]
fn bench_key_update_next(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];

    let max_time = (1 << param.get_d()) - 1;
    let rngseed = "";
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk, _) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 1);
        assert!(Pixel::sk_update(&mut sk, time, &param, rngseed).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk update to next time stamp", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            let tar_time = sknew.get_time() + 1;
            let res = Pixel::sk_update(&mut sknew, tar_time, &param, rngseed);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark key update: update to the a random time stamp
#[allow(dead_code)]
fn bench_key_update_random(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];

    let max_time = (1 << param.get_d()) - 1;
    let rngseed = "";
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk, _) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param, rngseed).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk update to random future", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            // the target time will be random between current time + 1 and max time
            let tar_time = rand::thread_rng().gen_range(sknew.get_time() + 1, max_time - 1);
            let res = Pixel::sk_update(&mut sknew, tar_time, &param, rngseed);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark sign at a random present/future time
#[allow(dead_code)]
fn bench_sign(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];

    let msg = "the message to be signed in benchmarking";
    let max_time = (1 << param.get_d()) - 1;
    let rngseed = "";
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk, _) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param, rngseed).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk at random time, sign a random future", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            // the target time will be random between current time + 1 and max time
            let tar_time = rand::thread_rng().gen_range(sknew.get_time() + 1, max_time - 1);
            assert!(Pixel::sign(&mut sknew, tar_time, &param, msg, rngseed).is_ok());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark sign at a random present time
#[allow(dead_code)]
fn bench_sign_present(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];
    let msg = "the message to be signed in benchmarking";
    let max_time = (1 << param.get_d()) - 1;
    let rngseed = b"";
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk, _) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param, rngseed).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk at random time, sign for present", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            let tar_time = sknew.get_time();
            let res = Pixel::sign_present(&mut sknew, tar_time, &param, msg);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark sign at a random present time then update to next time stamp
#[allow(dead_code)]
fn bench_sign_then_update(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];
    let msg = "the message to be signed in benchmarking";
    let max_time = (1 << param.get_d()) - 1;
    let rngseed = "";
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk, _) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param, rngseed).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk at random time, sign then update", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            let tar_time = sknew.get_time();
            let res = Pixel::sign_then_update(&mut sknew, tar_time, &param, msg, rngseed);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
            // check that the time stamp has advanced by 1
            assert_eq!(sknew.get_time(), tar_time + 1);
        })
    });
}

/// benchmark verification at a random time
#[allow(dead_code)]
fn bench_verify(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // get a list of public keys
    let mut pklist: Vec<PublicKey> = vec![];
    let mut poplist: Vec<ProofOfPossession> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let msg = "the message to be signed in benchmarking";
    let max_time = (1 << param.get_d()) - 1;
    let rngseed = "";
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (pk, mut sk, pop) = Pixel::key_gen(&seed, &param).unwrap();
        // sign at a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        let res = Pixel::sign(&mut sk, time, &param, msg, rngseed);
        assert!(res.is_ok(), res.err());
        // pack the signature, time, and public key
        pklist.push(pk);
        siglist.push(res.unwrap());
        poplist.push(pop);
    }

    // benchmarking
    let pklist_clone = pklist.clone();
    let mut counter = 0;
    c.bench_function("verifying POP", move |b| {
        b.iter(|| {
            let res = pklist_clone[counter].validate(&poplist[counter]);
            assert!(res, "verification failed");
            counter = (counter + 1) % SAMPLES;
        })
    });

    // benchmarking
    let mut counter = 0;
    c.bench_function("verifying signature", move |b| {
        b.iter(|| {
            let res = Pixel::verify(&pklist[counter], &param, msg, &siglist[counter]);
            assert!(res, "verification failed");
            counter = (counter + 1) % SAMPLES;
        })
    });
}

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
    // let max_time = (1 << param.get_d()) - 1;
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

criterion_group!(aggregation, bench_aggregation,);

criterion_group!(
    api,
    bench_key_update_next,
    bench_sign_present,
    bench_sign_then_update,
    bench_verify
);

criterion_group!(
    api_slow,
    bench_param,
    bench_keygen,
    bench_key_update_random,
    bench_sign,
);
