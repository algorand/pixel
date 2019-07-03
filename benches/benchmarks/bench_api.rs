extern crate pixel;
extern crate rand;

use self::pixel::Pixel;
use self::pixel::PixelSignature;
use self::pixel::{PublicKey, SecretKey, Signature, TimeStamp};
use self::rand::Rng;
use criterion::Criterion;

/// benchmark parameter generation
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
fn bench_keygen(c: &mut Criterion) {
    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

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
fn bench_key_update_next(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];

    let max_time = 1 << param.get_d() - 1;
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 1);
        assert!(Pixel::sk_update(&mut sk, time, &param).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk update to next time stamp", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            let tar_time = sknew.get_time() + 1;
            let res = Pixel::sk_update(&mut sknew, tar_time, &param);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark key update: update to the a random time stamp
fn bench_key_update_random(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];

    let max_time = 1 << param.get_d() - 1;
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk update to random future", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            // the target time will be random between current time + 1 and max time
            let tar_time = rand::thread_rng().gen_range(sknew.get_time() + 1, max_time - 1);
            let res = Pixel::sk_update(&mut sknew, tar_time, &param);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark sign at a random present/future time
fn bench_sign(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];

    let msg = "the message to be signed in benchmarking";
    let max_time = 1 << param.get_d() - 1;

    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk at random time, sign a random future", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            // the target time will be random between current time + 1 and max time
            let tar_time = rand::thread_rng().gen_range(sknew.get_time() + 1, max_time - 1);
            assert!(Pixel::sign(&mut sknew, tar_time, &param, msg).is_ok());
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark sign at a random present time
fn bench_sign_present(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];
    let msg = "the message to be signed in benchmarking";
    let max_time = 1 << param.get_d() - 1;

    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param).is_ok());
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
fn bench_sign_then_update(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // get a list of secret keys, as random time
    let mut sklist: Vec<SecretKey> = vec![];
    let msg = "the message to be signed in benchmarking";
    let max_time = 1 << param.get_d() - 1;

    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, mut sk) = Pixel::key_gen(&seed, &param).unwrap();
        // delegate it to a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        assert!(Pixel::sk_update(&mut sk, time, &param).is_ok());
        sklist.push(sk);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk at random time, sign then update", move |b| {
        b.iter(|| {
            let mut sknew = sklist[counter].clone();
            let tar_time = sknew.get_time();
            let res = Pixel::sign_then_update(&mut sknew, tar_time, &param, msg);
            assert!(res.is_ok(), res.err());
            counter = (counter + 1) % SAMPLES;
            // check that the time stamp has advanced by 1
            assert_eq!(sknew.get_time(), tar_time + 1);
        })
    });
}

/// benchmark verification at a random time
fn bench_verify(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // get a list of public keys
    let mut pklist: Vec<PublicKey> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut tartimelist: Vec<TimeStamp> = vec![];
    let msg = "the message to be signed in benchmarking";
    let max_time = 1 << param.get_d() - 1;

    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (pk, mut sk) = Pixel::key_gen(&seed, &param).unwrap();
        // sign at a random time
        let time = rand::thread_rng().gen_range(0u64, max_time - 2);
        let res = Pixel::sign(&mut sk, time, &param, msg);
        assert!(res.is_ok(), res.err());
        // pack the signature, time, and public key
        pklist.push(pk);
        siglist.push(res.unwrap());
        tartimelist.push(time);
    }

    // benchmarking
    let mut counter = 0;
    c.bench_function("sk at random time, sign then update", move |b| {
        b.iter(|| {
            let res = Pixel::verify(
                &pklist[counter],
                tartimelist[counter],
                &param,
                msg,
                &siglist[counter],
            );
            assert!(res, "verification failed");
            counter = (counter + 1) % SAMPLES;
        })
    });
}
criterion_group!(
    api,
    bench_param,
    bench_keygen,
    bench_key_update_next,
    bench_key_update_random,
    bench_sign,
    bench_sign_present,
    bench_sign_then_update,
    bench_verify
);
