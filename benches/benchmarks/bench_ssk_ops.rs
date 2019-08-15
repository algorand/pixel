use super::pairing::bls12_381::Fr;
use super::pixel::Pixel;
use super::pixel::PixelSignature;
use super::pixel::SubSecretKey;
use super::pixel::SecretKey;
use super::rand::{Rand, Rng};
use criterion::Criterion;
use super::pixel::SerDes;
use std::fs::File;

/// benchmark sub secret key delegation - without randomization
#[allow(dead_code)]
fn bench_ssk_delegate(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let param = Pixel::param_default();

    // ssklist at time 1
    let mut ssklist: Vec<SubSecretKey> = vec![];
    for i in 0..SAMPLES {
        let mut file = File::open(format!("benches/pre-keys/data/sk_bin_{:04?}.txt", i)).unwrap();
        let (sk, _) = SecretKey::deserialize(&mut file).unwrap();
        ssklist.push(sk.first_ssk().unwrap());
    }

    // from root to the leaf we can delegate d - 1 times
    for i in 0..param.depth() - 1 {
        // clone ssk and param for benchmarking
        let ssklist_clone = ssklist.clone();
        let param_clone = param.clone();
        let message = format!(
            "ssk delegate from {} to {}",
            ssklist_clone[i].time(),
            ssklist_clone[i].time() + 1
        );
        // benchmark ssk update
        c.bench_function(&message, move |b| {
            let mut counter = 0;
            b.iter(|| {
                let mut ssknew = ssklist_clone[counter].clone();
                let tar_time = ssknew.time() + 1;
                let res = ssknew.delegate(tar_time, param_clone.depth());
                assert!(res.is_ok(), res.err());
                counter = (counter + 1) % SAMPLES;
            })
        });
        // update ssk to next time stamp
        for e in ssklist.iter_mut().take(SAMPLES) {
            let tar_time = e.time() + 1;
            let res = e.delegate(tar_time, param.depth());
            assert!(res.is_ok(), res.err());
        }
    }
}

/// benchmark sub secret key randomization
#[allow(dead_code)]
fn bench_ssk_leveled_randomization(c: &mut Criterion) {
    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // ssk at time 1

    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    // generate a sk and store the first ssk
    let (_, sk, _) = Pixel::key_gen(&seed, &param).unwrap();
    let mut ssk = sk.first_ssk().unwrap();

    // from root to the leaf we can delegate d - 1 times
    for _ in 0..param.depth() - 1 {
        // clone ssk and param for benchmarking
        let ssk_clone = ssk.clone();
        let param_clone = param.clone();
        let message = format!("ssk randomization at time {}", ssk_clone.time(),);

        // benchmark ssk randomization
        c.bench_function(&message, move |b| {
            b.iter(|| {
                let mut ssknew = ssk_clone.clone();
                let r = Fr::rand(&mut rand::thread_rng());
                let res = ssknew.randomization(&param_clone, r);
                assert!(res.is_ok(), res.err());
            })
        });
        // update ssk to next time stamp
        let tar_time = ssk.time() + 1;
        let res = ssk.delegate(tar_time, param.depth());
        assert!(res.is_ok(), res.err());
    }
}

/// benchmark sub secret key randomization
#[allow(dead_code)]
fn bench_ssk_leaf_randomization(c: &mut Criterion) {
    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // ssk at time 1
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    // generate a sk and store the first ssk
    let (_, sk, _) = Pixel::key_gen(&seed, &param).unwrap();
    let mut ssk = sk.first_ssk().unwrap();
    // update ssk to a leaf node
    let tar_time = param.depth() as u64;
    let res = ssk.delegate(tar_time, param.depth());
    assert!(res.is_ok(), res.err());

    // clone ssk and param for benchmarking
    let message = format!("ssk randomization at time {}", ssk.time(),);

    // benchmark ssk randomization
    c.bench_function(&message, move |b| {
        b.iter(|| {
            //let mut ssknew = ssk_clone.clone();
            let r = Fr::rand(&mut rand::thread_rng());
            let res = ssk.randomization(&param, r);
            assert!(res.is_ok(), res.err());
        })
    });
}

criterion_group!(ssk_ops, bench_ssk_leaf_randomization, bench_ssk_delegate);
criterion_group!(ssk_ops_slow, bench_ssk_leveled_randomization);
