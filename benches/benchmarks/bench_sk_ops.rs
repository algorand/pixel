use super::pixel::Pixel;
use super::pixel::PixelSignature;
use super::pixel::SecretKey;
use super::rand::Rng;
use criterion::Criterion;

/// benchmark secret key update sequentially
fn bench_sk_update_seq(c: &mut Criterion) {
    const SAMPLES: usize = 100;

    // this benchmark uses a same set of parameter
    let seed = rand::thread_rng()
        .gen_ascii_chars()
        .take(32)
        .collect::<String>();
    let param = Pixel::param_gen(&seed, 0).unwrap();

    // sklist1 at time 1
    let mut sklist: Vec<SecretKey> = vec![];
    for _i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();
        // generate a sk
        let (_, sk) = Pixel::key_gen(&seed, &param).unwrap();
        sklist.push(sk);
    }

    for i in 0..64 {
        // clone sk and param for benchmarking
        let sklist_clone = sklist.clone();
        let param_clone = param.clone();
        let message = format!(
            "sk update from {} to {}",
            sklist_clone[i].get_time(),
            sklist_clone[i].get_time() + 1
        );
        // benchmark sk update
        c.bench_function(&message, move |b| {
            let mut counter = 0;
            b.iter(|| {
                let mut sknew = sklist_clone[counter].clone();
                let tar_time = sknew.get_time() + 1;
                let res = Pixel::sk_update(&mut sknew, tar_time, &param_clone);
                assert!(res.is_ok(), res.err());
                counter = (counter + 1) % SAMPLES;
            })
        });
        // update sk to next time stamp
        for mut e in sklist.iter_mut().take(SAMPLES) {
            let tar_time = e.get_time() + 1;
            let res = Pixel::sk_update(&mut e, tar_time, &param);
            assert!(res.is_ok(), res.err());
        }
    }
}

criterion_group!(sk_ops, bench_sk_update_seq);
