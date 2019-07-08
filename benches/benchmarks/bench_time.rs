use super::pixel::TimeVec;
use criterion::Criterion;

/// benchmark gamma list generation
#[allow(dead_code)]
fn bench_gamma_list(c: &mut Criterion) {
    for time in 1..64 {
        let time_vec = TimeVec::init(time, 32).unwrap();
        let message = format!("gamma list for time {}", time,);

        // benchmark gamma list generation
        c.bench_function(&message, move |b| {
            b.iter(|| {
                let res = time_vec.gamma_list(32);
                assert!(res.is_ok(), res.err());
            })
        });
    }
}

criterion_group!(time, bench_gamma_list);
