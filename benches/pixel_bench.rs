// this file benchmarks the core operations of Pixel signature scheme

#[macro_use]
extern crate criterion;
extern crate walkdir;

mod benchmarks;

criterion_main!(
    benchmarks::bench_time::time,
    benchmarks::bench_sk_ops::sk_ops,
    //    benchmarks::bench_sk_ops::sk_ops_slow,
    benchmarks::bench_ssk_ops::ssk_ops,
    //    benchmarks::bench_ssk_ops::ssk_ops_slow,
    benchmarks::bench_curve::group_ops,
    benchmarks::bench_api::api,
    //    benchmarks::bench_api::api_slow,
);
