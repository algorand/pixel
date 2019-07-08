use super::pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use super::pixel::membership::MembershipTesting;
use super::pixel::{PixelG1, PixelG2};
use super::rand::Rand;
use criterion::Criterion;

/// benchmark group multiplication
#[allow(dead_code)]
fn bench_group_multiplication(c: &mut Criterion) {
    const SAMPLES: usize = 100;
    let mut g1list: Vec<PixelG1> = vec![];
    let mut g2list: Vec<PixelG2> = vec![];
    let mut r1list: Vec<Fr> = vec![];
    let mut rng = rand::thread_rng();
    for _i in 0..SAMPLES {
        g1list.push(PixelG1::rand(&mut rng));
        g2list.push(PixelG2::rand(&mut rng));
        r1list.push(Fr::rand(&mut rng));
    }
    let r2list = r1list.clone();
    // benchmarking

    let mut counter = 0;
    c.bench_function("Pixel G1 muliplication cost", move |b| {
        b.iter(|| {
            g1list[counter].mul_assign(r1list[counter]);
            counter = (counter + 1) % SAMPLES;
        })
    });

    let mut counter = 0;
    c.bench_function("Pixel G2 muliplication cost", move |b| {
        b.iter(|| {
            g2list[counter].mul_assign(r2list[counter]);
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark group multiplication
#[allow(dead_code)]
fn bench_membership_testing(c: &mut Criterion) {
    const SAMPLES: usize = 100;
    let mut g1list: Vec<PixelG1> = vec![];
    let mut g2list: Vec<PixelG2> = vec![];

    let mut rng = rand::thread_rng();
    for _i in 0..SAMPLES {
        g1list.push(PixelG1::rand(&mut rng));
        g2list.push(PixelG2::rand(&mut rng));
    }
    // benchmarking

    let mut counter = 0;
    c.bench_function("Pixel G1 membership testing cost", move |b| {
        b.iter(|| {
            g1list[counter].is_in_prime_group();
            counter = (counter + 1) % SAMPLES;
        })
    });

    let mut counter = 0;
    c.bench_function("Pixel G2 membership testing cost", move |b| {
        b.iter(|| {
            g2list[counter].is_in_prime_group();
            counter = (counter + 1) % SAMPLES;
        })
    });
}

/// benchmark group multiplication
#[allow(dead_code)]
fn bench_pairing(c: &mut Criterion) {
    const SAMPLES: usize = 100;
    let mut g1list1: Vec<G1> = vec![];
    let mut g1list2: Vec<G1> = vec![];
    let mut g1list3: Vec<G1> = vec![];
    let mut g2list1: Vec<G2> = vec![];
    let mut g2list2: Vec<G2> = vec![];
    let mut g2list3: Vec<G2> = vec![];

    let mut rng = rand::thread_rng();
    for _i in 0..SAMPLES {
        g1list1.push(G1::rand(&mut rng));
        g1list2.push(G1::rand(&mut rng));
        g1list3.push(G1::rand(&mut rng));
        g2list1.push(G2::rand(&mut rng));
        g2list2.push(G2::rand(&mut rng));
        g2list3.push(G2::rand(&mut rng));
    }

    // benchmarking
    let mut counter = 0;
    let g11 = g1list1.clone();
    let g21 = g2list1.clone();
    c.bench_function("Single pairing cost", move |b| {
        b.iter(|| {
            Bls12::final_exponentiation(&Bls12::miller_loop(
                [(
                    &(g11[counter].into_affine().prepare()),
                    &(g21[counter].into_affine().prepare()),
                )]
                .iter(),
            ))
            .unwrap();
            counter = (counter + 1) % SAMPLES;
        })
    });

    let mut counter = 0;
    let g11 = g1list1.clone();
    let g12 = g1list2.clone();
    let g21 = g2list1.clone();
    let g22 = g2list2.clone();
    c.bench_function("Simutaneously 2 pairing cost", move |b| {
        b.iter(|| {
            Bls12::final_exponentiation(&Bls12::miller_loop(
                [
                    (
                        &(g11[counter].into_affine().prepare()),
                        &(g21[counter].into_affine().prepare()),
                    ),
                    (
                        &(g12[counter].into_affine().prepare()),
                        &(g22[counter].into_affine().prepare()),
                    ),
                ]
                .iter(),
            ))
            .unwrap();
            counter = (counter + 1) % SAMPLES;
        })
    });

    let mut counter = 0;
    c.bench_function("Simutaneously 3 pairing cost", move |b| {
        b.iter(|| {
            Bls12::final_exponentiation(&Bls12::miller_loop(
                [
                    (
                        &(g1list1[counter].into_affine().prepare()),
                        &(g2list1[counter].into_affine().prepare()),
                    ),
                    (
                        &(g1list2[counter].into_affine().prepare()),
                        &(g2list2[counter].into_affine().prepare()),
                    ),
                    (
                        &(g1list3[counter].into_affine().prepare()),
                        &(g2list3[counter].into_affine().prepare()),
                    ),
                ]
                .iter(),
            ))
            .unwrap();
            counter = (counter + 1) % SAMPLES;
        })
    });
}

criterion_group!(
    group_ops,
    bench_group_multiplication,
    bench_membership_testing,
    bench_pairing
);
