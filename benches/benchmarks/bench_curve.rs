use super::ff::Field;
use super::pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine, SubgroupCheck};
use super::pixel::{PixelG1, PixelG2};
use super::rand_core::*;
use super::rand_xorshift::XorShiftRng;
use criterion::Criterion;

/// benchmark group multiplication
#[allow(dead_code)]
fn bench_group_multiplication(c: &mut Criterion) {
    const SAMPLES: usize = 100;
    let mut g1list: Vec<PixelG1> = vec![];
    let mut g2list: Vec<PixelG2> = vec![];
    let mut r1list: Vec<Fr> = vec![];
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _i in 0..SAMPLES {
        g1list.push(PixelG1::random(&mut rng));
        g2list.push(PixelG2::random(&mut rng));
        r1list.push(Fr::random(&mut rng));
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

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _i in 0..SAMPLES {
        g1list.push(PixelG1::random(&mut rng));
        g2list.push(PixelG2::random(&mut rng));
    }
    // benchmarking

    let mut counter = 0;
    c.bench_function("Pixel G1 membership testing cost", move |b| {
        b.iter(|| {
            g1list[counter].into_affine().in_subgroup();
            counter = (counter + 1) % SAMPLES;
        })
    });

    let mut counter = 0;
    c.bench_function("Pixel G2 membership testing cost", move |b| {
        b.iter(|| {
            g2list[counter].into_affine().in_subgroup();
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

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _i in 0..SAMPLES {
        g1list1.push(G1::random(&mut rng));
        g1list2.push(G1::random(&mut rng));
        g1list3.push(G1::random(&mut rng));
        g2list1.push(G2::random(&mut rng));
        g2list2.push(G2::random(&mut rng));
        g2list3.push(G2::random(&mut rng));
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
