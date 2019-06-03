#[cfg(test)]
use keys::SecretKey;
#[cfg(test)]
use pairing::bls12_381::*;
#[cfg(test)]
use param::PubParam;
#[cfg(test)]
use pixel;
#[cfg(test)]
use rand::{ChaChaRng, Rand, Rng};
#[cfg(test)]
use sign::Signature;

// #[bench]
// fn bench_param_from_fr(b: &mut test::test::Bencher) {
//     let mut rng = ChaChaRng::new_unseeded();
//
//     b.iter(|| {
//         let pp: PubParam = pixel::pixel_param_gen(&[
//             rng.next_u32(),
//             rng.next_u32(),
//             rng.next_u32(),
//             rng.next_u32(),
//         ]);
//         pp
//     });
// }

#[bench]
fn bench_param(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();

    b.iter(|| {
        let pp: PubParam = pixel::pixel_param_gen(&[
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ]);
        pp
    });
}

#[bench]
fn bench_key_gen_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    b.iter(|| {
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        key
    });
}

#[bench]
fn bench_sign_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);
    let mut sklist: Vec<SecretKey> = vec![];
    let m = "random message";
    for _ in 0..1000 {

        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        sklist.push(key.get_sk());
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = pixel::pixel_sign(
            &sklist[counter],
            1,
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        counter = (counter + 1) % 1000;
        t
    });
}
#[bench]
fn bench_verify_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let m = "random message";
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G1> = vec![];
    for _ in 0..1000 {
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let t: Signature = pixel::pixel_sign(
            &sk,
            1,
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        siglist.push(t);
        pklist.push(key.get_pk());
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = pixel::pixel_verify(&pklist[counter], 1, m.as_bytes(), &siglist[counter], &pp);
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}

// ============================================================================
#[bench]
fn bench_delegate_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let mut sklist: Vec<SecretKey> = vec![];
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        timelist.push(time);
        sklist.push(sknew);
    }

    let mut counter = 0;
    b.iter(|| {
        let sknew = pixel::pixel_key_update(
            &sklist[counter],
            timelist[counter] + 1,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        counter = (counter + 1) % 1000;
        sknew
    });
}

#[bench]
fn bench_sign_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let mut sklist: Vec<SecretKey> = vec![];
    let m = "random message";
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        timelist.push(time);
        sklist.push(sknew);
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = pixel::pixel_sign(
            &sklist[counter],
            timelist[counter],
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        counter = (counter + 1) % 1000;
        t
    });
}

#[bench]
fn bench_verify_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let m = "random message";
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G1> = vec![];
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let t: Signature = pixel::pixel_sign(
            &sknew,
            time,
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        siglist.push(t);
        pklist.push(key.get_pk());
        timelist.push(time);
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = pixel::pixel_verify(
            &pklist[counter],
            timelist[counter],
            m.as_bytes(),
            &siglist[counter],
            &pp,
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}

#[bench]
fn bench_verify_level_rnd_pp(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let m = "random message";
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<Fq12> = vec![];
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let t: Signature = pixel::pixel_sign(
            &sknew,
            time,
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let pk_processed = pixel::pixel_pre_process_pk(&key.get_pk());
        siglist.push(t);
        pklist.push(pk_processed);
        timelist.push(time);
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = pixel::pixel_verify_pre_processed(
            &pklist[counter],
            timelist[counter],
            m.as_bytes(),
            &siglist[counter],
            &pp,
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}

#[bench]
fn bench_verify_level_rnd_reuse(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let m = "random message";
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G1> = vec![];
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {

        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );

        let sknewnew = pixel::pixel_key_update(
            &sknew,
            time + 1,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let t: Signature = pixel::pixel_sign(
            &sknewnew,
            time + 1,
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );

        siglist.push(t);
        pklist.push(key.get_pk());
        timelist.push(time);
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = pixel::pixel_verify(
            &pklist[counter],
            timelist[counter] + 1,
            m.as_bytes(),
            &siglist[counter],
            &pp,
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}

#[test]
fn test_verify_level_leveled() {
    use param::CONST_D;
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    let m = "random message";
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G1> = vec![];
    let mut timelist: Vec<u64> = vec![];

    for i in 0..CONST_D {
        let time = 1 << i;
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let pk = key.get_pk();
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sig: Signature = pixel::pixel_sign(
            &sknew,
            time,
            m.as_bytes(),
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );

        let ver = pixel::pixel_verify(&pk, time, m.as_bytes(), &sig, &pp);

        assert_eq!(ver, true, "verification failed");
    }
}
