use ff::Field;
#[cfg(test)]
use initkey::{InitKey, InitKeyAlgorithm};
#[cfg(test)]
use keys::{Keys, KeysAlgorithm, SSKAlgorithm};
#[cfg(test)]
use pairing::bls12_381::*;
#[cfg(test)]
use param::SecretKey;
#[cfg(test)]
use param::{PubParam, SubSecretKey};
#[cfg(test)]
use rand::{ChaChaRng, Rand, Rng};
#[cfg(test)]
use sign::{Sign, Signature};
#[cfg(test)]
use verify::verification;
use verify::verification_with_time;

#[bench]
fn bench_param_from_fr(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();

    b.iter(|| {
        let pp: PubParam = PubParam::init_with_w_and_seed(&[
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ]);
        pp
    });
}

#[bench]
fn bench_param(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();

    b.iter(|| {
        let pp: PubParam = PubParam::init_with_seed(&[
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ]);
        pp
    });
}

#[bench]
fn bench_key_gen_key_alpha(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();

    b.iter(|| {
        let keys: InitKey = InitKeyAlgorithm::key_gen_alpha_with_rng(&mut rng);
        keys
    });
}

#[bench]
fn bench_key_gen_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    b.iter(|| {
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        keys
    });
}

#[bench]
fn bench_sign_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut sklist: Vec<SecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..0 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        msglist.push(m);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        sklist.push(keys.get_sk());
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Sign::sign(&sklist[counter][0], &pp, &x, &msglist[counter], &mut rng);
        counter = (counter + 1) % 1000;
        t
    });
}
#[bench]
fn bench_verify_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let mut msglist: Vec<Fr> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G2> = vec![];
    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let t: Signature = Sign::sign(&sk[0], &pp, &vec![], &m, &mut rng);
        msglist.push(m);
        siglist.push(t);
        pklist.push(keys.get_pk());
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = verification(
            &pklist[counter],
            &pp,
            &vec![],
            &msglist[counter],
            &siglist[counter],
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}
// ============================================================================
#[bench]
fn bench_delegate_level_01(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut ssklist: Vec<SubSecretKey> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..0 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let ssknew = sk[0].subkey_delegate(&pp, &x, &mut rng);
        ssklist.push(ssknew);
    }
    x.push(Fr::one());
    let mut counter = 0;
    b.iter(|| {
        let ssknew = ssklist[counter].subkey_delegate(&pp, &x, &mut rng);
        counter = (counter + 1) % 1000;
        ssknew
    });
}

#[bench]
fn bench_sign_level_01(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut sklist: Vec<SecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..1 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        msglist.push(m);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        sklist.push(keys.get_sk());
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Sign::sign(&sklist[counter][0], &pp, &x, &msglist[counter], &mut rng);
        counter = (counter + 1) % 1000;
        t
    });
}

#[bench]
fn bench_verify_level_01(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let mut msglist: Vec<Fr> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G2> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..1 {
        x.push(Fr::one());
    }
    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let t: Signature = Sign::sign(&sk[0], &pp, &x, &m, &mut rng);
        msglist.push(m);
        siglist.push(t);
        pklist.push(keys.get_pk());
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = verification(
            &pklist[counter],
            &pp,
            &x,
            &msglist[counter],
            &siglist[counter],
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}
// ============================================================================
#[bench]
fn bench_delegate_level_02(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut ssklist: Vec<SubSecretKey> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..1 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let ssknew = sk[0].subkey_delegate(&pp, &x, &mut rng);
        ssklist.push(ssknew);
    }
    x.push(Fr::one());
    let mut counter = 0;
    b.iter(|| {
        let ssknew = ssklist[counter].subkey_delegate(&pp, &x, &mut rng);
        counter = (counter + 1) % 1000;
        ssknew
    });
}

#[bench]
fn bench_sign_level_02(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut sklist: Vec<SecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..2 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        msglist.push(m);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        sklist.push(keys.get_sk());
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Sign::sign(&sklist[counter][0], &pp, &x, &msglist[counter], &mut rng);
        counter = (counter + 1) % 1000;
        t
    });
}

#[bench]
fn bench_verify_level_02(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let mut msglist: Vec<Fr> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G2> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..2 {
        x.push(Fr::one());
    }
    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let t: Signature = Sign::sign(&sk[0], &pp, &x, &m, &mut rng);
        msglist.push(m);
        siglist.push(t);
        pklist.push(keys.get_pk());
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = verification(
            &pklist[counter],
            &pp,
            &x,
            &msglist[counter],
            &siglist[counter],
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}
// ============================================================================
#[bench]
fn bench_delegate_level_03(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut ssklist: Vec<SubSecretKey> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..2 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let ssknew = sk[0].subkey_delegate(&pp, &x, &mut rng);
        ssklist.push(ssknew);
    }
    x.push(Fr::one());
    let mut counter = 0;
    b.iter(|| {
        let ssknew = ssklist[counter].subkey_delegate(&pp, &x, &mut rng);
        counter = (counter + 1) % 1000;
        ssknew
    });
}

#[bench]
fn bench_sign_level_03(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut sklist: Vec<SecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..3 {
        x.push(Fr::one());
    }

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        msglist.push(m);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        sklist.push(keys.get_sk());
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Sign::sign(&sklist[counter][0], &pp, &x, &msglist[counter], &mut rng);
        counter = (counter + 1) % 1000;
        t
    });
}

#[bench]
fn bench_verify_level_03(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let mut msglist: Vec<Fr> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G2> = vec![];
    let mut x: Vec<Fr> = vec![];
    for _ in 0..3 {
        x.push(Fr::one());
    }
    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let t: Signature = Sign::sign(&sk[0], &pp, &x, &m, &mut rng);
        msglist.push(m);
        siglist.push(t);
        pklist.push(keys.get_pk());
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = verification(
            &pklist[counter],
            &pp,
            &x,
            &msglist[counter],
            &siglist[counter],
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}

// ============================================================================
#[bench]
fn bench_delegate_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut ssklist: Vec<SubSecretKey> = vec![];

    let mut timelist: Vec<u32> = vec![];
    for _ in 0..1000 {
        let time = rng.next_u32() & 0x3FFFFFFF;
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let ssknew = sk[0].subkey_delegate_time(&pp, &(time as u64), &mut rng);
        timelist.push(time);
        ssklist.push(ssknew);
    }

    let mut counter = 0;
    b.iter(|| {
        let ssknew =
            ssklist[counter].subkey_delegate_time(&pp, &(timelist[counter] as u64 + 1), &mut rng);
        counter = (counter + 1) % 1000;
        ssknew
    });
}

#[bench]
fn bench_sign_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut ssklist: Vec<SubSecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];
    let mut timelist: Vec<u32> = vec![];

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        msglist.push(m);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let time = rng.next_u32() & 0x3FFFFFFF;
        let ssk = sk[0].subkey_delegate_time(&pp, &(time as u64), &mut rng);
        timelist.push(time);
        ssklist.push(ssk);
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Sign::sign_with_seed_and_time(
            &ssklist[counter],
            &pp,
            &(timelist[counter] as u64),
            &msglist[counter],
            &[42; 4],
        );
        counter = (counter + 1) % 1000;
        t
    });
}

#[bench]
fn bench_verify_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let mut msglist: Vec<Fr> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G2> = vec![];
    let mut timelist: Vec<u32> = vec![];

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: Keys = KeysAlgorithm::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let time = rng.next_u32() & 0x3FFFFFFF;
        let t: Signature = Sign::sign_with_seed_and_time(&sk[0], &pp, &(time as u64), &m, &[42; 4]);
        msglist.push(m);
        siglist.push(t);
        pklist.push(keys.get_pk());
        timelist.push(time);
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = verification_with_time(
            &pklist[counter],
            &pp,
            &(timelist[counter] as u64),
            &msglist[counter],
            &siglist[counter],
        );
        counter = (counter + 1) % 1000;
        assert_eq!(ver, true, "verification failed");
        ver
    });
}
