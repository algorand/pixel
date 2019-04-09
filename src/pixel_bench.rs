#[feature(test)]
#[cfg(test)]
use ff::Field;

#[cfg(test)]
use keys::{KeyPair, SecretKey, SubSecretKey};

//#[cfg(test)]
//use keys::keypair::{root_key_gen_with_rng, *};

//::root_key_gen_with_rng;
#[cfg(test)]
use pairing::bls12_381::*;
#[cfg(test)]
use param::{PubParam, CONST_D};
#[cfg(test)]
use rand::{ChaChaRng, Rand, Rng};
#[cfg(test)]
use sign::Signature;
// #[cfg(test)]
// use sign::Signature::sign_with_seed_and_time;
#[cfg(test)]
//use verify::verification;
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
fn bench_key_gen_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    b.iter(|| {
        let keys: KeyPair = KeyPair::root_key_gen_with_rng(&mut rng, &pp);
        keys
    });
}

#[bench]
fn bench_sign_level_00(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut sklist: Vec<SecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        msglist.push(m);
        let keys: KeyPair = KeyPair::root_key_gen_with_rng(&mut rng, &pp);
        sklist.push(keys.get_sk());
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Signature::sign_with_seed_and_time(
            &sklist[counter].get_sub_secretkey()[0],
            &pp,
            &1,
            &msglist[counter],
            &[42; 4],
        );
        counter = (counter + 1) % 1000;
        t
    });
}
#[bench]
fn bench_verify_level_00(b: &mut test::test::Bencher) {
    let time = 1;

    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let mut msglist: Vec<Fr> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let mut pklist: Vec<G2> = vec![];
    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: KeyPair = KeyPair::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let t: Signature =
            Signature::sign_with_seed_and_time(&sk.get_sub_secretkey()[0], &pp, &1, &m, &[42; 4]);
        msglist.push(m);
        siglist.push(t);
        pklist.push(keys.get_pk());
    }
    let mut counter = 0;
    b.iter(|| {
        let ver = verification_with_time(
            &pklist[counter],
            &pp,
            &time,
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
    let mut sklist: Vec<SecretKey> = vec![];

    let mut timelist: Vec<u64> = vec![];
    for _ in 0..1000 {
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let keys: KeyPair = KeyPair::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let sknew = sk.delegate(&pp, time);
        timelist.push(time);
        sklist.push(sknew);
    }

    let mut counter = 0;
    b.iter(|| {
        let sknew = sklist[counter].optimized_delegate(&pp, timelist[counter] + 1);
        counter = (counter + 1) % 1000;
        sknew
    });
}

#[bench]
fn bench_sign_level_rnd(b: &mut test::test::Bencher) {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    let mut sklist: Vec<SecretKey> = vec![];
    let mut msglist: Vec<Fr> = vec![];
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let keys: KeyPair = KeyPair::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let sknew = sk.delegate(&pp, time);
        timelist.push(time);
        sklist.push(sknew);
        msglist.push(m);
    }

    let mut counter = 0;
    b.iter(|| {
        let t: Signature = Signature::sign_with_seed_and_time(
            &sklist[counter].get_sub_secretkey()[0],
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
    let mut timelist: Vec<u64> = vec![];

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let keys: KeyPair = KeyPair::root_key_gen_with_rng(&mut rng, &pp);
        let sk = keys.get_sk();
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let sknew = sk.delegate(&pp, time);
        let t: Signature = Signature::sign_with_seed_and_time(
            &sknew.get_sub_secretkey()[0],
            &pp,
            &(time as u64),
            &m,
            &[42; 4],
        );
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
