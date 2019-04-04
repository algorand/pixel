extern crate ff;
extern crate pairing;
extern crate rand;
use ff::{Field, PrimeField};
use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
//use keys::KeysAlgorithm;

//mod keys;
//mod param;
//mod sig;
//mod subkeys;
fn main() {
    let mut rng = ChaChaRng::new_unseeded();
    let hlist = gen_h_list(&mut rng);

    let h = G1::rand(&mut rng);
    let h0 = G1::rand(&mut rng);
    let pp: PubParam = PubParam {
        h: h,
        h0: h0,
        hlist: hlist,
    };
    let randvec = gen_randomness(&mut rng, &pp);
    let key = key_gen_alpha(&[3; 4], h);
    let t = root_key_gen_with_seed(&[3; 4], &pp);
    let s = delegate(
        &t.1[0],
        &randvec,
        &vec![Fr::from_repr(FrRepr([0, 0, 0, 1])).unwrap()],
    );
    // let ss = delegate(
    //     &s,
    //     &randvec,
    //     &vec![
    //         Fr::from_repr(FrRepr([0, 0, 0, 1])).unwrap(),
    //         Fr::from_repr(FrRepr([0, 0, 0, 1])).unwrap(),
    //     ],
    // );
    let hm = Fr::rand(&mut rng);
    let sig = sign(
        &t.1[0],
        &[1; 4],
        &pp,
        &vec![], //Fr::from_repr(FrRepr([0, 0, 0, 1])).unwrap()],
        hm,
    );
    //    let pp = param::PubParam::init();
    //    let key = keys::Keys::root_key_gen(&pp);
    //    println!("{:#?}", key);
    // println!("hlist {:#?}", hlist);
    // println!("randvec{:#?}", randvec);
    // println!("root secret {:#?}", key);
    // println!("key {:#?}", t);
    // println!("delgated key {:#?}", s);
    // println!("|x|: {}", get_vec_x_len(&s));
    // println!("delgated key {:#?}", ss);
    // println!("|x|: {}", get_vec_x_len(&ss));
    // println!("sig: {:#?}", sig);
    println!(
        "ver: {}",
        verify(
            &t.0,
            &pp,
            &vec![], //Fr::from_repr(FrRepr([0, 0, 0, 1])).unwrap(),],
            &hm,
            &sig
        )
    );
    println!("Hello, world!");
}

pub const LEVEL: usize = 1;

// h_1, ... h_{l+1}
type Hlist = [G1; LEVEL + 1];

// g2^r, h_0^r, ... h_{l+1}^r

#[derive(Debug, Clone)]
pub struct RandVec {
    g2: G2,
    h0: G1,
    hlist: Hlist,
}

// h, h_0, ... h_{l+1}
#[derive(Debug, Clone)]
pub struct PubParam {
    h: G1,
    h0: G1,
    hlist: Hlist,
}

// g2^\alpha
pub type PublicKey = G2;

//
//pub type SubSecretKey = (G2, [G1; LEVEL + 2]);
#[derive(Debug, Clone)]
pub struct SubSecretKey {
    c: G2,
    d: G1,
    e: [G1; LEVEL + 1],
}

//
pub type SecretKey = Vec<SubSecretKey>;

// \alpha, the root secret
pub type RootSecret = G1;

// h, h_0, ... h_{l+1}
#[derive(Debug, Clone)]
pub struct Signature {
    sigma1: G1,
    sigma2: G2,
}

fn gen_h_list<R: ::rand::Rng>(rng: &mut R) -> Hlist {
    let mut hlist: Hlist = [G1::zero(); LEVEL + 1];
    for i in 0..LEVEL + 1 {
        hlist[i] = G1::rand(rng);
    }
    hlist
}

fn gen_randomness<R: ::rand::Rng>(rng: &mut R, pp: &PubParam) -> RandVec {
    let mut randvec: RandVec = RandVec {
        g2: G2::one(),
        h0: pp.h0,
        hlist: pp.hlist,
    };

    let r = Fr::rand(rng);
    for e in randvec.hlist.iter_mut() {
        e.mul_assign(r);
    }
    randvec.g2.mul_assign(r);
    randvec.h0.mul_assign(r);
    randvec
}

fn key_gen_alpha(seed: &[u32; 4], h: G1) -> (PublicKey, RootSecret) {
    let mut rng = ChaChaRng::from_seed(seed);
    let alpha = Fr::rand(&mut rng);

    // sk = h^alpha; h is part of public parameter
    let mut rs = h.clone();
    rs.mul_assign(alpha);
    // pk = g2^alpha; g2 is the generator
    let mut pk = G2::one();
    pk.mul_assign(alpha);
    (pk, rs)
}

fn root_key_gen_with_seed(seed: &[u32; 4], pp: &PubParam) -> (PublicKey, SecretKey) {
    let mut rng = ChaChaRng::from_seed(seed);
    let seed1 = [
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ];

    let (pk, rs) = key_gen_alpha(&seed1, pp.h);
    let t = gen_randomness(&mut rng, pp);
    println!("{:#?}", t);
    let mut ssk: SubSecretKey = SubSecretKey {
        c: t.g2,
        d: t.h0,
        e: [G1::zero(); LEVEL + 1],
    };
    for i in 0..LEVEL + 1 {
        ssk.e[i] = t.hlist[i];
    }
    ssk.d.add_assign(&rs);
    println!("{:#?}", ssk);
    (pk, vec![ssk])
}

fn delegate(ssk: &SubSecretKey, randvec: &RandVec, timevec: &Vec<Fr>) -> SubSecretKey {
    let mut tilde_sk = randvec.clone();
    for i in 0..timevec.len() {
        tilde_sk.h0.add_assign(&randvec.hlist[i]);
        tilde_sk.hlist[i] = G1::zero();
    }
    let mut new_ssk = ssk.clone();
    new_ssk.c.add_assign(&tilde_sk.g2);
    for i in get_vec_x_len(&ssk)..timevec.len() {
        let mut tmp = new_ssk.e[i];
        tmp.mul_assign(timevec[i]);
        new_ssk.d.add_assign(&tmp);
        new_ssk.e[i] = G1::zero();
    }
    for i in timevec.len()..LEVEL + 1 {
        new_ssk.e[i].add_assign(&tilde_sk.hlist[i]);
    }
    new_ssk
}

fn get_vec_x_len(ssk: &SubSecretKey) -> usize {
    let mut counter = 0;
    for i in 0..ssk.e.len() {
        if ssk.e[i] == G1::zero() {
            counter += 1;
        }
    }
    counter
}

fn sign(
    ssk: &SubSecretKey,
    seed: &[u32; 4],
    pp: &PubParam,
    timevec: &Vec<Fr>,
    hm: Fr,
) -> Signature {
    let mut rng = ChaChaRng::from_seed(seed);
    let r = Fr::rand(&mut rng);

    // sigma1 = d * e_{l+1}^hm *
    let mut sigma1 = ssk.d;

    let mut tmp = ssk.e[LEVEL];
    tmp.mul_assign(hm);
    sigma1.add_assign(&tmp);

    let mut tmp = pp.h0;
    for i in 0..timevec.len() {
        let mut tt = pp.hlist[i];
        tt.mul_assign(timevec[i]);
        tmp.add_assign(&tt);
    }
    let mut tt = pp.hlist[LEVEL];
    tt.mul_assign(hm);
    tmp.add_assign(&tt);
    tmp.mul_assign(r);
    sigma1.add_assign(&tmp);

    // sigma2 = c * h2^r
    let mut sigma2 = ssk.c;
    let mut tmp = G2::one();
    tmp.mul_assign(r);
    sigma2.add_assign(&tmp);

    Signature {
        sigma1: sigma1,
        sigma2: sigma2,
    }
    // sigma1 = h[0] * h[l+1]^hm *
}

fn verify(pk: &PublicKey, pp: &PubParam, timevec: &Vec<Fr>, hm: &Fr, sig: &Signature) -> bool {
    let p1 = Bls12::pairing(sig.sigma1, G2::one());
    //    let p2 = Bls12::pairing(pp.h, *pk);
    let mut p3left = pp.h0;
    for i in 0..timevec.len() {
        let mut tmp = pp.hlist[i];
        tmp.mul_assign(timevec[i]);
        p3left.add_assign(&tmp);
    }
    let mut tmp = pp.hlist[LEVEL];
    tmp.mul_assign(*hm);
    p3left.add_assign(&tmp);
    //    p3left.add_assign(&pp.h);
    //    let mut p3right = sig.sigma2;
    //    p3right.add_assign(pk);
    //    let p3 = Bls12::pairing(p3left, p3right);
    let p3 = Bls12::pairing(p3left, sig.sigma2);
    let mut p2 = Bls12::pairing(pp.h, *pk);
    p2.mul_assign(&p3);
    p2 == p1

    //    true
}
