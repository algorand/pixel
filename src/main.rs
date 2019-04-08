#![warn(unused_extern_crates)]
extern crate ff;
extern crate pairing;
extern crate rand;
extern crate sha2;
mod gammafunction;
mod initkey;
mod keys;
mod param;
mod pixel;
mod sign;
mod verify;
use ff::Field;
use ff::PrimeField;
use gammafunction::GammaList;
use initkey::InitKeyAlgorithm;
use keys::{KeysAlgorithm, SKAlgorithm, SSKAlgorithm};
use pairing::bls12_381::*;
use param::PubParam;
use rand::{ChaChaRng, Rand};
fn main() {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);

    let k: keys::Keys = KeysAlgorithm::root_key_gen(&pp);
    let rs: initkey::InitKey = InitKeyAlgorithm::key_gen_alpha();
    println!("{:#?}", pp);
    println!("{:#?}", k);
    println!("{:#?}", rs);

    let ssk = k.get_sk().get_fist_ssk();
    println!("{:#?}", ssk);

    let mut x: Vec<Fr> = Vec::new();
    for i in 1..2 {
        let t = Fr::from_repr(FrRepr([0, 0, 0, i])).unwrap();
        println!("t: {:?}", t);
        x.push(t);
    }

    let ssknew = ssk.subkey_delegate(&pp, &x, &mut rng);
    println!("{:#?}", ssknew);
    println!("{:#?}", x);
    let m: Fr = Fr::rand(&mut rng);
    let t: sign::Signature = sign::Sign::sign(&ssknew, &pp, &x, &m, &mut rng);
    println!("{:#?}", t);
    let key: G2 = k.get_pk();
    let s: bool = verify::verification(&key, &pp, &x, &m, &t);
    println!("{:#?}", s);

    let mut xprime = x.clone();
    xprime.push(Fr::from_repr(FrRepr([0, 0, 0, 1])).unwrap());
    let ssknew = ssknew.subkey_delegate(&pp, &xprime, &mut rng);
    println!("{:#?}", ssknew);
    let m = Fr::rand(&mut rng);
    let t: sign::Signature = sign::Sign::sign_with_seed_and_time(&ssknew, &pp, &35, &m, &[42; 4]);
    println!("signature {:#?}", t);
    let s = verify::verification_with_time(&k.get_pk(), &pp, &35, &m, &t);
    println!("with time{:#?}", s);

    let ssknew = ssk.subkey_delegate(&pp, &xprime, &mut rng);
    println!("{:#?}", ssknew);
    let m = Fr::rand(&mut rng);
    let t: sign::Signature = sign::Sign::sign(&ssknew, &pp, &xprime, &m, &mut rng);
    println!("{:#?}", t);
    let s = verify::verification(&k.get_pk(), &pp, &xprime, &m, &t);
    println!("{:#?}", s);

    let t = Fr::one();
    println!("{:#?}", t);
    pub const FR_ONE: [u64; 4] = [1, 0, 0, 0];
    let t2 = Fr::from_repr(FrRepr(FR_ONE)).unwrap();
    println!("{:#?} {}", t2, t == t2);

    let mut t = GammaList::gen_list(30);
    println!("{:#?}", t);
    t.update_list(31);
    println!("{:#?}", t);
    t.update_list(32);
    println!("{:#?}", t);
    println!("Hello, world!");
}
