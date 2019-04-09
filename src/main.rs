#![feature(test)]

extern crate ff;
extern crate pairing;
extern crate rand;
extern crate sha2;

#[cfg(test)]
extern crate test;

mod gammafunction;
mod keys;
mod param;
mod pixel;
mod pixel_bench;
mod sign;
mod verify;

use keys::KeyPair;
use pairing::bls12_381::Fr;
use rand::ChaChaRng;
use rand::Rand;

fn main() {
    let mut t30 = gammafunction::GammaList::gen_list(30);
    let t31 = gammafunction::GammaList::gen_list(31);
    let t32 = gammafunction::GammaList::gen_list(32);

    println!("{:?}", t30);
    println!("{:?}", t31);
    println!("{:?}", t32);
    t30.update_list(32);
    println!("{:?}", t32);
    // for i in 1..16 {
    //     let t = gammafunction::GammaList::gen_list(i);
    //     println!("{:?}", t);
    // }
    let pp = param::PubParam::init_with_seed(&[1; 4]);
    let keys = KeyPair::root_key_gen_with_seed(&[1; 4], &pp);
    println!("keys {:?}", keys);
    let sk = keys.get_sk();
    let t = sk.delegate(&pp, 8);

    for e in t.get_sub_secretkey() {
        println!("{} {}", e.get_time(), e.get_g1poly());
    }
    //let t = sk.delegate(&pp, 16);

    let t = t.optimized_delegate(&pp, 9, &[1; 4]);
    println!();
    println!();
    println!();
    for e in t.get_sub_secretkey() {
        println!("{} {}", e.get_time(), e.get_g1poly());
    }

    let t = t.optimized_delegate(&pp, 10, &[1; 4]);
    println!();
    println!();
    println!();
    for e in t.get_sub_secretkey() {
        println!("{} {}", e.get_time(), e.get_g1poly());
    }

    let t = t.optimized_delegate(&pp, 11, &[1; 4]);
    println!();
    println!();
    println!();
    for e in t.get_sub_secretkey() {
        println!("{} {}", e.get_time(), e.get_g1poly());
    }

    let mut rng = ChaChaRng::new_unseeded();

    let pp = param::PubParam::init_with_seed(&[1; 4]);
    let keys = KeyPair::root_key_gen_with_seed(&[1; 4], &pp);

    let ssk = keys.get_sk().get_sub_secretkey()[0];
    println!("{:#?}", ssk);

    let sk = keys.get_sk();
    let pk = keys.get_pk();
    let k19 = sk.optimized_delegate(&pp, 19, &[1; 4]);
    let k20 = sk.optimized_delegate(&pp, 20, &[1; 4]);
    let m = Fr::rand(&mut rng);
    let sig: sign::Signature =
        sign::Signature::sign_with_seed(&k19.get_sub_secretkey()[0], &pp, &19, &m, &[1; 4]);
    println!("{:#?}", sig);

    let ver = verify::verification(&pk, &pp, &19, &m, &sig);
    println!("{:#?}", ver);

    let m = Fr::rand(&mut rng);
    let sig: sign::Signature =
        sign::Signature::sign_with_seed(&k20.get_sub_secretkey()[0], &pp, &20, &m, &[1; 4]);
    println!("{:#?}", sig);

    let ver = verify::verification(&pk, &pp, &20, &m, &sig);
    println!("{:#?}", ver);
    println!("Hello, world!");
}
