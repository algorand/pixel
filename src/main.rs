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
mod sign;
mod verify;

use pairing::bls12_381::Fr;
use rand::ChaChaRng;
use rand::Rand;

fn main() {
    let seed = &[42; 4];
    let pp = pixel::pixel_param_gen(seed);
    let key = pixel::pixel_key_gen(seed, &pp);
    let time = 30;
    let sk = key.get_sk();
    let pk = key.get_pk();
    let newsk = pixel::pixel_key_update(&sk, time, seed, &pp);
    let m = Fr::rand(&mut ChaChaRng::new_unseeded());
    let sigma = pixel::pixel_sign(&newsk, time, &m, seed, &pp);

    // verify with raw public key
    let ver = pixel::pixel_verify(&pk, time, &m, &sigma, &pp);
    assert_eq!(ver, true, "verification failed");

    // verify with processed secret key
    let pk_processed = pixel::pixel_pre_process_pk(&pk);
    let ver = pixel::pixel_verify_pre_processed(&pk_processed, time, &m, &sigma, &pp);
    assert_eq!(ver, true, "verification failed");
    println!("Hello, world!");
}
