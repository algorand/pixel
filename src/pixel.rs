// pixel module defines the main APIs

use keys::{KeyPair, SecretKey};
use pairing::{bls12_381::*, CurveProjective, Engine};
use param::PubParam;
use sign::Signature;
use verify::verification_aggregated;
use verify::{verification, verification_pre_computed};

// input a seed generate public parameters
pub fn pixel_param_gen(seed: &[u32; 4]) -> PubParam {
    PubParam::init_with_w_and_seed(seed)
}

// input a seed, public parameters, generate a pair of keys at time stamp 1
pub fn pixel_key_gen(seed: &[u32; 4], pp: &PubParam) -> KeyPair {
    KeyPair::root_key_gen_with_seed(seed, &pp)
}

// input a secret key, a new time stamp, a seed for randomness, and the public parameter
// update the secret key to the new time stamp
pub fn pixel_key_update(sk: &SecretKey, time: u64, seed: &[u32; 4], pp: &PubParam) -> SecretKey {
    //    sk.delegate(&pp, time, seed)
    sk.optimized_delegate(&pp, time, seed)
}

// inputs:
//  sk: the secret key
//  time: the time stamp
//  m: the message in Fr (todo:  change it to msg: &[u8] and m = hash_to_field(msg) )
//  seed: the seed for randomness - we want the signing algorithm to be deterministic
//  pp: public parameters
// output:
//  a signature
pub fn pixel_sign(sk: &SecretKey, time: u64, m: &Fr, seed: &[u32; 4], pp: &PubParam) -> Signature {
    // in pricipal we do not allow for signing for the future
    // if one were to sign for the future, one needs to update its secret key to the future time stamp
    // and then "sign for present"
    assert_eq!(
        sk.get_time(),
        time,
        "input time {} does not match timestamp on the key {}",
        time,
        sk.get_time()
    );

    Signature::sign_with_seed(&sk.get_sub_secretkey()[0], &pp, &time, m, seed)
}

// inputs:
//  pk: public key in G1
//  time: the time stamp
//  m: the message in Fr (todo:  change it to msg: &[u8] and m = hash_to_field(msg) )
//  sig: signature (G2, G1)
//  pp: Public Param
// outputs:
//  signature is correct or not
pub fn pixel_verify(pk: &G1, time: u64, m: &Fr, sig: &Signature, pp: &PubParam) -> bool {
    // todo: membership test for signatures -- confirmed, and will be added
    verification(&pk, &pp, &time, &m, &sig)
}

// pre-processing a public key; in most cases we will not perform preprocessing
pub fn pixel_pre_process_pk(pk: &G1) -> Fq12 {
    Bls12::pairing(*pk, G2::one())
}

// API for pre-processed keys, mirrors pixel_verify
pub fn pixel_verify_pre_processed(
    pk: &Fq12,
    time: u64,
    m: &Fr,
    sig: &Signature,
    pp: &PubParam,
) -> bool {
    // todo: membership test for signatures?
    verification_pre_computed(pk, pp, &time, m, sig)
}

// Aggregating a list of signatures into a single one
pub fn pixel_aggregate(siglist: &Vec<Signature>) -> Signature {
    Signature::aggregate(siglist)
}

// API to verify an aggregated signature
// inputs:
//  pk: a list of public keys in G1
//  time: the time stamp
//  m: the message in Fr (todo:  change it to msg: &[u8] and m = hash_to_field(msg) )
//  sig: signature (G2, G1)
//  pp: Public Param
// outputs:
//  signature is correct or not
pub fn pixel_verify_aggregated(
    pk: &Vec<G1>,
    time: u64,
    m: &Fr,
    sig: &Signature,
    pp: &PubParam,
) -> bool {
    verification_aggregated(&pk, &pp, &time, &m, &sig)
}
