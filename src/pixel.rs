use keys::{KeyPair, SecretKey};
use pairing::{bls12_381::*, CurveProjective, Engine};
use param::PubParam;
use sign::Signature;
use verify::verification_aggregated;
use verify::{verification, verification_pre_computed};

pub fn pixel_param_gen(seed: &[u32; 4]) -> PubParam {
    PubParam::init_with_w_and_seed(seed)
}

pub fn pixel_key_gen(seed: &[u32; 4], pp: &PubParam) -> KeyPair {
    KeyPair::root_key_gen_with_seed(seed, &pp)
}

pub fn pixel_key_update(sk: &SecretKey, time: u64, seed: &[u32; 4], pp: &PubParam) -> SecretKey {
    //    sk.optimized_delegate(&pp, time, seed)
    sk.optimized_delegate(&pp, time, seed)
}

pub fn pixel_sign(sk: &SecretKey, time: u64, m: &Fr, seed: &[u32; 4], pp: &PubParam) -> Signature {
    assert_eq!(
        sk.get_time(),
        time,
        "input time {} does not match timestamp on the key {}",
        time,
        sk.get_time()
    );

    Signature::sign_with_seed(&sk.get_sub_secretkey()[0], &pp, &time, m, seed)
}


#[allow(dead_code)]
pub fn pixel_verify(pk: &G1, time: u64, m: &Fr, sig: &Signature, pp: &PubParam) -> bool {

    // todo: membership test for signatures?
    verification(&pk, &pp, &time, &m, &sig)
}

#[allow(dead_code)]
pub fn pixel_pre_process_pk(pk: &G1) -> Fq12 {
    Bls12::pairing(*pk, G2::one())
}

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

pub fn pixel_aggregate(siglist: &Vec<Signature>) -> Signature {
    Signature::aggregate(siglist)
}

pub fn pixel_verify_aggregated(
    pk: &Vec<G2>,
    time: u64,
    m: &Fr,
    sig: &Signature,
    pp: &PubParam,
) -> bool {
    verification_aggregated(&pk, &pp, &time, &m, &sig)
}
