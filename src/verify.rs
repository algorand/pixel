use ff::Field;
use gammafunction::time_to_fr_vec;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use param::{PubParam, CONST_D};
use sign::Signature;
#[allow(dead_code)]
pub fn verification(pk: &G2, pp: &PubParam, time: &Vec<Fr>, msg: &Fr, sigma: &Signature) -> bool {
    // g1^{w[1] * msg}
    let mut g1fx = pp.get_g0();
    let list = pp.get_glist();
    for i in 0..time.len() {
        let mut tmp = list[i];
        tmp.mul_assign(time[i]);
        g1fx.add_assign(&tmp);
    }
    let mut tmp = list[CONST_D - 1];
    tmp.mul_assign(*msg);
    g1fx.add_assign(&tmp);

    let mut sigma1 = sigma.sigma1;
    sigma1.negate();

    // e(1/sigma1, g2) * e(g1^{f}, sigma2) * e(g1, pk)
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (
                &(sigma1.into_affine().prepare()),
                &(G2::one().into_affine().prepare()),
            ),
            (
                &(g1fx.into_affine().prepare()),
                &(sigma.sigma2.into_affine().prepare()),
            ),
            (
                &G1::one().into_affine().prepare(),
                &pk.into_affine().prepare(),
            ),
        ]
        .into_iter(),
    ))
    .unwrap();

    // e(1/sigma1, g2) * e(g1^{f}, sigma2) * e(g1, pk) == 1?
    pairingproduct
        == Fq12 {
            c0: Fq6::one(),
            c1: Fq6::zero(),
        }
}

pub fn verification_with_time(
    pk: &G2,
    pp: &PubParam,
    time: &u64,
    msg: &Fr,
    sigma: &Signature,
) -> bool {
    // g1^{w[1] * msg}
    let mut g1fx = pp.get_g0();
    let list = pp.get_glist();
    let timevec = time_to_fr_vec(*time, CONST_D as u32);
    for i in 0..timevec.len() {
        let mut tmp = list[i];
        tmp.mul_assign(timevec[i]);
        g1fx.add_assign(&tmp);
    }
    let mut tmp = list[CONST_D - 1];
    tmp.mul_assign(*msg);
    g1fx.add_assign(&tmp);

    let mut sigma1 = sigma.sigma1;
    sigma1.negate();

    // e(1/sigma1, g2) * e(g1^{f}, sigma2) * e(g1, pk)
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (
                &(sigma1.into_affine().prepare()),
                &(G2::one().into_affine().prepare()),
            ),
            (
                &(g1fx.into_affine().prepare()),
                &(sigma.sigma2.into_affine().prepare()),
            ),
            (
                &G1::one().into_affine().prepare(),
                &pk.into_affine().prepare(),
            ),
        ]
        .into_iter(),
    ))
    .unwrap();

    // e(1/sigma1, g2) * e(g1^{f}, sigma2) * e(g1, pk) == 1?
    pairingproduct
        == Fq12 {
            c0: Fq6::one(),
            c1: Fq6::zero(),
        }
}
