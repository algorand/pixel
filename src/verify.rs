use ff::Field;
use pairing::{bls12_381::*, CurveProjective, Engine};
use param::{PubParam, CONST_D};
use sign::Signature;

#[allow(dead_code)]
pub fn verification(pk: &G2, pp: &PubParam, time: &Vec<Fr>, msg: &Fr, sigma: &Signature) -> bool {
    // e(sigma_1, g2)
    let right = Bls12::pairing(sigma.sigma1, G2::one());

    // e(g1, pk)
    let mut left = Bls12::pairing(G1::one(), pk.into_affine());

    // g1^{w[1] * msg}
    let mut g1tmp = pp.get_g0();
    let list = pp.get_glist();
    for i in 0..time.len() {
        let mut tmp = list[i];
        tmp.mul_assign(time[i]);
        g1tmp.add_assign(&tmp);
    }
    let mut tmp = list[CONST_D - 1];
    tmp.mul_assign(*msg);
    g1tmp.add_assign(&tmp);
    let gttmp = Bls12::pairing(g1tmp, sigma.sigma2);
    left.mul_assign(&gttmp);
    left == right
}
