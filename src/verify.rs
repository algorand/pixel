use keys::PublicKey;
use keys::RootSecret;
use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine, Field};
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};


pub trait PKAlgorithm {
    //    fn verify(self, pp: &PubParam, vec_t: &Vec<Fr>, msg: &Fr, sigma: &Signature) -> bool;
    fn verify_raw(self, pp: &PubParam, msg: &Fr, sigma: &Signature) -> bool;
}

impl PKAlgorithm for PublicKey {
    fn verify_raw(self, pp: &PubParam, msg: &Fr, sigma: &Signature) -> bool {
        // g1^w[0]
        let mut left = Bls12::pairing(sigma.sigma1, G2::one());

        // g1^{w[1] * msg}
        let mut tmp = pp.get_two_elements()[1];
        tmp.mul_assign(*msg);
        left.add_assign(&tmp);

        let mut s = sigma[0].clone();
        s.negate();
        let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (
                    &(left.into_affine().prepare()),
                    &(s.into_affine().prepare()),
                ),
                (
                    &(G1::one().into_affine().prepare()),
                    &(sigma[1].into_affine().prepare()),
                ),
            ]
            .into_iter(),
        ))
        .unwrap();
        self == pairingproduct
    }
}
