use ff::Field;
use gammafunction::time_to_fr_vec;
use keys::SubSecretKey;
use pairing::{bls12_381::*, CurveProjective};
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, SeedableRng};

#[derive(Debug, Clone)]
pub struct Signature {

    pub sigma1: G2,
    pub sigma2: G1,

}

impl Signature {
    pub fn get_sigma1(&self) -> G1 {
        self.sigma1.clone()
    }
    pub fn get_sigma2(&self) -> G2 {
        self.sigma2.clone()
    }
    pub fn sign<R: ::rand::Rng>(
        ssk: &SubSecretKey,
        pp: &PubParam,
        vec_t: &Vec<Fr>,
        msg: &Fr,
        rng: &mut R,
    ) -> Self {
        let mut v = vec_t.clone();
        for _ in vec_t.len()..CONST_D - 1 {
            v.push(Fr::zero());
        }
        v.push(*msg);
        let ssknew = partial_subkey_delegate(&ssk, &pp, &v, rng);
        Signature {
            sigma1: ssknew.1,
            sigma2: ssknew.0,
        }
    }

    pub fn sign_with_seed(
        ssk: &SubSecretKey,
        pp: &PubParam,
        time: &u64,
        msg: &Fr,
        seed: &[u32; 4],
    ) -> Self {
        let mut rng = ChaChaRng::from_seed(seed);
        let time_vec = time_to_fr_vec(*time, CONST_D as u32);
        Self::sign(ssk, pp, &time_vec, msg, &mut rng)
    }

    pub fn aggregate_assign(&mut self, siglist: &Vec<Self>) {
        for sig in siglist {
            self.sigma1.add_assign(&sig.sigma1);
            self.sigma2.add_assign(&sig.sigma2);
        }
    }
    pub fn aggregate(siglist: &Vec<Self>) -> Self {
        let mut s: Signature = Signature {
            sigma1: G1::zero(),
            sigma2: G2::zero(),
        };
        for sig in siglist {
            s.sigma1.add_assign(&sig.sigma1);
            s.sigma2.add_assign(&sig.sigma2);
        }
        s
    }
}

fn partial_subkey_delegate<R: ::rand::Rng>(
    ssk: &SubSecretKey,
    pp: &PubParam,
    x_prime: &Vec<Fr>,
    rng: &mut R,
) -> (G1, G2) {
    // rightside = Subkey(pp, g2^0, x_prime)
    let rightside = partial_subkey_gen(pp, x_prime, rng);

    // g2^r * rightside[0]
    let mut g2r = ssk.get_g2r();
    g2r.add_assign(&rightside.0);

    // g1poly * rightside[1]
    // g1poly = K1* Prod_{i=|x|+1}^{|x'|} K_i ^ x'_i
    let xlen = ssk.get_vec_x_len();
    let mut g1poly = ssk.get_g1poly();
    let d_elements = ssk.get_d_elements();
    for i in xlen..x_prime.len() {
        let mut tmp2 = d_elements[i];
        tmp2.mul_assign(x_prime[i]);
        g1poly.add_assign(&tmp2);
    }

    g1poly.add_assign(&rightside.1);

    (g2r, g1poly)
}

fn partial_subkey_gen<R: ::rand::Rng>(pp: &PubParam, vec_x: &Vec<Fr>, rng: &mut R) -> (G1, G2) {
    let r = Fr::rand(rng);
    let list = pp.get_glist();

    // 1. g2^r
    let mut g2r = G1::one();
    g2r.mul_assign(r);

    // 2. g2^{\alpha + f(x)*r}
    // 2.1 g2^f(x)
    let mut g1fx = pp.get_g0();
    for i in 0..vec_x.len() {
        let mut tmp = list[i];
        tmp.mul_assign(vec_x[i]);
        g1fx.add_assign(&tmp);
    }
    // 2.2 g2^{f(x)*r}
    g1fx.mul_assign(r);

    (g2r, g1fx)
}
