use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
// the initial keys
#[derive(Debug, Clone)]
pub struct InitKey {
    pub pk: G2,
    pub sk: G1,
}

pub trait InitKeyAlgorithm {
    fn init() -> Self;
    fn key_gen_alpha() -> Self;
    fn key_gen_alpha_with_seed(seed: &[u32; 4]) -> Self;
    fn key_gen_alpha_with_rng<R: ::rand::Rng>(rng: &mut R) -> Self;
    fn get_sk(&self) -> G1;
    fn get_pk(&self) -> G2;
}
impl InitKeyAlgorithm for InitKey {
    fn get_sk(&self) -> G1 {
        self.sk.clone()
    }
    fn get_pk(&self) -> G2 {
        self.pk.clone()
    }

    fn init() -> Self {
        InitKey {
            sk: G1::zero(),
            pk: G2::zero(),
        }
    }

    fn key_gen_alpha_with_rng<R: ::rand::Rng>(rng: &mut R) -> Self {
        let alpha = Fr::rand(rng);
        let mut sk = G1::one();
        sk.mul_assign(alpha);
        let mut pk = G2::one();
        pk.mul_assign(alpha);

        InitKey { pk: pk, sk: sk }
    }

    fn key_gen_alpha_with_seed(seed: &[u32; 4]) -> Self {
        let mut rng = ChaChaRng::from_seed(seed);
        Self::key_gen_alpha_with_rng(&mut rng)
    }

    fn key_gen_alpha() -> Self {
        let mut rng = ChaChaRng::new_unseeded();
        let seed = [
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ];
        Self::key_gen_alpha_with_seed(&seed)
    }
}
