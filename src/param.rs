use pairing::{bls12_381::*, CurveProjective};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
// the depth (dimention) of the time vector
pub const CONST_D: usize = 30;

// public parameter is a list of G1/G2 pairs
#[derive(Debug, Clone)]
pub struct PubParam {
    g0: G1,               //  g0
    glist: [G1; CONST_D], // g_1, ..., g_d
}

#[allow(dead_code)]
impl PubParam {
    pub fn get_g0(&self) -> G1 {
        return self.g0;
    }

    pub fn get_glist(&self) -> [G1; CONST_D] {
        return self.glist;
    }

    pub fn init() -> Self {
        let mut rng = ChaChaRng::new_unseeded();
        let seed = [
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ];
        Self::init_with_seed(&seed)
    }

    pub fn init_with_seed(seed: &[u32; 4]) -> Self {
        let mut rng = ChaChaRng::from_seed(seed);

        let g0 = G1::rand(&mut rng);
        let mut d = [G1::zero(); CONST_D];
        for i in 0..CONST_D {
            d[i] = G1::rand(&mut rng);
        }
        PubParam { g0: g0, glist: d }
    }

    pub fn init_with_w_and_seed(seed: &[u32; 4]) -> Self {
        let mut rng = ChaChaRng::from_seed(seed);

        let mut g0 = G1::one();
        g0.mul_assign(Fr::rand(&mut rng));
        let mut d = [G1::one(); CONST_D];
        for i in 0..CONST_D {
            d[i].mul_assign(Fr::rand(&mut rng));
        }
        PubParam { g0: g0, glist: d }
    }
}
