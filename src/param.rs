use pairing::{bls12_381::*, CurveProjective};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
// the depth (dimention) of the time vector
pub const CONST_D: usize = 3;

// the public key is a Gt element
pub type PublicKey = G2;

// the secret key is a list of SubSecretKeys
// the length is arbitrary
pub type SecretKey = Vec<SubSecretKey>;

// g1^\alpha, the root secret
pub type RootSecret = G1;

#[derive(Debug, Clone)]
pub struct SubSecretKey {
    pub two_elements: [G1; 2],
    // the first d-1 elements are for delegations
    // the last element is for the message
    pub d_plus_one_elements: [G1; CONST_D + 1],
}

// public parameter is a list of G1/G2 pairs
#[derive(Debug, Clone)]
pub struct PubParam {
    h: G1,
    hlist: [G1; CONST_D + 2], // h_0, ..., h_{l+1}
}

#[allow(dead_code)]
impl PubParam {
    pub fn get_h(&self) -> G1 {
        return self.h;
    }

    pub fn get_hlist(&self) -> [G1; CONST_D + 2] {
        return self.hlist;
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

        let h = G1::rand(&mut rng);
        let mut d = [G1::zero(); CONST_D + 2];
        for i in 0..CONST_D + 2 {
            d[i] = G1::rand(&mut rng);
        }
        PubParam { h: h, hlist: d }
    }
}
