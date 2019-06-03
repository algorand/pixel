// param module implements the parameters that are used
// in pixel signature

use pairing::{bls12_381::G2, CurveProjective};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
use util::hash_to_field_fr;
pub const CONST_D: usize = 30;

// public parameter is a G2 element, followed
// by d G2 elements
// we need in total d+1 G2 elements
// the first d elements corresponding to 2^d time stamps
// the additional one element is used for signing the signature
#[derive(Debug, Clone)]
pub struct PubParam {
    g0: G2,               //  g0
    glist: [G2; CONST_D], // g_1, ..., g_d
}

impl PubParam {
    // accessing private field in PubParam
    pub fn get_g0(&self) -> G2 {
        return self.g0;
    }

    pub fn get_glist(&self) -> [G2; CONST_D] {
        return self.glist;
    }

    // initialization a public param
    // if the seed is unset, use chacha to generate a seed
    // in practice this function should not be used
    // use init_with_w_and_seed instead
    pub fn init() -> Self {
        println!("Seed for parameters are not specified");
        println!("Use this function with caution");
        let mut rng = ChaChaRng::new_unseeded();
        let seed = [
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ];
        Self::init_with_seed(&seed)
    }

    // initialize the parameter with a seed
    // use seed to instantiate a chacha random number generator
    // and use pairing library internal rand() to get the parameters
    pub fn init_with_seed(seed: &[u32; 4]) -> Self {
        let mut rng = ChaChaRng::from_seed(seed);

        let g0 = G2::rand(&mut rng);
        let mut d = [G2::zero(); CONST_D];
        for i in 0..CONST_D {
            d[i] = G2::rand(&mut rng);
        }
        PubParam { g0: g0, glist: d }
    }

    // initialize the parameter with a seed
    // use hash_to_field (seed, ctr, 1, 2) to generate field elements w0, ... wd
    // generate parameters as g^{w_i}
    pub fn init_with_w_and_seed(seed: &[u32; 4]) -> Self {
        // expand the input into a byte string
        // TODO: decide if we want to use
        //    1. seed, or
        //    2. hash(seed)
        let mut input: Vec<u8> = vec![];
        for i in 0..4 {
            let mut tmp = seed[i];
            for _ in 0..4 {
                let t = (tmp & 0xff) as u8;
                input.push(t);
                tmp >>= 8;
            }
        }

        // the counter for hash to field
        let mut ctr = 0;

        // generate a random Fr element from hash_to_field
        let r = hash_to_field_fr(input.as_ref(), ctr, 1, 2);
        // update the counter
        ctr += 1;
        // compute g^r
        let mut g0 = G2::one();
        g0.mul_assign(r[0]);

        let mut d = [G2::one(); CONST_D];
        for i in 0..CONST_D {
            // generate a random Fr element from hash_to_field
            let r = hash_to_field_fr(input.as_ref(), ctr, 1, 2);
            // update the counter
            ctr += 1;
            // compute g^r
            d[i].mul_assign(r[0]);
        }
        PubParam { g0: g0, glist: d }
    }
}
