use super::KeyPair;
use super::SecretKey;
use super::SubSecretKey;
//use gammafunction::time_to_fr_vec;
//use gammafunction::time_to_vec;
use pairing::{bls12_381::*, CurveProjective};
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};

impl KeyPair {
    pub fn get_sk(&self) -> SecretKey {
        self.sk.clone()
    }
    pub fn get_pk(&self) -> G1 {
        self.pk.clone()
    }
    pub fn init() -> Self {
        KeyPair {
            sk: SecretKey::init(),
            pk: G1::zero(),
        }
    }
    pub fn root_key_gen_with_rng<R: ::rand::Rng>(rng: &mut R, pp: &PubParam) -> Self {
        let initkey = key_gen_alpha_with_rng(rng);
        let r = Fr::rand(rng);
        let mut ssk: SubSecretKey = SubSecretKey {
            g2r: G1::zero(),
            g1poly: G2::zero(),
            d_elements: [G2::zero(); CONST_D],
            time: 1,
        };
        let glist = pp.get_glist();

        let mut tmp = G1::one();
        tmp.mul_assign(r);
        ssk.set_g2r(tmp);

        let mut tmp = pp.get_g0();
        tmp.mul_assign(r);
        tmp.add_assign(&initkey.1);
        //    ssk.g1poly = pp.get_g0();
        //    ssk.g1poly.mul_assign(r);
        //    ssk.g1poly.add_assign(&initkey.1);
        ssk.set_g1poly(tmp);

        for i in 0..CONST_D {
            ssk.d_elements[i] = glist[i];
            ssk.d_elements[i].mul_assign(r);
        }
        let mut sk = SecretKey::init();
        sk.set_time(1);
        sk.set_sub_secretkey(vec![ssk]);
        Self {
            sk: sk,

            pk: initkey.0,
        }
    }

    pub fn root_key_gen_with_seed(seed: &[u32; 4], pp: &PubParam) -> KeyPair {
        let mut rng = ChaChaRng::from_seed(seed);
        Self::root_key_gen_with_rng(&mut rng, &pp)
    }
    pub fn root_key_gen(pp: &PubParam) -> Self {
        let mut rng = ChaChaRng::new_unseeded();
        let seed = [
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ];
        Self::root_key_gen_with_seed(&seed, pp)
    }
}

fn key_gen_alpha_with_rng<R: ::rand::Rng>(rng: &mut R) -> (G1, G2) {
    let alpha = Fr::rand(rng);
    let mut sk = G2::one();
    sk.mul_assign(alpha);
    let mut pk = G1::one();
    pk.mul_assign(alpha);

    (pk, sk)
}

fn key_gen_alpha_with_seed(seed: &[u32; 4]) -> (G1, G2) {
    let mut rng = ChaChaRng::from_seed(seed);
    key_gen_alpha_with_rng(&mut rng)
}

fn key_gen_alpha() -> (G1, G2) {
    let mut rng = ChaChaRng::new_unseeded();
    let seed = [
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ];
    key_gen_alpha_with_seed(&seed)
}
