use super::KeyPair;
use super::SecretKey;
use super::SubSecretKey;
use pairing::{bls12_381::*, CurveProjective};
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};

impl KeyPair {
    // export private fields
    pub fn get_sk(&self) -> SecretKey {
        self.sk.clone()
    }
    pub fn get_pk(&self) -> G1 {
        self.pk.clone()
    }

    // initialize a key pair with 0s
    pub fn init() -> Self {
        KeyPair {
            sk: SecretKey::init(),
            pk: G1::zero(),
        }
    }

    // generate a root key from an RNG
    pub fn root_key_gen_with_rng<R: ::rand::Rng>(rng: &mut R, pp: &PubParam) -> Self {
        let initkey = key_gen_alpha_with_rng(rng);
        // todo: change to r = hash_to_field(seed)
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

    // this function in principal should not be used in practice
    pub fn root_key_gen(pp: &PubParam) -> Self {
        println!("Seed for root key gen are not specified");
        println!("Use this function with caution");
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

// change to hash_to_field method
fn key_gen_alpha_with_rng<R: ::rand::Rng>(rng: &mut R) -> (G1, G2) {
    let alpha = Fr::rand(rng);
    let mut sk = G2::one();
    sk.mul_assign(alpha);
    let mut pk = G1::one();
    pk.mul_assign(alpha);

    (pk, sk)
}

#[allow(dead_code)]
fn key_gen_alpha_with_seed(seed: &[u32; 4]) -> (G1, G2) {
    let mut rng = ChaChaRng::from_seed(seed);
    key_gen_alpha_with_rng(&mut rng)
}

#[allow(dead_code)]
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
