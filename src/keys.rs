use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine};

use param::PublicKey;
use param::RootSecret;
use param::SecretKey;
use param::SubSecretKey;
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
use subkeys::SSKAlgorithm;
#[derive(Debug, Clone)]
pub struct Keys {
    sk: SecretKey,
    pk: PublicKey,
}

pub trait KeysAlgorithm {
    fn init() -> Self;
    //    fn key_gen(&mut self, pp: &PubParam);
    //    fn key_gen_with_seed(&mut self, pp: &PubParam, seed: [u32; 4]);
    //     next two function return g2^a as the secret key instead of a fully expanded version
    fn key_gen_alpha(pp: &PubParam) -> (RootSecret, PublicKey);
    fn key_gen_alpha_with_seed(seed: &[u32; 4], pp: &PubParam) -> (RootSecret, PublicKey);
    fn get_sk(&self) -> SecretKey;
    fn get_pk(&self) -> PublicKey;
    fn root_key_gen(pp: &PubParam) -> Keys;
    fn root_key_gen_with_seed(seed: &[u32; 4], pp: &PubParam) -> Keys;
}

impl KeysAlgorithm for Keys {
    fn get_sk(&self) -> SecretKey {
        self.sk.clone()
    }
    fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }
    fn init() -> Self {
        Keys {
            sk: Vec::new(),
            pk: G2::zero(),
        }
    }
    fn key_gen_alpha_with_seed(seed: &[u32; 4], pp: &PubParam) -> (RootSecret, PublicKey) {
        let mut rng = ChaChaRng::from_seed(seed);
        let alpha = Fr::rand(&mut rng);
        let mut sk = pp.get_h();
        sk.mul_assign(alpha);
        let mut pk = G2::one();
        pk.mul_assign(alpha);

        (sk, pk)
    }

    fn key_gen_alpha(pp: &PubParam) -> (RootSecret, PublicKey) {
        let mut rng = ChaChaRng::new_unseeded();
        let seed = [
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ];
        Self::key_gen_alpha_with_seed(&seed, pp)
    }

    fn root_key_gen_with_seed(seed: &[u32; 4], pp: &PubParam) -> Keys {
        let mut rng = ChaChaRng::from_seed(seed);
        let seed1 = [
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
            rng.next_u32(),
        ];

        let (skraw, pk) = Self::key_gen_alpha_with_seed(&seed1, pp);
        let r = Fr::rand(&mut rng);
        let mut ssk: SubSecretKey = SSKAlgorithm::init();
        let hlist = pp.get_hlist();
        ssk.two_elements[0] = G1::one();
        ssk.two_elements[0].mul_assign(r);
        ssk.two_elements[1] = hlist[0];
        ssk.two_elements[1].mul_assign(r);
        ssk.two_elements[1].add_assign(&skraw);
        for i in 0..CONST_D + 1 {
            ssk.d_plus_one_elements[i] = hlist[i + 1];
            ssk.d_plus_one_elements[i].mul_assign(r);
        }

        Keys {
            sk: vec![ssk],
            pk: pk,
        }
    }
    fn root_key_gen(pp: &PubParam) -> Keys {
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
