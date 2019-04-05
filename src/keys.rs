use gammafunction::time_to_fr_vec;
use initkey::{InitKey, InitKeyAlgorithm};
use pairing::{bls12_381::*, CurveProjective};
use param::SecretKey;
use param::SubSecretKey;
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};

#[derive(Debug, Clone)]
pub struct Keys {
    sk: SecretKey,
    pk: G2,
}

pub trait KeysAlgorithm {
    fn init() -> Self;
    fn get_sk(&self) -> SecretKey;
    fn get_pk(&self) -> G2;
    fn root_key_gen(pp: &PubParam) -> Self;
    fn root_key_gen_with_seed(seed: &[u32; 4], pp: &PubParam) -> Self;
    fn root_key_gen_with_rng<R: ::rand::Rng>(rng: &mut R, pp: &PubParam) -> Self;
}

// pub trait SKAlgorithm {
//     fn key_delegate<R: ::rand::Rng>(&mut self, pp: &PubParam, time: &u64, rng: &mut R);
// }

pub trait SSKAlgorithm {
    fn init() -> Self;
    fn get_vec_x_len(&self) -> usize;
    fn subkey_gen<R: ::rand::Rng>(pp: &PubParam, g1a: G1, vec_x: &Vec<Fr>, rng: &mut R) -> Self;
    fn subkey_delegate<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        x_prime: &Vec<Fr>,
        rng: &mut R,
    ) -> Self;

    fn subkey_delegate_time<R: ::rand::Rng>(&self, pp: &PubParam, time: &u64, rng: &mut R) -> Self;
    fn print(&self);
}

impl KeysAlgorithm for Keys {
    fn get_sk(&self) -> SecretKey {
        self.sk.clone()
    }
    fn get_pk(&self) -> G2 {
        self.pk.clone()
    }
    fn init() -> Self {
        Keys {
            sk: Vec::new(),
            pk: G2::zero(),
        }
    }
    fn root_key_gen_with_rng<R: ::rand::Rng>(rng: &mut R, pp: &PubParam) -> Self {
        let initkey = InitKey::key_gen_alpha_with_rng(rng);
        let r = Fr::rand(rng);
        let mut ssk: SubSecretKey = SSKAlgorithm::init();
        let glist = pp.get_glist();

        ssk.g2r = G2::one();
        ssk.g2r.mul_assign(r);
        ssk.g1poly = pp.get_g0();
        ssk.g1poly.mul_assign(r);
        ssk.g1poly.add_assign(&initkey.sk);

        for i in 0..CONST_D {
            ssk.d_elements[i] = glist[i];
            ssk.d_elements[i].mul_assign(r);
        }

        Self {
            sk: vec![ssk],
            pk: initkey.pk,
        }
    }

    fn root_key_gen_with_seed(seed: &[u32; 4], pp: &PubParam) -> Keys {
        let mut rng = ChaChaRng::from_seed(seed);
        Self::root_key_gen_with_rng(&mut rng, &pp)
    }
    fn root_key_gen(pp: &PubParam) -> Self {
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

// impl SKAlgorithm for SecretKey {
//     fn key_delegate<R: ::rand::Rng>(&mut self, pp: &PubParam, time: &u64, rng: &mut R) {
//         let current_time = self[0]
//
//
//     }
// }

impl SSKAlgorithm for SubSecretKey {
    fn init() -> Self {
        SubSecretKey {
            g2r: G2::zero(),
            g1poly: G1::zero(),
            d_elements: [G1::zero(); CONST_D],
        }
    }

    fn get_vec_x_len(&self) -> usize {
        let mut counter = 0;
        for i in 0..self.d_elements.len() {
            if self.d_elements[i] == G1::zero() {
                counter += 1;
            }
        }
        counter
    }

    fn subkey_gen<R: ::rand::Rng>(pp: &PubParam, g1a: G1, vec_x: &Vec<Fr>, rng: &mut R) -> Self {
        let mut sk_new: SubSecretKey = SubSecretKey::init();
        let r = Fr::rand(rng);
        let list = pp.get_glist();

        // 1. g2^r
        let mut g2r = G2::one();
        g2r.mul_assign(r);
        sk_new.g2r = g2r;

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

        // 2.3 g2^{\alpha + f(x)*r}
        g1fx.add_assign(&g1a);
        sk_new.g1poly = g1fx;

        // 3. fill with |x| number of 0s
        // for i in 0..vec_x.len() {
        //     sk_new.d_elements[i] = G2::zero();
        // }

        // 4. g2^{w_i*r}
        for i in vec_x.len()..CONST_D {
            let mut g2wr = list[i];
            g2wr.mul_assign(r);
            sk_new.d_elements[i] = g2wr;
        }
        sk_new
    }

    fn subkey_delegate<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        x_prime: &Vec<Fr>,
        rng: &mut R,
    ) -> Self {
        // rightside = Subkey(pp, g2^0, x_prime)
        let rightside = Self::subkey_gen(pp, G1::zero(), x_prime, rng);

        // leftside = (K0, ..., KD)
        // leftside[0] = K0
        let mut leftside = self.clone();
        let xlen = leftside.get_vec_x_len();

        // leftside[1] = K1* Prod_{i=|x|+1}^{|x'|} K_i ^ x'_i
        let mut tmp21 = leftside.g1poly;
        for i in xlen..x_prime.len() {
            let mut tmp2 = self.d_elements[i];
            tmp2.mul_assign(x_prime[i]);
            tmp21.add_assign(&tmp2);
        }
        leftside.g1poly = tmp21;

        // leftside[2..|x'|] = 0
        for i in 0..x_prime.len() {
            leftside.d_elements[i] = G1::zero();
        }

        // scala mutliplication
        let mut tilde_sk = leftside.clone();
        for i in 0..CONST_D {
            tilde_sk.d_elements[i].add_assign(&rightside.d_elements[i]);
        }
        tilde_sk.g2r.add_assign(&rightside.g2r);
        tilde_sk.g1poly.add_assign(&rightside.g1poly);

        tilde_sk
    }
    fn subkey_delegate_time<R: ::rand::Rng>(&self, pp: &PubParam, time: &u64, rng: &mut R) -> Self {
        let timevec = time_to_fr_vec(*time as u32, CONST_D as u32);
        Self::subkey_delegate(&self, &pp, &timevec, rng)
    }

    fn print(&self) {
        println!("==============");
        println!("sub secret key");
        println!("first element: \n{:?}\n", self.g2r);
        println!("second element: \n{:?}\n", self.g1poly);
        for i in 0..self.d_elements.len() {
            println!("{}th element: \n{:?}\n", i, self.d_elements[i]);
        }
        println!("==============\n");
    }
}
