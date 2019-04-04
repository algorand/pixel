use param::RootSecret;
use param::SubSecretKey;
//use keys::RootSecret;
use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine};
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};

pub trait SSKAlgorithm {
    fn init() -> Self;
    fn get_vec_x_len(&self) -> usize;
    fn subkey_gen<R: ::rand::Rng>(
        pp: &PubParam,
        g2a: RootSecret,
        vec_x: &Vec<Fr>,
        rng: &mut R,
    ) -> Self;
    fn subkey_delegate<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        x_prime: &Vec<Fr>,
        rng: &mut R,
    ) -> Self;
    fn print(&self);
}

impl SSKAlgorithm for SubSecretKey {
    fn init() -> Self {
        SubSecretKey {
            two_elements: [G1::zero(); 2],
            d_plus_one_elements: [G1::zero(); CONST_D + 1],
        }
    }

    fn get_vec_x_len(&self) -> usize {
        let mut counter = 0;
        for i in 0..self.d_plus_one_elements.len() {
            if self.d_plus_one_elements[i] == G1::zero() {
                counter += 1;
            }
        }
        counter
    }

    fn subkey_gen<R: ::rand::Rng>(
        pp: &PubParam,
        g2a: RootSecret,
        vec_x: &Vec<Fr>,
        rng: &mut R,
    ) -> Self {
        let mut sk_new: SubSecretKey = SubSecretKey::init();
        let r = Fr::rand(rng);
        let g1 = G1::one();

        // 1. g2^r
        let mut g1r = g1;
        g1r.mul_assign(r);
        sk_new.two_elements[0] = g1r;

        // 2. g2^{\alpha + f(x)*r}
        // 2.1 g2^f(x)
        let mut g1fx = pp.get_two_elements()[0];
        for i in 0..vec_x.len() {
            let mut tmp = pp.get_d_elements()[i];
            tmp.mul_assign(vec_x[i]);
            g1fx.add_assign(&tmp);
        }
        // 2.2 g2^{f(x)*r}
        g1fx.mul_assign(r);

        // 2.3 g2^{\alpha + f(x)*r}
        g1fx.add_assign(&g2a);
        sk_new.two_elements[1] = g1fx;

        // 3. fill with |x| number of 0s
        // for i in 0..vec_x.len() {
        //     sk_new.d_elements[i] = G2::zero();
        // }

        // 4. g2^{w_i*r}
        for i in vec_x.len()..CONST_D {
            let mut g2wr = pp.get_d_elements()[i];
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
        let xlen = leftside.clone().get_vec_x_len();

        // leftside[1] = K1* Prod_{i=|x|+1}^{|x'|} K_i ^ x'_i
        let mut tmp21 = leftside.two_elements[1];
        for i in xlen..x_prime.len() {
            let mut tmp2 = self.d_elements[i];
            tmp2.mul_assign(x_prime[i]);
            tmp21.add_assign(&tmp2);
        }
        leftside.two_elements[1] = tmp21;

        // leftside[2..|x'|] = 0
        for i in 0..x_prime.len() {
            leftside.d_elements[i] = G1::zero();
        }

        // scala mutliplication
        let mut tilde_sk = leftside.clone();
        for i in 0..CONST_D {
            tilde_sk.d_elements[i].add_assign(&rightside.d_elements[i]);
        }
        tilde_sk.two_elements[0].add_assign(&rightside.two_elements[0]);
        tilde_sk.two_elements[1].add_assign(&rightside.two_elements[1]);

        tilde_sk
    }

    fn print(&self) {
        println!("==============");
        println!("sub secret key");
        println!("first element: \n{:?}\n", self.two_elements[0]);
        println!("second element: \n{:?}\n", self.two_elements[1]);
        for i in 0..self.d_elements.len() {
            println!("{}th element: \n{:?}\n", i, self.d_elements[i]);
        }
        println!("==============\n");
    }
}
