use super::SubSecretKey;
use gammafunction::{time_to_fr_vec, time_to_vec};
use pairing::{bls12_381::*, CurveProjective};
use param::{PubParam, CONST_D};
use rand::Rand;
impl SubSecretKey {
    // initialization
    pub fn init() -> Self {
        SubSecretKey {
            g2r: G1::zero(),
            g1poly: G2::zero(),
            d_elements: [G2::zero(); CONST_D],
            time: 1,
        }
    }

    // get the length of the corresponding vector length
    pub fn get_vec_x_len(&self) -> usize {
        let mut counter = 0;
        for i in 0..self.d_elements.len() {
            if self.d_elements[i] == G2::zero() {
                counter += 1;
            }
        }
        assert_eq!(
            counter,
            self.get_time_vec().len(),
            "unequal x-vec length {}, {}",
            counter,
            self.get_time_vec().len()
        );
        counter
    }

    pub fn get_time(&self) -> u64 {
        self.time
    }
    fn get_time_vec(&self) -> Vec<u64> {
        time_to_vec(self.time, CONST_D as u32)
    }

    pub fn get_g1poly(&self) -> G2 {
        self.g1poly.clone()
    }
    pub fn get_g2r(&self) -> G1 {
        self.g2r.clone()
    }
    pub fn get_d_elements(&self) -> [G2; CONST_D] {
        self.d_elements.clone()
    }

    pub fn set_g1poly(&mut self, tar: G2) {
        self.g1poly = tar;
    }
    pub fn set_g2r(&mut self, tar: G1) {
        self.g2r = tar;
    }
    pub fn set_d_elements(&mut self, tar: [G2; CONST_D]) {
        self.d_elements = tar;
    }
    pub fn set_time(&mut self, tar: u64) {
        self.time = tar;
    }

    fn subkey_gen<R: ::rand::Rng>(pp: &PubParam, g1a: G2, vec_x: &Vec<Fr>, rng: &mut R) -> Self {
        let mut sk_new: SubSecretKey = SubSecretKey::init();
        let r = Fr::rand(rng);
        let list = pp.get_glist();

        // 1. g2^r
        let mut g2r = G1::one();
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
    pub fn subkey_delegate_with_reuse<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        time: u64,
        rng: &mut R,
    ) -> Self {
        let x_prime = time_to_fr_vec(time, CONST_D as u32);
        let mut newsubkey = self.clone();
        for i in self.get_vec_x_len()..x_prime.len() {
            let mut tmp = newsubkey.d_elements[i];
            tmp.mul_assign(x_prime[i]);
            newsubkey.g1poly.add_assign(&tmp);
            newsubkey.d_elements[i] = G2::zero();
        }
        newsubkey.time = time;
        newsubkey
    }
    pub fn subkey_delegate<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        time: u64,
        //x_prime: &Vec<u32>,
        rng: &mut R,
    ) -> Self {
        let x_prime = time_to_fr_vec(time, CONST_D as u32);
        // rightside = Subkey(pp, g2^0, x_prime)
        let rightside = Self::subkey_gen(pp, G2::zero(), &x_prime, rng);

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
            leftside.d_elements[i] = G2::zero();
        }

        // scala mutliplication
        let mut tilde_sk = leftside.clone();
        for i in 0..CONST_D {
            tilde_sk.d_elements[i].add_assign(&rightside.d_elements[i]);
        }
        tilde_sk.g2r.add_assign(&rightside.g2r);
        tilde_sk.g1poly.add_assign(&rightside.g1poly);
        tilde_sk.time = time;
        tilde_sk
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
