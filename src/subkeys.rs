use pairing::bls12_381::Fr;

use param::PubParam;
use param::CONST_D;

use pairing::CurveProjective;
use std::fmt;
use time::{TimeStamp, TimeVec};
use PixelG1;
use PixelG2;

#[cfg(test)]
use pairing::CurveAffine;

#[cfg(test)]
use pairing::{bls12_381::*, Engine};

#[cfg(test)]
use ff::Field;

/// each SubSecretKey consists of
/// * time: the time stamp for the current key
/// * g1r: the randomization on G1
/// * h0poly: h0^{alpha + f(x) r}
/// * hlist: the randomization of the public parameter hlist
#[derive(Clone, PartialEq)]
pub struct SubSecretKey {
    /// timestamp for the current subkey
    time: TimeStamp,
    /// randomization on g1: g1^r
    g2r: PixelG2,

    /// mirroring the public parameter
    hpoly: PixelG1, //  h^{alpha + f(x) r}

    /// the randomization of the public parameter hlist
    hvector: Vec<PixelG1>,
}

impl SubSecretKey {
    /// function initialize the root secret key at time stamp = 1
    /// with input public parameters, the state of randomness, and a master secret alpha
    pub fn init(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
        let mut hlist = pp.get_hlist().clone();

        // g1^r
        let mut g2r = pp.get_g2();
        g2r.mul_assign(r);

        // h^msk * h0^r
        let mut hpoly = hlist[0];
        hpoly.mul_assign(r);
        hpoly.add_assign(&alpha);

        // hi^r
        let mut hvector: Vec<PixelG1> = vec![];
        for i in 1..CONST_D + 1 {
            hlist[i].mul_assign(r);
            hvector.push(hlist[i]);
        }
        // format the output
        SubSecretKey {
            // time stamp is 1 since this is the root key
            time: 1,
            g2r: g2r,
            hpoly: hpoly,
            hvector: hvector,
        }
    }

    /// this initialization function uses randomization
    /// as a subroutine;
    /// it should generate a same subsecret key as Self::init()
    /// as long as the randomness stays the same
    /// see test_init()
    pub fn init_from_randomization(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
        let mut s = SubSecretKey {
            // time stamp is 1 since this is the root key
            time: 1,
            g2r: PixelG2::zero(),
            hpoly: alpha,
            hvector: [PixelG1::zero(); CONST_D].to_vec(),
        };
        s.randomization(pp, r);
        s
    }

    /// given a subsecrerkey,
    /// re-randomize it with r
    /// g2^r, (h_0 prod hj^wj)^r, h_{|w|+1}^r, ..., h_D^r
    pub fn randomization(&mut self, pp: &PubParam, r: Fr) {
        // randomize g1r
        let mut tmp = pp.get_g2();
        tmp.mul_assign(r);
        self.g2r.add_assign(&tmp);

        // compute tmp = hv[0] * prod_i h[i]^time_vec[i]
        let hlist = pp.get_hlist();
        let timevec = self.get_time_vec();
        let tlen = timevec.get_time_vec_len();
        let tv = timevec.get_time_vec();
        let mut tmp = hlist[0];
        for i in 0..tlen {
            let mut tmp2 = hlist[i + 1];
            tmp2.mul_assign(tv[i]);
            tmp.add_assign(&tmp2);
        }

        // radomize hpoly += tmp^r
        tmp.mul_assign(r);
        self.hpoly.add_assign(&tmp);

        // randmoize hlist
        //        let mut hvector: Vec<PixelG2> = vec![];
        for i in 0..self.hvector.len() {
            // randomnize the non-zero elements
            //        if self.hlist[i] != G2::zero() {
            let mut tmp = hlist[tlen + i + 1];
            tmp.mul_assign(r);
            self.hvector[i].add_assign(&tmp);
            //            hlist[i].mul_assign(r);
            //            self.hvector[i].add_assign(&hlist[i]);
            //        }
        }
    }

    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    pub fn get_time_vec(&self) -> TimeVec {
        TimeVec::init(self.time, CONST_D as u32)
    }

    /// delegate the key into TimeStamp time,
    pub fn delegate(&mut self, time: TimeStamp) {
        let cur_time_vec = TimeVec::init(self.time, CONST_D as u32);
        let tar_time_vec = TimeVec::init(time, CONST_D as u32);

        // check that cur_time_vec is a prefix of tar_time_vec
        assert!(
            cur_time_vec.is_prefix(&tar_time_vec),
            "error:invalid vectors\nthe current time vector is {:?},\n trying to delegeate into {:?}\n",
            cur_time_vec,
            tar_time_vec,
        );
        let tar_time_vec_fr = tar_time_vec.into_fr();
        let cur_vec_length = cur_time_vec.get_time_vec_len();
        let tar_vec_length = tar_time_vec.get_time_vec_len();
//        println!("time: in tests  {:?} {:?}", cur_vec_length, tar_time_vec_fr);

        // hpoly += h_i ^ t_i
        for i in 0..tar_vec_length - cur_vec_length {
    //        println!("{:?}", i);
            let mut tmp = self.hvector[i];
            tmp.mul_assign(tar_time_vec_fr[i + cur_vec_length]);
            self.hpoly.add_assign(&tmp);
        }

        // remove the first tar_vec_length - cur_vec_length elements in h-vector
        for _ in 0..tar_vec_length - cur_vec_length {
            // h_i = 0
            self.hvector.remove(0);
        }
        self.time = time;
    }

    /// this function is used to verify if a subsecretkey is valid
    /// for some public key
    /// it is used for test only
    #[cfg(test)]
    pub fn validate(&self, pk: &PixelG2, pp: &PubParam) -> bool {
        let list = pp.get_hlist();
        let t = TimeVec::init(self.time, CONST_D as u32);

        let timevec = t.get_time_vec();

        // h2fx = h0 * \prod hi^ti
        let mut h2fx = list[0];
        for i in 0..t.get_time_vec_len() {
            let mut tmp = list[i + 1];
            tmp.mul_assign(timevec[i]);
            h2fx.add_assign(&tmp);
        }

        // we want to check if
        //   e(hpoly, g2) == e(h, pk) * e(h0*hi^ti, g2r)
        // we first negate g2
        let mut g2 = pp.get_g2();
        g2.negate();

        // and then use sim-pairing for faster computation

        // due to the api changes in asymmetric pairing,
        // we need two pieces of codes, depending on which group PK is in
        #[cfg(feature = "pk_in_g2")]
        let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (
                    &(self.hpoly.into_affine().prepare()),
                    &(g2.into_affine().prepare()),
                ),
                (
                    &(h2fx.into_affine().prepare()),
                    &(self.g2r.into_affine().prepare()),
                ),
                (
                    &(pp.get_h().into_affine().prepare()),
                    &(pk.into_affine().prepare()),
                ),
            ]
            .into_iter(),
        ))
        .unwrap();

        #[cfg(not(feature = "pk_in_g2"))]
        let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (
                    &(g2.into_affine().prepare()),
                    &(self.hpoly.into_affine().prepare()),
                ),
                (
                    &(self.g2r.into_affine().prepare()),
                    &(h2fx.into_affine().prepare()),
                ),
                (
                    &(pk.into_affine().prepare()),
                    &(pp.get_h().into_affine().prepare()),
                ),
            ]
            .into_iter(),
        ))
        .unwrap();

        // verification is successful if
        //   e(hpoly, -g2) * e(h, pk) * e(h0*hi^ti, g2r) == 1
        pairingproduct
            == Fq12 {
                c0: Fq6::one(),
                c1: Fq6::zero(),
            }
    }
}

/// convenient function to output a subsecretkey object
impl fmt::Debug for SubSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Sub Secret key========\n\
             time : {:?}\n\
             time_vec: {:?}\n\
             g1r: {:#?}\n\
             h0 : {:#?}\n",
            self.time,
            self.get_time_vec(),
            self.g2r.into_affine(),
            self.hpoly.into_affine(),
        )?;
        for i in 0..self.hvector.len() {
            write!(f, "hlist: h{}: {:#?}\n", i, self.hvector[i].into_affine())?;
        }
        write!(f, "================================\n")
    }
}

#[test]
fn test_init() {
    use ff::PrimeField;

    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();
    let pp = PubParam::init_without_seed();
    // a random master secret key
    let mut alpha = pp.get_g1();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    let t = SubSecretKey::init(&pp, alpha, r);
    let t1 = SubSecretKey::init_from_randomization(&pp, alpha, r);

    // make sure the sub secret keys are the same
    assert_eq!(t.g2r, t1.g2r, "g1r incorrect");
    assert_eq!(
        t.hpoly.into_affine(),
        t1.hpoly.into_affine(),
        "hpoly incorrect"
    );
    for i in 0..CONST_D {
        assert_eq!(
            t.hvector[i], t1.hvector[i],
            "error on {}th element in hlist",
            i
        )
    }
}

#[test]
fn test_randomization() {
    use ff::PrimeField;
    let pp = PubParam::init_without_seed();
    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();

    // a random master secret key
    let mut alpha = pp.get_h();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    // a random public key
    let mut pk = pp.get_g2();
    pk.mul_assign(msk);

    // initialize a random secret key
    let mut t = SubSecretKey::init(&pp, alpha, r);
    // check if the key is valid or not
    assert!(t.validate(&pk, &pp), "initial key failure for validation");

    // randomize the key
    let r = Fr::from_str("12345").unwrap();
    t.randomization(&pp, r);

    // check if the key remains valid or not
    assert!(
        t.validate(&pk, &pp),
        "randomized key failure for validation"
    );
}

#[test]
fn test_delegate() {
    use ff::PrimeField;
    let pp = PubParam::init_without_seed();
    // a random field element
    let r = Fr::from_str(
        "5902757315117623225217061455046442114914317855835382236847240262163311537283",
    )
    .unwrap();

    // a random master secret key
    let mut alpha = pp.get_h();
    let msk = Fr::from_str(
        "8010751325124863419913799848205334820481433752958938231164954555440305541353",
    )
    .unwrap();
    alpha.mul_assign(msk);

    // a random public key
    let mut pk = pp.get_g2();
    pk.mul_assign(msk);

    // initialize a random secret key
    let mut t = SubSecretKey::init(&pp, alpha, r);
    let t1 = t.clone();

    // check if the key is valid or not
    assert!(t.validate(&pk, &pp), "fail init");

    // randomize the key
    let r = Fr::from_str("12345").unwrap();
    t.randomization(&pp, r);

    // check if the key remains valid or not
    assert!(
        t.validate(&pk, &pp),
        "randomized key failure for validation"
    );

    // delegate gradually, 1 -> 2 -> 3 -> 4
    for i in 2..5 {
        // delegate the key to the time
        t.delegate(i);
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after delation, \n{:?}",
            i,
            t
        );
        // randomize the key
        t.randomization(&pp, r);
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after randomizeation, \n{:?}",
            i,
            t
        );
    }

    // fast delegation, always starts from t = 1
    // 1 -> 2, 1 -> 3, 1 -> 4
    for i in 2..5 {
        let mut t = t1.clone();
        t.delegate(i);
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after delation, \n{:?}",
            i,
            t
        );
        // randomize the key
        t.randomization(&pp, r);
        // check if the key remains valid or not
        assert!(
            t.validate(&pk, &pp),
            "failure: {}-th key after randomizeation, \n{:?}",
            i,
            t
        );
    }
}
