// a module for sub secret keys and related functions
// to decide: whether this should be packed into key.rs?

use ff::Field;
use keys::PublicKey;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use param::PubParam;
use std::fmt;
use time::{TimeStamp, TimeVec};
use PixelG1;
use PixelG2;

/// Each SubSecretKey consists of ...
/// * time: the time stamp for the current key
/// * g1r: the randomization on G1
/// * h0poly: h0^{alpha + f(x) r}
/// * hlist: the randomization of the public parameter hlist
#[derive(Clone, PartialEq)]
pub struct SubSecretKey {
    /// timestamp for the current subkey
    time: TimeStamp,
    /// randomization on g2: g2^r
    g2r: PixelG2,

    /// mirroring the public parameter
    hpoly: PixelG1, //  h^{alpha + f(x) r}

    /// the randomization of the public parameter hlist
    hvector: Vec<PixelG1>,
}

impl SubSecretKey {
    /// Returns the time stamp of the sub secret key.
    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    /// Returns the time vector associated with the time stamp.
    /// for the current sub secret key.
    pub fn get_time_vec(&self, depth: usize) -> TimeVec {
        TimeVec::init(self.time, depth)
    }

    /// Returns the first element `g^r` in a sub secret key.
    pub fn get_g2r(&self) -> PixelG2 {
        self.g2r.clone()
    }

    /// Returns the second element `(h0 \prod h_i^t_i )^r`
    /// in a sub secret key.
    pub fn get_hpoly(&self) -> PixelG1 {
        self.hpoly.clone()
    }

    /// Returns the last coefficient of the h_vector;
    /// a short cut used by signing algorithm.
    /// note that by default the rest of the elements in
    /// h_vector are private.
    pub fn get_last_hvector_coeff(&self) -> PixelG1 {
        self.hvector[self.hvector.len() - 1].clone()
    }

    /// This function initializes the root secret key at time stamp = 1,
    /// with input public parameters and a master secret `alpha`.
    //  It produces a same key as init_from_randomization if
    //  same randomness are used. see `test_key_gen()`.
    pub fn init(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
        let mut hlist = pp.get_hlist().clone();
        let depth = pp.get_d();

        // g2^r
        let mut g2r = pp.get_g2();
        g2r.mul_assign(r);

        // h^msk * h0^r
        let mut hpoly = hlist[0];
        hpoly.mul_assign(r);
        hpoly.add_assign(&alpha);

        // hi^r
        let mut hvector: Vec<PixelG1> = Vec::with_capacity(depth);
        for i in 1..depth + 1 {
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

    /// Given a subsecrerkey `sk = [g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r]`,
    /// re-randomize it with `r`, and outputs
    /// `g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r`.
    pub fn randomization(&mut self, pp: &PubParam, r: Fr) {
        let depth = pp.get_d();

        // randomize g2r
        let mut tmp = pp.get_g2();
        tmp.mul_assign(r);
        self.g2r.add_assign(&tmp);

        // compute tmp = hv[0] * prod_i h[i]^time_vec[i]
        let hlist = pp.get_hlist();
        let timevec = self.get_time_vec(depth);
        let tlen = timevec.get_time_vec_len();
        let tv = timevec.get_time_vec();
        let mut tmp = hlist[0];
        for i in 0..tlen {
            let mut tmp2 = hlist[i + 1];
            tmp2.mul_assign(tv[i]);
            tmp.add_assign(&tmp2);
        }

        // radomize tmp and set hpoly *= tmp^r
        tmp.mul_assign(r);
        self.hpoly.add_assign(&tmp);

        // randmoize hlist
        for i in 0..self.hvector.len() {
            let mut tmp = hlist[tlen + i + 1];
            tmp.mul_assign(r);
            self.hvector[i].add_assign(&tmp);
        }
    }

    /// Delegate the key into TimeStamp time.
    /// This function does NOT handle re-randomizations.
    /// Input `sk = [g, hpoly, h_{|t|+1}, ..., h_D]`,
    /// and a new time `tn`,
    /// output `sk = [g, hpoly*\prod_{i=|t|}^|tn| hi^tn[i], h_{|tn|+1}, ..., h_D]`.
    pub fn delegate(&mut self, time: TimeStamp, depth: usize) -> Result<(), String> {
        let cur_time_vec = TimeVec::init(self.time, depth);
        let tar_time_vec = TimeVec::init(time, depth);

        // check that cur_time_vec is a prefix of tar_time_vec
        if !cur_time_vec.is_prefix(&tar_time_vec) {
            #[cfg(debug_assertions)]
            println!(
                "The current time vector is {:?},\n trying to delegate into {:?}",
                cur_time_vec, tar_time_vec
            );
            return Err("Current time vector is not a prefix of target vector".to_owned());
        }

        let tv = tar_time_vec.get_time_vec();
        let cur_vec_length = cur_time_vec.get_time_vec_len();
        let tar_vec_length = tar_time_vec.get_time_vec_len();

        // hpoly *= h_i ^ t_i
        for i in 0..tar_vec_length - cur_vec_length {
            // if tv[i] == 1
            //  hpoly *= tmp
            // if tv[2] == 2
            //  hpoly *= tmp^2
            let mut tmp = self.hvector[i];
            if tv[i + cur_vec_length] == 2 {
                tmp.double();
            }
            self.hpoly.add_assign(&tmp);
        }

        // remove the first `tar_vec_length - cur_vec_length` elements in h-vector
        for _ in 0..tar_vec_length - cur_vec_length {
            // h_i = 0
            self.hvector.remove(0);
        }
        // update the time to the new time stamp
        self.time = time;
        Ok(())
    }

    /// this function is used to verify if a subsecretkey is valid
    /// for some public key
    /// it is used for testing only
    pub fn validate(&self, pk: &PublicKey, pp: &PubParam) -> bool {
        let pke = pk.get_pk();
        let depth = pp.get_d();
        let list = pp.get_hlist();
        let t = TimeVec::init(self.time, depth);

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
                    &(pke.into_affine().prepare()),
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
                    &(pke.into_affine().prepare()),
                    &(pp.get_h().into_affine().prepare()),
                ),
            ]
            .into_iter(),
        ))
        .unwrap();

        // verification is successful if
        //   e(hpoly, -g2) * e(h, pk) * e(h0*hi^ti, g2r) == 1
        pairingproduct == Fq12::one()
    }
}

impl fmt::Debug for SubSecretKey {
    /// Convenient function to output a `SubSecretKey` object.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Sub Secret key========\n\
             time : {:?}\n\
             g1r: {:#?}\n\
             h0 : {:#?}\n",
            self.time,
            self.g2r.into_affine(),
            self.hpoly.into_affine(),
        )?;
        for i in 0..self.hvector.len() {
            write!(f, "hlist: h{}: {:#?}\n", i, self.hvector[i].into_affine())?;
        }
        write!(f, "================================\n")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use keys::PublicKey;

    impl SubSecretKey {
        /// This initialization function uses (re-)randomization
        /// as a subroutine;
        /// it should generate a same subsecret key as Self::init()
        /// as long as the randomness stays the same
        /// see `test_key_gen()`.
        fn init_from_randomization(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
            // rust needs to know the size of the array at compile time
            // hence we use a const here rather than param.get_d()
            use param::CONST_D;
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
    }

    #[test]
    fn test_key_gen() {
        use ff::PrimeField;

        // a random field element
        let r = Fr::from_str(
            "5902757315117623225217061455046442114914317855835382236847240262163311537283",
        )
        .unwrap();
        let pp = PubParam::init_without_seed();
        // a random master secret key
        let mut alpha = pp.get_h();
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
        for i in 0..pp.get_d() {
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
        let mut pke = pp.get_g2();
        pke.mul_assign(msk);
        let pk = PublicKey::init(&pp, pke).unwrap();

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
        let depth = pp.get_d();
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
        let mut pke = pp.get_g2();
        pke.mul_assign(msk);
        let pk = PublicKey::init(&pp, pke).unwrap();

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
            let res = t.delegate(i, depth);
            assert!(res.is_ok(), "delegation failed");
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
            let res = t.delegate(i, depth);
            assert!(res.is_ok(), "delegation failed");
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
}
