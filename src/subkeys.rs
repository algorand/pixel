// a module for sub secret keys and related functions
// to decide: whether this should be packed into key.rs?

use ff::Field;
use keys::PublicKey;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use param::PubParam;
use pixel_err::*;
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
    /// Build a sub secret key from the given inputs. Does not check
    /// if the validity of the key.
    pub fn construct(time: TimeStamp, g2r: PixelG2, hpoly: PixelG1, hvector: Vec<PixelG1>) -> Self {
        SubSecretKey {
            time,
            g2r,
            hpoly,
            hvector,
        }
    }

    /// Returns the time stamp of the sub secret key.
    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    /// Returns the time vector associated with the time stamp.
    /// for the current sub secret key.
    /// Returns an error if the depth or time stamp is invalid.
    pub fn get_time_vec(&self, depth: usize) -> Result<TimeVec, String> {
        TimeVec::init(self.time, depth)
    }

    /// Returns the first element `g^r` in a sub secret key.
    pub fn get_g2r(&self) -> PixelG2 {
        self.g2r
    }

    /// Returns the second element `(h0 \prod h_i^t_i )^r`
    /// in a sub secret key.
    pub fn get_hpoly(&self) -> PixelG1 {
        self.hpoly
    }

    /// Returns the second element `(h0 \prod h_i^t_i )^r`
    /// in a sub secret key.
    pub fn get_hvector(&self) -> Vec<PixelG1> {
        self.hvector.clone()
    }

    /// Returns the last coefficient of the h_vector;
    /// a short cut used by signing algorithm.
    pub fn get_last_hvector_coeff(&self) -> Result<PixelG1, String> {
        if self.hvector.is_empty() {
            return Err(ERR_SSK_EMPTY.to_owned());
        }
        Ok(self.hvector[self.hvector.len() - 1])
    }

    /// This function initializes the root secret key at time stamp = 1,
    /// with input public parameters and a master secret `alpha`.
    //  It produces a same key as init_from_randomization if
    //  same randomness are used. see `test_key_gen()`.
    pub fn init(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
        let mut hlist = pp.get_hlist();
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
        for e in hlist.iter_mut().take(depth + 1).skip(1) {
            e.mul_assign(r);
            hvector.push(*e);
        }
        // format the output
        SubSecretKey {
            // time stamp is 1 since this is the root key
            time: 1,
            g2r,
            hpoly,
            hvector,
        }
    }

    /// Given a subsecrerkey `sk = [g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r]`,
    /// re-randomize it with `r`, and outputs
    /// `g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r`.
    /// An error is returned if the ssk's time stamp is invalid w.r.t the
    /// depth in the public parameter.
    pub fn randomization(&mut self, pp: &PubParam, r: Fr) -> Result<(), String> {
        let depth = pp.get_d();

        // randomize g2r
        let mut tmp = pp.get_g2();
        tmp.mul_assign(r);
        self.g2r.add_assign(&tmp);

        // compute tmp = hv[0] * prod_i h[i]^time_vec[i]
        let hlist = pp.get_hlist();
        let timevec = self.get_time_vec(depth)?;
        let tlen = timevec.get_vector_len();
        let tv = timevec.get_vector();
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
        Ok(())
    }

    /// Delegate the key into TimeStamp time.
    /// This function does NOT handle re-randomizations.
    /// Input `sk = [g, hpoly, h_{|t|+1}, ..., h_D]`,
    /// and a new time `tn`,
    /// output `sk = [g, hpoly*\prod_{i=|t|}^|tn| hi^tn[i], h_{|tn|+1}, ..., h_D]`.
    /// An error is returned if self's time vector is not a prefix of the target time, or
    /// if self's or target time stamp is invalid w.r.t. depth.
    pub fn delegate(&mut self, tar_time: TimeStamp, depth: usize) -> Result<(), String> {
        let cur_time_vec = TimeVec::init(self.time, depth)?;
        let tar_time_vec = TimeVec::init(tar_time, depth)?;

        // check that cur_time_vec is a prefix of tar_time_vec
        if !cur_time_vec.is_prefix(&tar_time_vec) {
            #[cfg(debug_assertions)]
            println!(
                "The current time vector is {:?},\n trying to delegate into {:?}",
                cur_time_vec, tar_time_vec
            );
            return Err(ERR_TIME_NONE_PREFIX.to_owned());
        }

        let tv = tar_time_vec.get_vector();
        let cur_vec_length = cur_time_vec.get_vector_len();
        let tar_vec_length = tar_time_vec.get_vector_len();

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
        self.time = tar_time;
        Ok(())
    }

    /// This function is used to verify if a subsecretkey is valid
    /// for some public key.
    pub fn validate(&self, pk: &PublicKey, pp: &PubParam) -> bool {
        let pke = pk.get_pk();
        let depth = pp.get_d();
        let list = pp.get_hlist();
        let t = match TimeVec::init(self.time, depth) {
            Err(_e) => {
                #[cfg(feature = "verbose")]
                #[cfg(debug_assertions)]
                println!("Error in ssk validation: {}", _e);
                return false;
            }
            Ok(p) => p,
        };

        let timevec = t.get_vector();

        // h2fx = h0 * \prod hi^ti
        let mut h2fx = list[0];
        for i in 0..t.get_vector_len() {
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
            .iter(),
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
            .iter(),
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
            writeln!(f, "hlist: h{}: {:#?}", i, self.hvector[i].into_affine())?;
        }
        writeln!(f, "================================")
    }
}

#[cfg(test)]
impl SubSecretKey {
    /// This initialization function uses (re-)randomization
    /// as a subroutine;
    /// it should generate a same subsecret key as Self::init()
    /// as long as the randomness stays the same
    /// see `test_key_gen()`.
    pub fn init_from_randomization(pp: &PubParam, alpha: PixelG1, r: Fr) -> Result<Self, String> {
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
        s.randomization(pp, r)?;
        Ok(s)
    }
}
