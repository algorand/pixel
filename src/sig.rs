// implements the signature structure, the signing and verification algorithms
use crate::{PixelG1, PixelG2, PublicKey, SecretKey};
use domain_sep::DOM_SEP_SIG;
use ff::Field;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine, SubgroupCheck};
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use prng;
use sha2::Digest;
use std::fmt;
use time::{TimeStamp, TimeVec};
use zeroize::Zeroize;

/// A signature consists of two elements sigma1 and sigma2,
/// where ...
///
/// * `sigma1 = g^r` in `PixelG2`
/// * `sigma2 = ssk.hpoly * hv[d]^m * (h0 * \prod h_i ^ t_i * h_d^m)^r` in `PixelG1`.
/// This follows the python code by having sigma1 in PixelG2 and sigma2 in PixelG1.
/// https://github.com/hoeteck/pixel/blob/2dfc15c6b3bcd47fd2061cccf358ff685b7ed03e/pixel.py#L354.
/// Note that it is the opposite in the paper: sigma1 and sigma2 are switched.
#[derive(Eq, Clone, Default)]
pub struct Signature {
    ciphersuite: u8,
    time: TimeStamp,
    sigma1: PixelG2,
    sigma2: PixelG1,
}

impl Signature {
    /// Constructing a signature object.
    pub fn new(ciphersuite: u8, time: TimeStamp, sigma1: PixelG2, sigma2: PixelG1) -> Self {
        Signature {
            ciphersuite,
            time,
            sigma1,
            sigma2,
        }
    }

    /// Returns the ciphersuite of a signature.
    pub fn ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// Returns the time stamp of a signature.
    pub fn time(&self) -> TimeStamp {
        self.time
    }

    /// Returns the first component of the signature.
    pub fn sigma1(&self) -> PixelG2 {
        self.sigma1
    }

    /// Returns the second component of the signature.
    pub fn sigma2(&self) -> PixelG1 {
        self.sigma2
    }

    /// This function signs a message for a time stamp. It does NOT require the
    /// time stamp to match the secret key.
    /// * If the time stamp is greater than that
    /// of the secret key, it firstly update the secret key to the new time stamp,
    /// and then use the updated secret key to sign. Note that, for safety reason,
    /// once the key is updated, we no longer have the original secret key.
    /// * It returns an error if the time stamp is smaller than the that of the secret key,
    /// or the seed is too short.
    /// The secret key remained unchanged in this case.
    pub fn sign(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        seed: &[u8],
    ) -> Result<Self, String> {
        // update the sk to the target time;
        // if the target time is in future, update self to the future.
        let cur_time = sk.time();

        if cur_time > tar_time {
            #[cfg(debug_assertions)]
            println!(
                "Cannot sign for a previous time stamp, current time {} is greater than target time {}",
                cur_time,
                tar_time,
            );
            return Err(ERR_TIME_STAMP.to_owned());
        }
        if cur_time < tar_time {
            // this is when we update the secret key to target time
            sk.update(&pp, tar_time, seed)?
        }

        Signature::sign_bytes(&sk, tar_time, &pp, msg)
    }

    /// This function signs a message for current time stamp. It requires the
    /// time stamp to match the secret key.
    /// It returns an error if the time stamp is not the same as that of the secret key.
    /// The secret key remained unchanged.
    pub fn sign_present(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Self, String> {
        // update the sk to the target time;
        // if the target time is in future, update self to the future.
        let cur_time = sk.time();

        if cur_time != tar_time {
            #[cfg(debug_assertions)]
            println!(
                "Cannot sign for a non-current time stamp, current time {} is not the same as target time {}",
                cur_time,
                tar_time,
            );
            return Err(ERR_TIME_STAMP.to_owned());
        }

        Signature::sign_bytes(&sk, tar_time, &pp, msg)
    }

    /// This function signs a message for current time stamp. It requires the
    /// time stamp to match the secret key.
    /// It updates the key to time stamp + 1, and uses the seed to re-randomize the key.
    /// It returns an error if the time stamp is not the same as that of the secret key.
    /// The secret key is updated to next time stamp.
    pub fn sign_then_update(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        seed: &[u8],
    ) -> Result<Self, String> {
        // update the sk to the target time;
        // if the target time is in future, update self to the future.
        let cur_time = sk.time();

        if cur_time != tar_time {
            #[cfg(debug_assertions)]
            println!(
                "Cannot sign for a previous time stamp, current time {} is greater than target time {}",
                cur_time,
                tar_time,
            );
            return Err(ERR_TIME_STAMP.to_owned());
        }

        match Signature::sign_bytes(&sk, tar_time, &pp, msg) {
            // if the signing is successful,
            // update the key before returning the signature
            Err(e) => Err(e),
            Ok(p) => {
                sk.update(&pp, tar_time + 1, seed)?;
                Ok(p)
            }
        }
    }

    /// This function generates a signature for a message that is a byte of arbitrary length.
    /// It requires that the tar_time to match timestamp of the secret key.
    pub fn sign_bytes(
        sk: &SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Self, String> {
        // check that the ciphersuite identifier is correct
        let ciphersuite = pp.ciphersuite();
        if !VALID_CIPHERSUITE.contains(&ciphersuite) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if sk.ciphersuite() != ciphersuite {
            #[cfg(debug_assertions)]
            println!(
                "Inconsistant ciphersuite ids. pp: {} sk: {}",
                ciphersuite,
                sk.ciphersuite()
            );
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // makes sure that the time stamp matches.
        // the upper layer has already checked the tar_time is correct
        // so if the tar_time is incorrect, we should panic here instead of
        // recovering from the error
        assert_eq!(sk.time(), tar_time, "The time stamps does not match!");

        let time_tmp = [
            (tar_time >> 24 & 0xFF) as u8,
            (tar_time >> 16 & 0xFF) as u8,
            (tar_time >> 8 & 0xFF) as u8,
            (tar_time & 0xFF) as u8,
        ];

        // We generate a random field element from the prng; the prng is not updated.
        // Within sample():
        //  m = HKDF-Expand(prng_seed, info, 64)
        //  r = OS2IP(m) % p
        let info = [DOM_SEP_SIG.as_bytes(), msg, time_tmp.as_ref()].concat();
        let mut r_sec = sk.prng().sample(info);

        // hash the message into a field element
        let m = hash_msg_into_fr(msg, pp.ciphersuite());
        // calls the sign_fr subroutine
        let sig = Signature::sign_fr(&sk, tar_time, &pp, m, r_sec);

        // clear the secret data
        r_sec.zeroize();

        sig
    }

    /// This function generates a signature for a message in the form of a field element.
    /// It requires that the tar_time matches timestamp of the secret key
    pub fn sign_fr(
        sk: &SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: Fr,
        r: Fr,
    ) -> Result<Self, String> {
        // makes sure that the time stamp matches.
        // the upper layer has already checked the tar_time is correct
        // so if the tar_time is incorrect, we should panic here instead of
        // recovering from the error
        assert_eq!(sk.time(), tar_time, "The time stamps does not match!");
        // we only use the first sub secret key to sign
        // this creates a copy of ssk and therefore needs to be destroyed
        let ssk_sec = sk.first_ssk()?;

        // get all neccessary variables
        let depth = pp.depth();
        let hlist = pp.hlist();
        let timevec = match ssk_sec.time_vec(depth) {
            // clear ssk_sec before returing the error
            Err(e) => return Err(e),

            Ok(p) => p,
        };
        let tlen = timevec.vector_len();
        let tv = timevec.vector();

        // re-randomizing sigma1
        // sig1 = ssk.g2r + g2^r
        // sig1 is returned to the caller, so it does not need to be cleared
        let mut sig1 = ssk_sec.g2r();
        let mut tmp_sec = pp.g2();
        tmp_sec.mul_assign(r);
        sig1.add_assign(&tmp_sec);
        tmp_sec.zeroize();

        // tmp3 = h0 * \prod h_i ^ t_i * h_d^m
        let mut tmp3_sec = hlist[0];
        for i in 0..tlen {
            let mut tmp2 = hlist[i + 1];
            // accecelate this with doubling
            if tv[i] == 2 {
                tmp2.double();
            }
            // tmp2.mul_assign(tv[i]);
            tmp3_sec.add_assign(&tmp2);
        }
        // tmp2 does not handle secret data
        let mut tmp2 = hlist[depth];
        tmp2.mul_assign(msg);
        tmp3_sec.add_assign(&tmp2);

        // re-randomizing sigma2
        // sig2 = ssk.hpoly * hv[d]^m * tmp3^r
        tmp3_sec.mul_assign(r);
        let mut sig2 = ssk_sec.hpoly();
        let mut hv_last_sec = match ssk_sec.last_hvector_coeff() {
            // clear buffer before returing the error
            Err(e) => {
                tmp3_sec.zeroize();
                // ssk will be cleared automatically
                return Err(e);
            }
            Ok(p) => p,
        };
        hv_last_sec.mul_assign(msg);
        sig2.add_assign(&hv_last_sec);
        sig2.add_assign(&tmp3_sec);

        hv_last_sec.zeroize();
        tmp3_sec.zeroize();
        // ssk_vec will be cleared automatically

        Ok(Signature {
            ciphersuite: pp.ciphersuite(),
            time: tar_time,
            sigma1: sig1,
            sigma2: sig2,
        })
    }

    /// This verification function takes in a public key, the public parameters
    /// a message in the form of a byte array, and a signature.
    /// The signature may be malformed -- the elements are not in the right group.
    /// It returns true if the signature is valid.
    pub fn verify_bytes(&self, pk: &PublicKey, pp: &PubParam, msg: &[u8]) -> bool {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.ciphersuite());
            return false;
        }
        // check that the ciphersuite identifier is correct
        if self.ciphersuite != pp.ciphersuite() {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.ciphersuite());
            return false;
        }

        // hash the message into a field element
        let m = hash_msg_into_fr(msg, pp.ciphersuite());

        Signature::verify_fr(&self, &pk, &pp, m)
    }

    /// This verification function takes in a public key, the public parameters
    /// a message in the form of a field element, and a signature.
    /// It assumes that the signature is well formed (in the right subgroup) already.
    /// It returns true if the signature is valid.
    pub fn verify_fr(&self, pk: &PublicKey, pp: &PubParam, msg: Fr) -> bool {
        // membership testing
        let s1_aff = self.sigma1().into_affine();
        let s2_aff = self.sigma2().into_affine();
        if !s1_aff.in_subgroup() || !s2_aff.in_subgroup() {
            #[cfg(debug_assertions)]
            println!(
                "Signature not it the correct subgroup\n\
                 sigma1: {}, sigma2: {}",
                s1_aff.in_subgroup(),
                s2_aff.in_subgroup()
            );
            return false;
        }

        let depth = pp.depth();

        // extract the group element in pk
        let pke = pk.pk();

        // extract the target time
        let tar_time = self.time();

        // hfx = h0 + h_i * t_i + h_d * m
        let list = pp.hlist();
        let mut hfx = list[0];
        let timevec = match TimeVec::init(tar_time, depth) {
            Err(_e) => {
                #[cfg(debug_assertions)]
                println!("Error in verification: {}", _e);
                return false;
            }
            Ok(p) => p,
        }
        .vector();

        // if timevec[i] == 1 -> hfx += list[i+1]
        // if timevec[i] == 2 -> hfx += list[i+1]*2
        for i in 0..timevec.len() {
            let mut tmp = list[i + 1];
            if timevec[i] == 2 {
                tmp.double();
            }
            hfx.add_assign(&tmp);
        }
        // the last coefficient is multiplied by the message
        let mut tmp = list[depth];
        tmp.mul_assign(msg);
        hfx.add_assign(&tmp);

        // to use simultaneous pairing, we compute
        //  e(1/g2, sigma2) * e(sigma1, hv^{time_vec}) * e(pk, h)
        // we negate g2 rather than sigma2, since it is slightly faster
        // to compute the nagete in PixelG2 (a.k.a. BLS G1)
        let mut neg_g2 = pp.g2();
        neg_g2.negate();

        match Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (&(neg_g2.into_affine().prepare()), &(s2_aff.prepare())),
                (&(s1_aff.prepare()), &(hfx.into_affine().prepare())),
                (
                    &(pke.into_affine().prepare()),
                    &(pp.h().into_affine().prepare()),
                ),
            ]
            .iter(),
        )) {
            None => false,
            // signature is valid if
            // e(1/g2, sigma2) * e(sigma1, hv^{time_vec}) * e(pk, h) = 1
            Some(pairingproduct) => pairingproduct == Fq12::one(),
        }
    }

    /// This function aggregates the signatures without checking if a signature is valid or not.
    /// It does check that all the signatures are for the same time stamp.
    /// It returns an error if ciphersuite fails or time stamp is not consistent.
    pub fn aggregate_without_validate(sig_list: &[Self]) -> Result<Self, String> {
        let mut res = sig_list[0].clone();
        // check the time and the ciphersuite match
        for e in sig_list.iter().skip(1) {
            if res.ciphersuite() != e.ciphersuite() {
                #[cfg(debug_assertions)]
                println!("ciphersuite do not match");
                return Err(ERR_CIPHERSUITE.to_owned());
            }
            if res.time() != e.time() {
                #[cfg(debug_assertions)]
                println!("ciphersuite do not match");
                return Err(ERR_TIME_STAMP.to_owned());
            }
        }

        // aggregating the signatures
        for e in sig_list.iter().skip(1) {
            res.sigma1.add_assign(&e.sigma1);
            res.sigma2.add_assign(&e.sigma2);
        }
        Ok(res)
    }

    /// Input an aggregated signature, a list of public keys, a public parameter, and a
    /// message, output true if the signatures verifies.
    /// Signatures verified through this way may be vulnerable to rogue key attacks,
    /// unless a proof of possession of the public key is presented -- this should be
    /// handled by the upper layer.
    pub fn verify_bytes_aggregated(
        &self,
        pk_list: &[PublicKey],
        pp: &PubParam,
        msg: &[u8],
    ) -> bool {
        // checks the ciphersuite ids match
        let ciphersuite = pp.ciphersuite();
        for e in pk_list {
            if ciphersuite != e.ciphersuite() {
                #[cfg(debug_assertions)]
                println!("ciphersuite do not match");
                return false;
            }
        }
        if self.ciphersuite() != ciphersuite {
            #[cfg(debug_assertions)]
            println!("ciphersuite do not match");
            return false;
        }

        let mut agg_pke = pk_list[0].pk();
        for e in pk_list.iter().skip(1) {
            agg_pke.add_assign(&e.pk());
        }
        let pk = PublicKey::new(ciphersuite, agg_pke);
        Signature::verify_bytes(&self, &pk, &pp, msg)
    }
}

/// This function hashes a message into a field element
/// by returning sha512(DOM_SEP_HASH_TO_MSG | ciphersuite | msg) % p
fn hash_msg_into_fr(msg: &[u8], ciphersuite: u8) -> Fr {
    use domain_sep::DOM_SEP_HASH_TO_MSG;
    // output sha512(DOM_SEP_HASH_TO_MSG | ciphersuite | msg) % p
    //  DOM_SEP_HASH_TO_MSG:    domain seperator
    //  msg:                    input message
    let m = [DOM_SEP_HASH_TO_MSG.as_bytes(), [ciphersuite].as_ref(), msg].concat();
    let mut hasher = sha2::Sha512::new();
    hasher.input(m);
    // obtain the output
    let hashresult = hasher.result();
    prng::os2ip_mod_p(&hashresult)
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Signature======\n\
             sigma1  : {:#?}\n\
             sigma2  : {:#?}\n",
            self.sigma1.into_affine(),
            self.sigma2.into_affine(),
        )?;
        writeln!(f, "================================")
    }
}

/// convenient function to compare secret key objects
impl std::cmp::PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sigma1 == other.sigma1 && self.sigma2 == other.sigma2
    }
}
