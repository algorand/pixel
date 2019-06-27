// implements the signature structure, the signing and verification algorithms
use bls_sigs_ref_rs::FromRO;
use ff::Field;
use keys::{PublicKey, SecretKey};
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use param::PubParam;
use std::fmt;
use time::{TimeStamp, TimeVec};
use PixelG1;
use PixelG2;

/// A signature consists of two elements sigma1 and sigma2,
/// where ...
///
/// * `sigma1 = g^r` in `PixelG2`, and
/// * `sigma2 = ssk.hpoly * hv[d]^m * (h0 * \prod h_i ^ t_i * h_d^m)^r` in `PixelG1`.
///
/// As in the python code, sigma1 and sigma2 are switched --  not consistent with the paper.
pub struct Signature {
    sigma1: PixelG2,
    sigma2: PixelG1,
}

impl Signature {
    /// This function signs a message for a time stamp. It does NOT require the
    /// time stamp to match the secret key.
    /// * If the time stamp is greater than that
    /// of the secret key, it firstly update the secret key to the new time stamp,
    /// and then use the updated secret key to sign. Note that, for safety reason,
    /// once the key is updated, we no longer have the original secret key.
    /// * It returns an error if the time stamp is smaller than the that of the secret key.
    /// The secret key remained unchanged in this case.
    pub fn sign(
        sk: &mut SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> Result<Self, String> {
        // TODO: to decide the right way to generate this randomness
        let r = Fr::from_ro("seed used for signing", 0);

        // update the sk to the target time;
        // if the target time is in future, update self to the future.
        let cur_time = sk.get_time();

        #[cfg(debug_assertions)]
        assert!(
            cur_time <= tar_time,
            "Cannot sign for a previous time stamp, current time {} is greater than target time {}",
            cur_time,
            tar_time,
        );
        if cur_time > tar_time {
            return Err("Cannot sign for a previous time stamp!".to_owned());
        }
        if cur_time < tar_time {
            // this is when we update the secret key to target time
            let () = match sk.update(&pp, tar_time) {
                Err(e) => return Err(e),
                Ok(()) => (),
            };
        }

        Ok(Signature::sign_bytes(&sk, tar_time, &pp, msg, r))
    }

    /// This function generates a signature for a message that is a byte of arbitrary length.
    /// It requires that the tar_time to match timestamp of the secret key.
    pub fn sign_bytes(
        sk: &SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        r: Fr,
    ) -> Self {
        // makes sure that the time stamp matches.
        // the upper layer has already checked the tar_time is correct
        // so if the tar_time is incorrect, we should panic here instead of
        // recovering from the error
        assert_eq!(sk.get_time(), tar_time, "The time stamps does not match!");

        // hash the message into a field element
        // TODO: domain seperation?
        let m = Fr::from_ro(msg, 0);
        // calls the sign_fr subroutine
        Signature::sign_fr(&sk, tar_time, &pp, m, r)
    }

    /// This function generates a signature for a message in the form of a field element.
    /// It requires that the tar_time matches timestamp of the secret key
    pub fn sign_fr(sk: &SecretKey, tar_time: TimeStamp, pp: &PubParam, msg: Fr, r: Fr) -> Self {
        // makes sure that the time stamp matches.
        // the upper layer has already checked the tar_time is correct
        // so if the tar_time is incorrect, we should panic here instead of
        // recovering from the error
        assert_eq!(sk.get_time(), tar_time, "The time stamps does not match!");
        // we only use the first sub secret key to sign
        let ssk = sk.get_first_ssk();

        // get all neccessary variables
        let depth = pp.get_d();
        let hlist = pp.get_hlist();
        let timevec = ssk.get_time_vec(depth);
        let tlen = timevec.get_time_vec_len();
        let tv = timevec.get_time_vec();

        // re-randomizing sigma1
        // sig1 = ssk.g2r + g2^r
        let mut sig1 = ssk.get_g2r();
        let mut tmp = pp.get_g2();
        tmp.mul_assign(r);
        sig1.add_assign(&tmp);

        // tmp = h0 * \prod h_i ^ t_i * h_d^m
        let mut tmp = hlist[0];
        for i in 0..tlen {
            let mut tmp2 = hlist[i + 1];
            tmp2.mul_assign(tv[i]);
            tmp.add_assign(&tmp2);
        }
        let mut tmp2 = hlist[depth];
        tmp2.mul_assign(msg);
        tmp.add_assign(&tmp2);
        // re-randomizing sigma2
        // sig2 = ssk.hpoly * hv[d]^m * tmp^r
        tmp.mul_assign(r);
        let mut sig2 = ssk.get_hpoly();
        let mut hv_last = ssk.get_last_hvector_coeff();
        hv_last.mul_assign(msg);
        sig2.add_assign(&hv_last);
        sig2.add_assign(&tmp);

        Signature {
            sigma1: sig1,
            sigma2: sig2,
        }
    }

    /// This verification function takes in a public key, a target time, the public parameters
    /// and a message in the form of a byte array. It returns true if the signature is valide.
    pub fn verify_bytes(
        &self,
        pk: &PublicKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
    ) -> bool {
        // TODO: membership testing

        // hash the message into a field element
        // TODO: domain seperation?
        let m = Fr::from_ro(msg, 0);

        Signature::verify_fr(&self, &pk, tar_time, &pp, m)
    }

    /// This verification function takes in a public key, a target time, the public parameters
    /// and a message in the form of a field element. It returns true if the signature is valide.
    pub fn verify_fr(&self, pk: &PublicKey, tar_time: TimeStamp, pp: &PubParam, msg: Fr) -> bool {
        // TODO: membership testing

        let depth = pp.get_d();

        // extract the group element in pk
        let pke = pk.get_pk();

        // hfx = h0 + h_i * t_i + h_d * m
        let list = pp.get_hlist();
        let mut hfx = list[0];
        let timevec = TimeVec::init(tar_time, depth).get_time_vec();

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

        // negate sigma2 so that we can use sim-pairing
        let mut neg_sigma2 = self.sigma2;
        neg_sigma2.negate();
        let sigma1 = self.sigma1;

        #[cfg(feature = "pk_in_g2")]
        // e(1/sigma2, g2) * e( hv^{time_vec}, sigma1) * e(h, pk)
        let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (
                    &(neg_sigma2.into_affine().prepare()),
                    &(pp.get_g2().into_affine().prepare()),
                ),
                (
                    &(hfx.into_affine().prepare()),
                    &(sigma1.into_affine().prepare()),
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
        // e(g2, 1/sigma2) * e( sigma1, hv^{time_vec}) * e(pk, h)
        let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (
                    &(pp.get_g2().into_affine().prepare()),
                    &(neg_sigma2.into_affine().prepare()),
                ),
                (
                    &(sigma1.into_affine().prepare()),
                    &(hfx.into_affine().prepare()),
                ),
                (
                    &(pke.into_affine().prepare()),
                    &(pp.get_h().into_affine().prepare()),
                ),
            ]
            .into_iter(),
        ))
        .unwrap();
        pairingproduct == Fq12::one()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Signature======\n\
             sigma1  : {:#?}\n\
             sigma2  : {:#?}\n",
            //            self.g1.into_affine(),
            self.sigma1.into_affine(),
            self.sigma2.into_affine(),
        )?;

        write!(f, "================================\n")
    }
}

#[cfg(test)]
mod signature_test {

    use bls_sigs_ref_rs::FromRO;
    use keys::KeyPair;
    use pairing::bls12_381::Fr;
    use param::PubParam;
    //    use util;

    /// A simple and quick tests on
    /// * key generation
    /// * key update
    /// * sign
    /// * verification
    #[test]
    fn test_quick_signature_tests() {
        let pp = PubParam::init_without_seed();
        let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        assert!(res.is_ok(), "key gen failed");
        let keypair = res.unwrap();
        let sk = keypair.get_sk();
        let pk = keypair.get_pk();
        let r = Fr::from_ro("this is also a very very long seed for testing", 0);

        let msg = b"message to sign";
        let sig = super::Signature::sign_bytes(&sk, 1, &pp, msg, r);
        assert!(sig.verify_bytes(&pk, 1, &pp, msg), "verification failed");

        for j in 2..16 {
            let mut sk2 = sk.clone();
            let res = sk2.update(&pp, j);
            assert!(res.is_ok(), "updating failed");
            let r = Fr::from_ro("this is also a very very long seed for testing", j as u8);
            let sig = super::Signature::sign_bytes(&sk2, sk2.get_time(), &pp, msg, r);
            assert!(
                sig.verify_bytes(&pk, sk2.get_time(), &pp, msg),
                "signature verification failed"
            );
        }
    }

    /// this test takes quite some time to finish
    /// enable this test with `cargo test -- --ignored`
    #[ignore]
    #[test]
    fn test_long_signature_tests() {
        let pp = PubParam::init_without_seed();
        let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        assert!(res.is_ok(), "key gen failed");
        let keypair = res.unwrap();
        let sk = keypair.get_sk();
        let pk = keypair.get_pk();
        let r = Fr::from_ro("this is also a very very long seed for testing", 0);

        let msg = b"message to sign";
        let sig = super::Signature::sign_bytes(&sk, 1, &pp, msg, r);
        assert!(sig.verify_bytes(&pk, 1, &pp, msg), "verification failed");

        // this double loop
        // 1. performs key updates with all possible `start_time` and `finish_time`
        // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
        // 3. check that the signature generated from dedicated keys can be verified
        for j in 2..16 {
            let mut sk2 = sk.clone();
            let res = sk2.update(&pp, j);
            assert!(res.is_ok(), "updating failed");
            assert!(sk2.validate(&pk, &pp), "validation failed");

            for i in j + 1..16 {
                let mut sk3 = sk2.clone();
                let res = sk3.update(&pp, i);
                assert!(res.is_ok(), "updating failed");
                assert!(sk3.validate(&pk, &pp), "validation failed");
                let r = Fr::from_ro(
                    "this is also a very very long seed for testing",
                    (i * 16 + j) as u8,
                );

                let sig = super::Signature::sign_bytes(&sk3, sk3.get_time(), &pp, msg, r);
                assert!(
                    sig.verify_bytes(&pk, sk3.get_time(), &pp, msg),
                    "signature verification failed"
                );
            }

            let r = Fr::from_ro("this is also a very very long seed for testing", 255);

            let sig = super::Signature::sign_bytes(&sk2, sk2.get_time(), &pp, msg, r);
            assert!(
                sig.verify_bytes(&pk, sk2.get_time(), &pp, msg),
                "signature verification failed"
            );
        }
    }
}
