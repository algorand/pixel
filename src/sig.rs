use ff::Field;
use keys::PublicKey;
use keys::SecretKey;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use param::{PubParam, CONST_D};
use time::{TimeStamp, TimeVec};
use util;
use PixelG1;
use PixelG2;

use std::fmt;

/// A signature consists of two elements sigma1 and sigma2,
/// where ...
///
/// * `sigma1 = g^r` in `PixelG2`, and
/// * `sigma2 = ssk.hpoly * hv[d]^m * (h0 * \prod h_i ^ t_i * h_d^m)^r` in `PixelG1`.
///
/// As in the python code, sigma1 and sigma2 are switched -- not consistent with the paper.
pub struct Signature {
    sigma1: PixelG2,
    sigma2: PixelG1,
}

impl Signature {
    /// This function signs a message for a time stamp. It does NOT require the
    /// time stamp to match the secret key. If the time stamp is greater than that
    /// of the secret key, it firstly update the secret key to the new time stamp,
    /// and then use the updated secret key to sign. Note that, for safety reason,
    /// once the key is updated, we no longer have the original secret key.
    pub fn sign(sk: &mut SecretKey, tar_time: TimeStamp, pp: &PubParam, msg: &[u8], r: Fr) -> Self {
        let cur_time = sk.get_time();
        assert!(cur_time > tar_time, "Cannot sign for a previous time");
        if cur_time < tar_time {
            sk.update(&pp, tar_time)
        }
        Signature::gen(&sk, tar_time, &pp, msg, r)
    }

    /// This function generates a signature for a message that is a byte of arbitrary length.
    /// It requires that the tar_time matches timestamp of the secret key
    pub fn gen(sk: &SecretKey, tar_time: TimeStamp, pp: &PubParam, msg: &[u8], r: Fr) -> Self {
        assert_eq!(sk.get_time(), tar_time, "The time stamps does not match!");
        // TODO: use secure ways to hash message into Field
        let m: Vec<Fr> = util::HashToField::hash_to_field(msg, 0, 1, util::HashIDs::Sha256, 2);
        // calls the sign_fr subroutine
        Signature::sign_fr(&sk, tar_time, &pp, m[0], r)
    }

    /// This function generates a signature for a message in the form of a field element.
    /// It requires that the tar_time matches timestamp of the secret key
    pub fn sign_fr(sk: &SecretKey, tar_time: TimeStamp, pp: &PubParam, msg: Fr, r: Fr) -> Self {
        assert_eq!(sk.get_time(), tar_time, "The time stamps does not match!");
        // we only use the first sub secret key to sign
        let ssk = sk.get_first_ssk();
        let hlist = pp.get_hlist();
        let timevec = ssk.get_time_vec();
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
        let mut tmp2 = hlist[CONST_D];
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
    pub fn verify(&self, pk: &PublicKey, tar_time: TimeStamp, pp: &PubParam, msg: &[u8]) -> bool {
        // TODO: membership testing

        // TODO: use secure ways to hash message into Field
        let m: Vec<Fr> = util::HashToField::hash_to_field(msg, 0, 1, util::HashIDs::Sha256, 2);

        Signature::verify_fr(&self, &pk, tar_time, &pp, m[0])
    }

    pub fn verify_fr(&self, pk: &PublicKey, tar_time: TimeStamp, pp: &PubParam, msg: Fr) -> bool {
        // TODO: membership testing

        // extract the group element in pk
        let pke = pk.get_pk();

        // g1^{w[1] * msg}
        let list = pp.get_hlist();
        let mut hfx = list[0];
        let timevec = TimeVec::init(tar_time, CONST_D as u32).into_fr();
        for i in 0..timevec.len() {
            let mut tmp = list[i + 1];
            tmp.mul_assign(timevec[i]);
            hfx.add_assign(&tmp);
        }
        let mut tmp = list[CONST_D];
        tmp.mul_assign(msg);
        hfx.add_assign(&tmp);

        let mut sigma2 = self.sigma2;
        sigma2.negate();
        let sigma1 = self.sigma1;

        #[cfg(feature = "pk_in_g2")]
        // e(1/sigma2, g2) * e( hv^{time_vec}, sigma1) * e(h, pk)
        let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
            [
                (
                    &(sigma2.into_affine().prepare()),
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
                    &(sigma2.into_affine().prepare()),
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
        pairingproduct
            == Fq12 {
                c0: Fq6::one(),
                c1: Fq6::zero(),
            }
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

    use keys::KeyPair;

    use pairing::bls12_381::*;
    use param::PubParam;
    use util;

    #[test]
    fn test_quick_signature_tests() {
        let pp = PubParam::init_without_seed();
        let keypair = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        let sk = keypair.get_sk();
        let pk = keypair.get_pk();
        let r: Vec<Fr> = util::HashToField::hash_to_field(
            b"this is also a very very long seed for testing",
            0,
            1,
            util::HashIDs::Sha256,
            2,
        );

        let msg = b"message to sign";
        let sig = super::Signature::gen(&sk, 1, &pp, msg, r[0]);
        assert!(sig.verify(&pk, 1, &pp, msg), "verification failed");

        for j in 2..16 {
            let mut sk2 = sk.clone();
            sk2.update(&pp, j);
            let sig = super::Signature::gen(&sk2, sk2.get_time(), &pp, msg, r[0]);
            assert!(
                sig.verify(&pk, sk2.get_time(), &pp, msg),
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
        let keypair = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        let sk = keypair.get_sk();
        let pk = keypair.get_pk();
        let r: Vec<Fr> = util::HashToField::hash_to_field(
            b"this is also a very very long seed for testing",
            0,
            1,
            util::HashIDs::Sha256,
            2,
        );

        let msg = b"message to sign";
        let sig = super::Signature::gen(&sk, 1, &pp, msg, r[0]);
        assert!(sig.verify(&pk, 1, &pp, msg), "verification failed");

        // this double loop
        // 1. performs key updates with all possible `start_time` and `finish_time`
        // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
        // 3. check that the signature generated from dedicated keys can be verified
        for j in 2..16 {
            let mut sk2 = sk.clone();
            sk2.update(&pp, j);
            for i in j + 1..16 {
                let mut sk3 = sk2.clone();
                sk3.update(&pp, i);
                println!("{:?}", sk3);
                let sig = super::Signature::gen(&sk3, sk3.get_time(), &pp, msg, r[0]);
                assert!(
                    sig.verify(&pk, sk3.get_time(), &pp, msg),
                    "signature verification failed"
                );
                for ssk in sk3.get_ssk_vec() {
                    assert!(ssk.validate(&pk, &pp), "validation failed");
                }
            }
            for ssk in sk2.get_ssk_vec() {
                assert!(ssk.validate(&pk, &pp), "validation failed");
            }
            let sig = super::Signature::gen(&sk2, sk2.get_time(), &pp, msg, r[0]);
            assert!(
                sig.verify(&pk, sk2.get_time(), &pp, msg),
                "signature verification failed"
            );
        }
    }
}
