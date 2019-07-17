use crate::ProofOfPossession;
use bls_sigs_ref_rs::{BLSSignature, FromRO};
use clear_on_drop::ClearOnDrop;
use domain_sep;
use ff::Field;
use pairing::{bls12_381::Fr, CurveProjective};
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use prng::PRNG;
use public_key::PublicKey;
use secret_key::SecretKey;
use serdes::SerDes;
use sha2::Digest;
use std::fmt;
pub use subkeys::SubSecretKey;
use time::{TimeStamp, TimeVec};
use PixelG1;
use PixelG2;

/// The keypair is  a pair of public and secret keys,
/// and a proof of possesion of the public key.
#[derive(Debug, Clone, Default)]
pub struct KeyPair;

impl KeyPair {
    /// Generate a pair of public keys and secret keys,
    /// and a proof of possession of the public key.
    /// This function does NOT return the master secret
    /// therefore this is the only method that generates POP.
    /// This function does NOT destroy the seed.
    /// Returns an error if
    /// * the seed is not long enough
    /// * the ciphersuite is not supported
    pub fn keygen(
        seed: &[u8],
        pp: &PubParam,
    ) -> Result<(PublicKey, SecretKey, ProofOfPossession), String> {
        // update then extract the seed
        // make sure we have enough entropy
        let seed_len = seed.len();
        if seed_len < 32 {
            #[cfg(debug_assertions)]
            println!(
                "the seed length {} is not long enough (required as least 32 bytes)",
                seed_len
            );
            return Err(ERR_SEED_TOO_SHORT.to_owned());
        }

        // this may fail if the seed is too short or
        // the ciphersuite is not supported

        // inside master_key_gen:
        // extract the a secret from the seed using the HKDF-SHA512-Extract
        //  m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)
        // then expand the secret with HKDF-SHA512-Expand
        //  t = HKDF-Expand(m, info, 128)
        // with info = "key initialization"
        // use the first 64 bytes as the input to hash_to_field
        // use the last 64 bytes as the prngseed
        // msk_sec is a local variable and will need to be cleared
        let (pk, mut msk_sec, pop, mut prng) = master_key_gen(seed, &pp)?;

        // this may fail if the ciphersuite is not supported
        // it should also erase the msk
        let sk_sec = SecretKey::init(&pp, msk_sec, prng)?;
        // makes sure the seed and msk are distroyed
        // the seed shold always be cleared
        // so if not, we should panic rather than return errors
        assert_eq!(
            prng,
            PRNG::default(),
            "seed not cleared after secret key initialization"
        );
        {
            let _clear = ClearOnDrop::new(&mut msk_sec);
        }
        assert_eq!(
            msk_sec,
            PixelG1::default(),
            "msk not cleared after secret key initialization"
        );

        // this may fail if the ciphersuite is not supported
        let pk = PublicKey::init(&pp, pk)?;

        // return the keys and the proof of possession
        Ok((
            pk,
            // momery for sec_sk is not cleared -- it is passed to the called
            sk_sec,
            ProofOfPossession::construct(pp.get_ciphersuite(), pop),
        ))
    }
}

/// This function generates the master key pair from a seed.
/// Input a seed,
/// extract the a secret from the seed using the HKDF-SHA512-Extract
///  `m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)`
/// then expand the secret with HKDF-SHA512-Expand
///  `t = HKDF-Expand(m, info, 64)`
/// with info = "key initialization"
/// Use the first 32 bytes as the input to hash_to_field.
/// Use the last 32 bytes as the rngseed.
/// The public/secret key is then set to g2^x and h^x
/// It also generate a proof of possesion which is a BLS signature on g2^x.
/// This function is private -- it should be used only as a subroutine to key gen function
fn master_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PixelG2, PixelG1, PixelG1, PRNG), String> {
    // make sure we have enough entropy
    if seed.len() < 32 {
        #[cfg(debug_assertions)]
        println!(
            "the seed length {} is not long enough (required as least 32 bytes)",
            seed.len()
        );
        return Err(ERR_SEED_TOO_SHORT.to_owned());
    }

    // check that the ciphersuite identifier is correct
    let ciphersuite = pp.get_ciphersuite();
    if !VALID_CIPHERSUITE.contains(&ciphersuite) {
        #[cfg(debug_assertions)]
        println!("Incorrect ciphersuite id: {}", ciphersuite);
        return Err(ERR_CIPHERSUITE.to_owned());
    }

    // Instantiate the prng with the seed and a salt
    //  salt = DOM_SEP_MASTER_KEY | ciphersuite
    let salt = [
        domain_sep::DOM_SEP_MASTER_KEY.as_ref(),
        [ciphersuite].as_ref(),
    ]
    .concat();
    // prng is passed to the caller - so we do not clear it.
    let mut prng = PRNG::init(seed, &salt);

    // get a field element
    let info = b"key initialization";
    // this is a local secret - need to clear after use
    //  x = hkdf-expand(prng, info, ctr)
    //  ctr is set to 0
    let mut x_sec = prng.sample_then_update(info, 0);

    // pk = g2^x
    // sk = h^x
    let mut pk = pp.get_g2();
    let mut sk = pp.get_h();
    pk.mul_assign(x_sec);
    sk.mul_assign(x_sec);
    let pop = proof_of_possession(x_sec, pk, pp.get_ciphersuite())?;

    // clear temporary data
    {
        let _clear1 = ClearOnDrop::new(&mut x_sec);
    }
    assert_eq!(x_sec, Fr::zero(), "Random r is not cleared!");

    Ok((pk, sk, pop, prng))
}

/// This function generate a proof of possesion of the master secret.
/// This function is a subroutine of the key generation function, and
/// should not be called anywhere else -- the master secret key is
/// destroyed after key generation.
fn proof_of_possession(msk: Fr, pk: PixelG2, ciphersuite: u8) -> Result<PixelG1, String> {
    // buf = DOM_SEP_POP | serial (PK)
    let mut buf = domain_sep::DOM_SEP_POP.as_bytes().to_vec();
    if pk.serialize(&mut buf, true).is_err() {
        return Err(ERR_SERIAL.to_owned());
    };
    // the pop is a signature on the buf
    let sig = BLSSignature::sign(msk, buf, ciphersuite);
    Ok(sig)
}

/// This function tests if a public key and a master secret key has a same exponent.
/// This function is private, and test only, since by default no one shall have the master secret key.
#[cfg(test)]
fn validate_master_key(pk: &PixelG2, sk: &PixelG1, pp: &PubParam) -> bool {
    use pairing::{bls12_381::*, CurveAffine, Engine};

    let mut g2 = pp.get_g2();
    g2.negate();
    let h = pp.get_h();

    // check e(pk, h) ?= e(g2, sk)
    // which is e(pk,h) * e(-g2,sk) == 1
    #[cfg(feature = "pk_in_g2")]
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (&(sk.into_affine().prepare()), &(g2.into_affine().prepare())),
            (&(h.into_affine().prepare()), &(pk.into_affine().prepare())),
        ]
        .iter(),
    ))
    .unwrap();
    #[cfg(not(feature = "pk_in_g2"))]
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (&(g2.into_affine().prepare()), &(sk.into_affine().prepare())),
            (&(pk.into_affine().prepare()), &(h.into_affine().prepare())),
        ]
        .iter(),
    ))
    .unwrap();

    // verification is successful if
    //   pairingproduct == 1
    pairingproduct == Fq12::one()
}

#[test]
fn test_master_key() {
    let pp = PubParam::init_without_seed();
    let res = master_key_gen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "master key gen failed");
    let (pk, sk, _pop, _seed) = res.unwrap();
    assert!(validate_master_key(&pk, &sk, &pp), "master key is invalid")
}
