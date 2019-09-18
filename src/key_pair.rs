use bls_sigs_ref_rs::BLSSigCore;
use clear_on_drop::ClearOnDrop;
use domain_sep;
use ff::Field;
use pairing::{bls12_381::Fr, CurveProjective};
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use prng::PRNG;

use crate::{PixelG1, PixelG2, ProofOfPossession, PublicKey, SecretKey, SerDes};

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
        // msk_sec and prng are local variable and will need to be cleared
        let (pk, mut msk_sec, pop, mut prng_sec) = master_key_gen(seed, &pp)?;

        // this may fail if the ciphersuite is not supported
        let pk = PublicKey::init(&pp, pk)?;

        // this may fail if the ciphersuite is not supported
        // it should also erase the msk
        let sk = match SecretKey::init(&pp, msk_sec, prng_sec) {
            Err(e) => {
                // if failed, clear the buffer before exit
                {
                    let _clear2 = ClearOnDrop::new(&mut msk_sec);
                    let _clear2 = ClearOnDrop::new(&mut prng_sec);
                }
                assert_eq!(msk_sec, PixelG1::default(), "msk buffer not cleared");
                assert_eq!(prng_sec, PRNG::default(), "prng buffer not cleared");
                return Err(e);
            }
            Ok(p) => p,
        };

        // clean up the memory
        // makes sure the seed, msk are distroyed
        // so if not, we should panic rather than return errors
        {
            let _clear1 = ClearOnDrop::new(&mut prng_sec);
            let _clear2 = ClearOnDrop::new(&mut msk_sec);
        }

        assert_eq!(
            prng_sec,
            PRNG::default(),
            "seed not cleared after secret key initialization"
        );
        assert_eq!(
            msk_sec,
            PixelG1::default(),
            "msk not cleared after secret key initialization"
        );

        // return the keys and the proof of possession
        Ok((pk, sk, ProofOfPossession::new(pp.ciphersuite(), pop)))
    }
}

/// This function generates the master key pair from a seed.
/// Input a seed,
/// extract the a secret from the seed using the HKDF-SHA512-Extract
///  `m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)`
/// then expand the secret with HKDF-SHA512-Expand
///  `t = HKDF-Expand(m, info, 64)`
/// with info = "key initialization"
/// Use the first 64 bytes as the input to hash_to_field.
/// Use the last 64 bytes as the rngseed.
/// The public/secret key is then set to g2^x and h^x
/// It also generate a proof of possesion which is a BLS signature on g2^x.
/// TODO: change BLS signature to Pixel signature, to remove dependencies on BLS crate.
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
    let ciphersuite = pp.ciphersuite();
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
    //  x = hkdf-expand(prng, info)
    let mut x_sec = prng.sample_then_update(info);

    // pk = g2^x
    // sk = h^x
    let mut pk = pp.g2();
    pk.mul_assign(x_sec);
    let pop = match proof_of_possession(x_sec, pk, pp.ciphersuite()) {
        Err(e) => {
            {
                let _clear1 = ClearOnDrop::new(&mut x_sec);
            }
            assert_eq!(x_sec, Fr::zero(), "Random x is not cleared!");
            return Err(e);
        }
        Ok(p) => p,
    };

    let mut sk = pp.h();
    sk.mul_assign(x_sec);
    // clear temporary data
    {
        let _clear1 = ClearOnDrop::new(&mut x_sec);
    }
    assert_eq!(x_sec, Fr::zero(), "Random x is not cleared!");

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
    let sig = BLSSigCore::core_sign(msk, buf, ciphersuite);
    Ok(sig)
}

/// This function tests if a public key and a master secret key has a same exponent.
/// This function is private, and test only, since by default no one shall have the master secret key.
#[cfg(test)]
fn validate_master_key(pk: &PixelG2, sk: &PixelG1, pp: &PubParam) -> bool {
    use pairing::{bls12_381::*, CurveAffine, Engine};

    let mut g2 = pp.g2();
    g2.negate();
    let h = pp.h();

    // check e(pk, h) ?= e(g2, sk)
    // which is e(pk,h) * e(-g2,sk) == 1
    match Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (&(g2.into_affine().prepare()), &(sk.into_affine().prepare())),
            (&(pk.into_affine().prepare()), &(h.into_affine().prepare())),
        ]
        .iter(),
    )) {
        None => false,
        // verification is successful if
        //   pairingproduct == 1
        Some(pairingproduct) => pairingproduct == Fq12::one(),
    }
}

#[test]
fn test_master_key() {
    let pp = PubParam::init_without_seed();
    let res = master_key_gen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "master key gen failed");
    let (pk, sk, _pop, _seed) = res.unwrap();
    assert!(validate_master_key(&pk, &sk, &pp), "master key is invalid")
}
