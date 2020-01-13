use crate::prng::PRNG;
use crate::ProofOfPossession;
use crate::{PixelG1, PixelG2};
use crate::{PubParam, PublicKey, Signature};
use key_pair::KeyPair;
use pairing::CurveProjective;
use PK_LEN;
#[test]
fn test_pop_getter() {
    let pop = ProofOfPossession::new(0, PixelG1::one());
    assert_eq!(pop.ciphersuite(), 0);
    assert_eq!(pop.pop(), PixelG1::one());
}

#[test]
fn test_prng_getter() {
    let prng = PRNG::default();
    assert_eq!(prng.seed().to_vec(), vec![0u8; 64]);
}

#[test]
fn test_pk_getter() {
    let pk = PublicKey::new(1, PixelG2::one());
    assert_eq!(pk.size(), PK_LEN);
    assert_eq!(pk.ciphersuite(), 1);
    assert_eq!(pk.pk(), PixelG2::one());
}

#[test]
fn test_sk_getter() {
    let pp = PubParam::default();
    let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);

    let (_pk, sk, _pop) = res.unwrap();
    assert_eq!(sk.ciphersuite(), 0);
    assert_eq!(sk.time(), 1);
    assert!(sk.digest().is_ok());
}

#[test]
fn test_sig_getter() {
    let sig = Signature::new(0, 1, PixelG2::one(), PixelG1::one());
    assert_eq!(sig.ciphersuite(), 0);
    assert_eq!(sig.time(), 1);
    assert_eq!(sig.sigma1(), PixelG2::one());
    assert_eq!(sig.sigma2(), PixelG1::one());
}
