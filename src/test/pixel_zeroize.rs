use crate::{prng::PRNG, PixelG1, PixelG2, SecretKey, SubSecretKey};
use pairing::CurveProjective;

#[test]
fn test_zeroize() {
    let tmp_prng = PRNG::new([1; 64]);
    let tmp_ssk = SubSecretKey::new(1, PixelG2::one(), PixelG1::one(), vec![PixelG1::one(); 2]);
    let tmp_sk = SecretKey::new(0, 1, vec![tmp_ssk.clone()], tmp_prng.clone());

    let t = foo_prng(tmp_prng);
    unsafe {
        assert_eq!(*t, PRNG::default());
    }

    let t = foo_ssk(tmp_ssk);
    unsafe {
        assert_eq!(*t, SubSecretKey::default());
    }

    let t = foo_sk(tmp_sk);
    unsafe {
        assert_eq!(*t, SecretKey::default());
    }
}

#[cfg(test)]
fn foo_prng(prng: PRNG) -> *const PRNG {
    &prng as *const PRNG
}

#[cfg(test)]
fn foo_ssk(ssk: SubSecretKey) -> *const SubSecretKey {
    &ssk as *const SubSecretKey
}

#[cfg(test)]
fn foo_sk(sk: SecretKey) -> *const SecretKey {
    &sk as *const SecretKey
}
