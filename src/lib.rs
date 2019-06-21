extern crate bigint;
extern crate ff;
extern crate pairing;
extern crate sha2;

#[cfg(test)]
extern crate rand;

pub mod keys;
pub mod param;
pub mod sig;
// TODO: decide if we allow external access to subkeys?
pub mod subkeys;
pub mod time;
pub mod util;

// by default the groups are switched so that
// the public key lies in G2
// this yields smaller public keys
// in the case where public key lies in G1,
// we need to unswitch the groups
// to enable this feature, set `features=pk_in_g2` flag

//  additional comments for cargo doc
/// The pixel G1 group is mapped to G1 over BLS12-381 curve.
/// Note that `features=pk_in_g2` flag is set.
#[cfg(feature = "pk_in_g2")]
pub type PixelG1 = pairing::bls12_381::G1;
//  additional comments for cargo doc
/// The pixel G2 group is mapped to G2 over BLS12-381 curve.
/// Note that `features=pk_in_g2` flag is set.
#[cfg(feature = "pk_in_g2")]
pub type PixelG2 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G2.
/// This means pixel G1 group is mapped to G2 over BLS12-381 curve.
#[cfg(not(feature = "pk_in_g2"))]
pub type PixelG1 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G2.
/// This means pixel G2 group is mapped to G1 over BLS12-381 curve.
#[cfg(not(feature = "pk_in_g2"))]
pub type PixelG2 = pairing::bls12_381::G1;

#[test]
// a simple test to ensure that we have pixel groups mapped to the
// right groups over the BLS12-381 curve
// the code will generate a compiler error if we are in a wrong group
fn test_group_is_correct() {
    use pairing::CurveProjective;
    let a = PixelG1::one();
    #[cfg(not(feature = "pk_in_g2"))]
    assert_eq!(a, pairing::bls12_381::G2::one());
    #[cfg(feature = "pk_in_g2")]
    assert_eq!(a, pairing::bls12_381::G1::one());
}
