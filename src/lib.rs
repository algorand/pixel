extern crate bigint;
extern crate ff;
extern crate pairing;
extern crate sha2;

#[cfg(test)]
extern crate rand;

use pairing::bls12_381::{G1, G2};


pub mod keys;
pub mod param;
pub mod subkeys;
pub mod time;
pub mod util;

/// in the case where public key lies in G1,
/// we need to switch the groups
#[cfg(feature = "pk_in_g2")]
pub type PixelG1 = G1;
#[cfg(feature = "pk_in_g2")]
pub type PixelG2 = G2;

#[cfg(not(feature = "pk_in_g2"))]
pub type PixelG1 = G2;
#[cfg(not(feature = "pk_in_g2"))]
pub type PixelG2 = G1;

#[cfg(test)]
use pairing::CurveProjective;
#[test]
fn test_group_is_correct() {
    let a = PixelG1::one();
    // the following code will generate a compiler error if we are in a wrong group
    #[cfg(not(feature = "pk_in_g2"))]
    assert_eq!(a, G2::one());
    #[cfg(feature = "pk_in_g2")]
    assert_eq!(a, G1::one());
}
