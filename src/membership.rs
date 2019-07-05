use ff::PrimeField;
use pairing::{bls12_381::*, CurveProjective};

/// This trait performs membership testing for curve elements.
/// It checks if a curve element is in the right subgroup, i.e., the largest prime
/// subgroup.
pub trait MembershipTesting {
    /// Input a projective or affine curve point, check if it is in the
    /// correct group, a.k.a, the largest prime subgroup.
    fn is_in_prime_group(&self) -> bool;
}

impl MembershipTesting for G1 {
    fn is_in_prime_group(&self) -> bool {
        let mut g = *self;
        // check if g^r == 0
        let grouporder = Fr::char();
        g.mul_assign(grouporder);
        g == G1::zero()
    }
}

impl MembershipTesting for G2 {
    fn is_in_prime_group(&self) -> bool {
        let mut g = *self;
        // check if g^r == 0
        let grouporder = Fr::char();
        g.mul_assign(grouporder);
        g == G2::zero()
    }
}
