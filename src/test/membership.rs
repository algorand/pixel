use membership::MembershipTesting;
use pairing::{bls12_381::*, CurveProjective};

// It would be nice to have some curve point that are not in G1/G2 for testing...
#[test]
fn test_membership_testing() {
    use super::rand::{Rand, SeedableRng, XorShiftRng};
    let mut rng = XorShiftRng::from_seed([1, 2, 3, 4]);

    // generator
    let g1 = G1::one();
    assert_eq!(g1.is_in_prime_group(), true, "fail! not in group");
    // random element
    for _i in 0..100 {
        let g1 = G1::rand(&mut rng);
        assert_eq!(g1.is_in_prime_group(), true, "fail! not in group");
    }

    // generator
    let g2 = G2::one();
    assert_eq!(g2.is_in_prime_group(), true, "fail! not in group");
    // random element
    for _i in 0..100 {
        let g2 = G2::rand(&mut rng);
        assert_eq!(g2.is_in_prime_group(), true, "fail! not in group");
    }
}
