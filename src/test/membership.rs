use membership::MembershipTesting;
use pairing::{bls12_381::*, CurveProjective};

// It would be nice to have some more curve points that are not in G1/G2 for testing...
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
    //
    // // a curve point on invalid subgroup
    // let data = hex!(
    //     "b8 d2 c4 1d 7a e7 d3 53 9d 81 52 82 85 28 50
    // 60 5c a3 cc 01 d6 93 9b 0e 2a 13 2b d0 3a 5a af
    // cb d7 92 b5 e1 85 b4 be 72 e9 ad d9 e5 77 c1 76
    // 6a");
    // PixelG1::deserialize(data)
}
