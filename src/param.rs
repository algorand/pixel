use pairing::bls12_381::Fr;
use pairing::CurveProjective;
use std::fmt;
use util;
use PixelG1;
use PixelG2;

/// This is a global constant which determines the maximum time
/// stamp, i.e. `max_time_stamp = 2^D-1`.
/// For testing we use a small depth d = 5.
#[cfg(debug_assertions)]
pub const CONST_D: usize = 5;

/// This is a global constant which determines the maximum time
/// stamp, i.e. `max_time_stamp = 2^D-1`.
/// For deployment we use a depth = 32 which should be more than
/// enough in practise.
#[cfg(not(debug_assertions))]
pub const CONST_D: usize = 32;

/// This is a list of PixelG1 elements with arbitrary length,
/// a wrapper of `Vec<PixelG1>`.
pub type Hlist = Vec<PixelG1>;

// /// convenient functions for Hlist.
// pub trait HlistFn
// where
//     Self: std::marker::Sized,
// {
//     /// This fucntion generates a list of d+1 zero elements in PixelG2.
//     fn zero() -> Self;
//
//     /// This fucntion generates a list of d+1 one elements in PixelG2.
//     fn one() -> Self;
// }
// impl HlistFn for Hlist {
//     fn zero() -> Self {
//         [PixelG1::zero(); CONST_D + 1].to_vec()
//     }
//     fn one() -> Self {
//         [PixelG1::one(); CONST_D + 1].to_vec()
//     }
// }

/// public parameter consists of the following:
/// g1, g2: group generators (may be randomized)
/// h: a PixelG2 element,
/// hlist: D+1 PixelG2 elements h_0, h_1, ..., h_d
#[derive(Clone)]
pub struct PubParam {
    g1: PixelG1,
    g2: PixelG2,
    h: PixelG1,   // h
    hlist: Hlist, // h_0, h_1, ..., h_d
}

impl PubParam {
    /// Returns the PixelG1 generator
    pub fn get_g1(&self) -> PixelG1 {
        return self.g1;
    }

    /// Returns the PixelG2 generator
    pub fn get_g2(&self) -> PixelG2 {
        return self.g2;
    }

    /// Returns the h parmeter, i.e., the first PixelG2 element of the public param
    pub fn get_h(&self) -> PixelG1 {
        return self.h;
    }

    /// Returns the list of PixelG2 elements of the public param
    pub fn get_hlist(&self) -> Hlist {
        return self.hlist.clone();
    }

    /// this function initialize the parameter with a default seed = empty string ""
    /// it should not be used except for testing purpose
    #[cfg(test)]
    pub fn init_without_seed() -> Self {
        println!("warning!!!\nthis function should be used for testing purpose only\nuse PubParam::init() instead\n");
        Self::init(b"this is a long and determinstic seed")
    }

    /// this function takes input a string and output the
    /// public parameters as follows
    /// 1. use hash_to_field(msg, ctr) to hash into many field elements by increasing the ctr
    /// 2. get random group element by raise to power of the generator
    /// depending on the configuration `use_rand_generators`
    /// the generators may be generated randomly
    pub fn init(seed: &[u8]) -> Self {
        // make sure we have enough entropy
        assert!(
            seed.len() > 31,
            "the seed length {} is not long enough (required as least 32 bytes)",
            seed.len()
        );

        let mut ctr = 0;

        // if feature = use_rand_generators then we use randomized generators
        #[cfg(feature = "use_rand_generators")]
        let g1 = {
            let mut g1 = PixelG1::one();
            let r: Vec<Fr> =
                util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
            ctr += 1;
            g1.mul_assign(r[0]);
            g1
        };
        #[cfg(feature = "use_rand_generators")]
        let g2 = {
            let mut g2 = PixelG2::one();
            let r: Vec<Fr> =
                util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
            ctr += 1;
            g2.mul_assign(r);
            g2
        };

        // else we set the generators to the default ones from bls12-381 curve
        #[cfg(not(feature = "use_rand_generators"))]
        let g1 = PixelG1::one();
        #[cfg(not(feature = "use_rand_generators"))]
        let g2 = PixelG2::one();

        // hash_to_field(msg, ctr, p, m, hash_fn, hash_reps)
        //  msg         <- seed
        //  ctr         <- incremantal from 0
        //  p           <- group order, implied
        //  m           <- 1; since we are working on F_{r^1}
        //  hash_fn     <- Sha256
        //  hash_reps   <- 2; requires two sha256 runs to get uniform mod p elements
        let r: Vec<Fr> = util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
        ctr += 1;
        let mut h = PixelG1::one();
        h.mul_assign(r[0]);
        let mut hlist: Hlist = [PixelG1::one(); CONST_D + 1].to_vec();
        for i in 0..CONST_D + 1 {
            let r: Vec<Fr> =
                util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
            ctr += 1;
            hlist[i].mul_assign(r[0]);
        }

        // format the output
        PubParam {
            g1: g1,
            g2: g2,
            h: h,
            hlist: hlist,
        }
    }
}

impl fmt::Debug for PubParam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Public Parameter======\n\
             g1 : {:#?}\n\
             g2 : {:#?}\n\
             h  : {:#?}\n",
            self.g1.into_affine(),
            self.g2.into_affine(),
            self.h.into_affine(),
        )?;
        for i in 0..CONST_D + 1 {
            write!(f, "hlist: h{}: {:#?}\n", i, self.hlist[i].into_affine())?;
        }
        write!(f, "================================\n")
    }
}
