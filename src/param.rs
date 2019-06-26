// this file defines the structures for the public parameter
// and its associated methods

use pairing::{bls12_381::Fr, CurveProjective};
use std::fmt;
use util;
use PixelG1;
use PixelG2;

// todo: decide if the depth

/// This is a global constant which determines the maximum time
/// stamp, i.e. `max_time_stamp = 2^D-1`.
/// For testing we use a small depth d = 5.
#[cfg(debug_assertions)]
pub const CONST_D: usize = 4;

/// This is a global constant which determines the maximum time
/// stamp, i.e. `max_time_stamp = 2^D-1`.
/// For deployment we use a depth = 32 which should be more than
/// enough in practise.
#[cfg(not(debug_assertions))]
pub const CONST_D: usize = 32;

/// This is a fixed lenght array of PixelG1 elements,
/// a wrapper of `[PixelG1; CONST_D + 1]`.
pub type Hlist = [PixelG1; CONST_D + 1];

/// The public parameter consists of the following ...
/// * g2: group generators for `PixelG2` group (may be randomized)
/// * h: a `PixelG2` element,
/// * hlist: D+1 PixelG2 elements `h_0, h_1, ..., h_d`
///
/// This struct is read-only once initlized.
/// By default all fields are private. Use correspoding
/// functions to access specific field.
#[derive(Clone)]
pub struct PubParam {
    d: usize, // the depth of the time vector
    g2: PixelG2,
    h: PixelG1,   // h
    hlist: Hlist, // h_0, h_1, ..., h_d
}

impl PubParam {
    //  we no longer require a generator on g1
    // Returns the PixelG1 generator
    // pub fn get_g1(&self) -> PixelG1 {
    //     return self.g1;
    // }

    /// Returns the depth of the time stamp.
    pub fn get_d(&self) -> usize {
        self.d
    }

    /// Returns the `PixelG2` generator. Note: the generator will be different
    /// from `bls12-381` curve's if randomized generator is used.
    pub fn get_g2(&self) -> PixelG2 {
        self.g2
    }

    /// Returns the `h` parmeter, i.e., the first `PixelG2` element of the public param.
    pub fn get_h(&self) -> PixelG1 {
        self.h
    }

    /// Returns the list of `PixelG2` elements of the public param.
    pub fn get_hlist(&self) -> Hlist {
        self.hlist.clone()
    }

    /// This function initialize the parameter with a default seed = empty string "".
    /// It should not be used except for testing purpose
    #[cfg(test)]
    pub fn init_without_seed() -> Self {
        println!("warning!!!\nthis function should be used for testing purpose only\nuse PubParam::init() instead\n");
        Self::init(b"this is a long and determinstic seed").unwrap()
    }

    /// This function takes input a string and outputs the
    /// public parameters as follows
    /// 1. use `hash_to_field(msg, ctr)` to hash into many field elements by increasing the `ctr`
    /// 2. get random group element by raise to power of the generator
    ///
    /// TODO: use `hash_to_group` functions instead.
    ///
    /// Note: depending on the configuration `use_rand_generators`,
    /// the generators may be generated randomly.
    pub fn init(seed: &[u8]) -> Result<Self, String> {
        // make sure we have enough entropy
        if seed.len() < 32 {
            return Err(
                "the seed length is not long enough (required as least 32 bytes)".to_owned(),
            );
        }

        let mut ctr = 0;

        // if feature = use_rand_generators then we use randomized generators
        // #[cfg(feature = "use_rand_generators")]
        // let g1 = {
        //     let mut g1 = PixelG1::one();
        //     let r: Vec<Fr> =
        //         util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
        //     ctr += 1;
        //     g1.mul_assign(r[0]);
        //     g1
        // };
        #[cfg(feature = "use_rand_generators")]
        let g2 = {
            let mut g2 = PixelG2::one();
            // TODO: use hash_to_group function
            let r: Vec<Fr> =
                util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
            ctr += 1;
            g2.mul_assign(r[0]);
            g2
        };

        // else we set the generators to the default ones from bls12-381 curve
        // #[cfg(not(feature = "use_rand_generators"))]
        // let g1 = PixelG1::one();
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
        let mut hlist: Hlist = [PixelG1::one(); CONST_D + 1];
        for i in 0..CONST_D + 1 {
            let r: Vec<Fr> =
                util::HashToField::hash_to_field(seed, ctr, 1, util::HashIDs::Sha256, 2);
            ctr += 1;
            hlist[i].mul_assign(r[0]);
        }

        // format the output
        Ok(PubParam {
            d: CONST_D,
            g2: g2,
            h: h,
            hlist: hlist,
        })
    }

    /// This a deterministic method to generate public parameters that matchs
    /// pixel-python implemetation.
    /// Specifically, the parameters are `\[g2, g1, g1, g1^2, ... g1^(d+1)\]`.
    /// The parameters generated here are insecure
    /// Do not use in deployment!
    #[cfg(test)]
    pub fn det_param_gen() -> PubParam {
        println!("Warning: insecure parameters detected. Use for testing only!");
        let h = PixelG1::one();
        let g2 = PixelG2::one();
        let mut hv = [PixelG1::one(); CONST_D + 1];
        for i in 1..CONST_D + 1 {
            let tmp = hv[i - 1];
            hv[i].add_assign(&tmp);
        }
        PubParam {
            d: CONST_D,
            g2: g2,
            h: h,
            hlist: hv,
        }
    }
}

impl fmt::Debug for PubParam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Public Parameter======\n\
             depth: {}\n\
             g2 : {:#?}\n\
             h  : {:#?}\n",
            //            self.g1.into_affine(),
            self.d,
            self.g2.into_affine(),
            self.h.into_affine(),
        )?;
        for i in 0..CONST_D + 1 {
            write!(f, "hlist: h{}: {:#?}\n", i, self.hlist[i].into_affine())?;
        }
        write!(f, "================================\n")
    }
}
