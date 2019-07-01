// this file defines the structures for the public parameter
// and its associated methods

use pairing::CurveProjective;
use std::fmt;
// use hash to curve functions from bls reference implementation
use bls_sigs_ref_rs::HashToCurve;
use pixel_err::*;
use PixelG1;
use PixelG2;

/// Currently, ciphersuite identifier must be either 0 or 1.
/// The maps between CSID and actual parameters is TBD.
/// Additional ciphersuite identifiers may be added later.
pub const VALID_CIPHERSUITE: [u8; 2] = [0, 1];

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
    ciphersuite: u8,
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

    /// get the cipher suite id from the public param
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

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
        self.hlist
    }

    /// This function initialize the parameter with a default seed = empty string "".
    /// It should not be used except for testing purpose
    #[cfg(test)]
    pub fn init_without_seed() -> Self {
        println!("warning!!!\nthis function should be used for testing purpose only\nuse PubParam::init() instead\n");
        Self::init(b"this is a long and determinstic seed", 0).unwrap()
    }

    /// This function takes input a string seed, and a ciphersuite id, and outputs the
    /// public parameters using `hash_to_group(seed|ctr, ciphersuite)`
    ///
    /// Note: depending on the configuration `use_rand_generators`,
    /// the generators will be generated randomly.
    pub fn init(seed: &[u8], ciphersuite: u8) -> Result<Self, String> {
        // make sure we have enough entropy
        if seed.len() < 32 {
            return Err(ERR_SEED_TOO_SHORT.to_owned());
        }
        // make sure the ciphersuite is valid    <- the valid list is tentitive
        if !VALID_CIPHERSUITE.contains(&ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // the input to the HashToCurve is formated as
        //  hash_to_group( seed|ctr, ciphersuite)
        // where ctr starts from 0 and is incremental

        let mut ctr = 0;
        let mut t = seed.to_vec();
        t.push(ctr);

        #[cfg(feature = "verbose")]
        #[cfg(debug_assertions)]
        println!(
            "the {}th input to the hash to curve function is {:?}, with a ciphersuite id = {}",
            ctr, t, ciphersuite
        );

        // if feature = use_rand_generators then we use randomized generators
        // that is generated from HashToCurve
        #[cfg(feature = "use_rand_generators")]
        let g2 = {
            // generate a new group element, and increment the counter
            let g2 = PixelG2::hash_to_curve(t.clone(), ciphersuite);
            ctr += 1;
            t.pop();
            t.push(ctr);
            #[cfg(feature = "verbose")]
            #[cfg(debug_assertions)]
            println!(
                "the {}th input to the hash to curve function is {:?}, with a ciphersuite id = {}",
                ctr, t, ciphersuite
            );
            g2
        };

        // else we set the generators to the default ones from bls12-381 curve
        #[cfg(not(feature = "use_rand_generators"))]
        let g2 = PixelG2::one();

        // generate h
        // generate a new group element, and increment the counter
        let h = PixelG1::hash_to_curve(t.clone(), ciphersuite);
        ctr += 1;
        t.pop();
        t.push(ctr);

        #[cfg(feature = "verbose")]
        #[cfg(debug_assertions)]
        println!(
            "the {}th input to the hash to curve function is {:?}, with a ciphersuite id = {}",
            ctr, t, ciphersuite
        );

        // generate hlist
        let mut hlist: Hlist = [PixelG1::zero(); CONST_D + 1];
        for element in &mut hlist  {
            // generate a new group element, and increment the counter
            *element = PixelG1::hash_to_curve(t.clone(), ciphersuite);
            ctr += 1;
            t.pop();
            t.push(ctr);
            #[cfg(feature = "verbose")]
            #[cfg(debug_assertions)]
            println!(
                "the {}th input to the hash to curve function is {:?}, with a ciphersuite id = {}",
                ctr, t, ciphersuite
            );
        }

        // format the output
        Ok(PubParam {
            d: CONST_D,
            ciphersuite,
            g2,
            h,
            hlist,
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
        for i in 1..=CONST_D {
            let tmp = hv[i - 1];
            hv[i].add_assign(&tmp);
        }
        PubParam {
            d: CONST_D,
            ciphersuite: 0,
            g2,
            h,
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
             ciphersuite: {}\n\
             g2 : {:#?}\n\
             h  : {:#?}\n",
            //            self.g1.into_affine(),
            self.d,
            self.ciphersuite,
            self.g2.into_affine(),
            self.h.into_affine(),
        )?;
        for i in 0..=CONST_D {
            writeln!(f, "hlist: h{}: {:#?}", i, self.hlist[i].into_affine())?;
        }
        writeln!(f, "================================")
    }
}

#[test]
fn test_param_gen() {
    let res = PubParam::init(b"this is a very long seed to test parameter generation", 0);
    assert!(res.is_ok());
    println!("Public parameter: \n{:?}", res.unwrap());
}
