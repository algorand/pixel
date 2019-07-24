/// This file implements the functions that we will be using to, initiate, maintain and update
/// the seeds of random number generators.
// use clear on drop to zero out buffer
use clear_on_drop::ClearOnDrop;
// use hkdf-sha512 to extract and expand a seed
use hkdf::Hkdf;
use sha2::{digest::generic_array, Sha512};
// hash to Fr
use ff::PrimeField;
use num_bigint::BigUint;
use pairing::bls12_381::{Fr, FrRepr};
use std::ops::Rem;

/// A PRNG in Pixel is a wrapper of 32 byte array.
/// This array is initiated during key generation,
/// stored as part of the secret key, updated When
/// secret key is updated, and is used to generate
/// random field elements.
#[derive(Clone, Copy)]
pub struct PRNG([u8; 64]);

/// implement the Default trait for PRNG
/// a trait bound for ClearOnDrop
impl Default for PRNG {
    fn default() -> Self {
        PRNG([0u8; 64])
    }
}

/// implement the Debug trait for PRNG
impl std::fmt::Debug for PRNG {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for i in 0..8 {
            for j in 0..8 {
                write!(f, "0x{:02x}, ", self.0[i * 8 + j])?;
            }
            writeln!(f)?;
        }
        write!(f, "")
    }
}

/// convenient function to compare PRNGs
impl std::cmp::PartialEq for PRNG {
    fn eq(&self, other: &Self) -> bool {
        for i in 0..64 {
            if self.0[i] != other.0[i] {
                return false;
            }
        }
        true
    }
}

impl PRNG {
    /// Expose the seed.
    pub fn get_seed(&self) -> &[u8; 64] {
        &self.0
    }

    /// Build a prng from an rngseed.
    pub fn construct(rngseed: [u8; 64]) -> Self {
        Self(rngseed)
    }

    /// This function takes in a seed, and a salt,
    /// and instantiate a PRNG by extracting the randomness
    /// from the seed using HKDF-Extract
    pub fn init<Blob: AsRef<[u8]>>(seed: Blob, salt: Blob) -> Self {
        // now build the hkdf-sha512: m = hkdf-extract(salt, seed)
        let mut hk_sec = Hkdf::<Sha512>::extract(Some(salt.as_ref()), seed.as_ref());
        let mut rng_seed = [0u8; 64];
        rng_seed.copy_from_slice(&hk_sec.prk[0..64]);
        // clear the hk
        {
            let _clear2 = ClearOnDrop::new(&mut hk_sec.prk);
        }
        // make sure the HKDF memory is cleared
        assert_eq!(
            hk_sec.prk.to_vec(),
            vec![0u8; 64],
            "HKDF buffer not cleared"
        );
        Self(rng_seed)
    }

    /// This function takes in a PRNG, some public info, and a counter
    /// and sample a field element; the PRNG is updated.
    pub fn sample_then_update<Blob: AsRef<[u8]>>(&mut self, info: Blob) -> Fr {
        // re-build the hkdf-sha512 from the PRNG seed
        let mut hk_sec = Hkdf::<Sha512> {
            prk: generic_array::GenericArray::clone_from_slice(self.get_seed()),
        };

        // hkdf-expand(seed, info)
        let mut output_sec = vec![0u8; 128];
        assert!(
            hk_sec.expand(info.as_ref(), &mut output_sec).is_ok(),
            "hkdf expand failed"
        );
        let r = os2ip_mod_p(&output_sec[0..64]);

        // clear the old seed
        {
            let _clear1 = ClearOnDrop::new(&mut (*self));
        }
        assert_eq!(*self, PRNG::default(), "old seed not cleared");

        // update self to the new seed
        let mut new_seed = [0u8; 64];
        new_seed.clone_from_slice(&output_sec[64..128]);
        *self = Self(new_seed);

        // Here is something tricky.
        // When new_seed is wraped into the `Self` structure,
        // there are two copies in the memory, one in `new_seed`
        // and the other in *self.
        // Therefore, we also need to clear new_seed.
        // But new_seed is a [u8;64] type - Default trait is
        // not defined for this type - and we cannot implement
        // default trait either, since neither [u8;64] nor Default
        // are local to this crate. This means we cannot use
        // ClearOnDrop (which sets the memory to the default value)
        // to clear the memory.
        // So we manually clear out this array by writing
        // travial data to it.
        for i in 0..64 {
            new_seed[i] = i as u8;
        }

        // clear the buffer and hk
        {
            let _clear2 = ClearOnDrop::new(&mut output_sec);
            let _clear3 = ClearOnDrop::new(&mut hk_sec.prk);
        }
        // make sure the memory is cleared
        assert_eq!(output_sec, vec![], "secret buf not cleared");
        assert_eq!(
            hk_sec.prk.to_vec(),
            vec![0u8; 64],
            "HKDF buffer not cleared"
        );

        // return the field element
        r
    }

    /// This function takes in a PRNG, some public info, and a counter
    /// and sample a field element; the PRNG is NOT updated.
    pub fn sample<Blob: AsRef<[u8]>>(&mut self, info: Blob) -> Fr {
        // re-build the hkdf-sha512 from the PRNG seed
        let mut hk_sec = Hkdf::<Sha512> {
            prk: generic_array::GenericArray::clone_from_slice(self.get_seed()),
        };

        // hkdf-expand(seed, info)
        let mut output_sec = vec![0u8; 64];
        assert!(
            hk_sec.expand(info.as_ref(), &mut output_sec).is_ok(),
            "hkdf expand failed"
        );

        // hash the first 64 bytes of the output to a field element
        let r = os2ip_mod_p(&output_sec);

        // clear the buffer and hk
        {
            let _clear2 = ClearOnDrop::new(&mut output_sec);
            let _clear3 = ClearOnDrop::new(&mut hk_sec.prk);
        }
        // make sure the memory is cleared
        assert_eq!(output_sec, vec![], "secret buf not cleared");
        assert_eq!(
            hk_sec.prk.to_vec(),
            vec![0u8; 64],
            "HKDF buffer not cleared"
        );

        // return the field element
        r
    }

    /// Use this function to safely clear the secret within a PRNG.
    pub fn destroy(&mut self) {
        // clear the seed within a PRNG
        {
            let _clear = ClearOnDrop::new(&mut (*self));
        }
        assert_eq!(*self, PRNG::default(), "old seed not cleared");
    }
}

/// this is pixel's Octect String to Integer Primitive (os2ip) function
/// https://tools.ietf.org/html/rfc8017#section-4
/// the input is a 64 bytes array, and the output is between 0 and p-1
/// i.e., it performs mod operation by default.
fn os2ip_mod_p(oct_str: &[u8]) -> Fr {
    // OS2IP converts an octet string to a nonnegative integer.
    // OS2IP (X)
    // Input:  X octet string to be converted
    // Output:  x corresponding nonnegative integer
    // Steps:
    // 1.  Let X_1 X_2 ... X_xLen be the octets of X from first to last,
    //  and let x_(xLen-i) be the integer value of the octet X_i for 1
    //  <= i <= xLen.
    // 2.  Let x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) +
    //  ...  + x_1 256 + x_0.
    // 3.  Output x.

    // This says the os2ip uses little endian representation
    // TODO: review and test it.

    let r = BigUint::from_bytes_le(oct_str.as_ref());
    // hard coded modulus p
    let p = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10,
    )
    .unwrap();
    let t = r.rem(p);
    let bytes = t.to_bytes_be();
    // FIXME: it may be that t < 2^248 with 1/256 probability, then
    // bytes will be an array of 31 bytes, instead of 32.
    // this triggers an failure in API tests.
    println!("bytes: {} {:?}", bytes.len(), bytes);
    let s = FrRepr([
        u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
        u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
    ]);

    println!("bytes: {:?}", s);
    Fr::from_repr(s).unwrap()
}

// TODO: more test cases
// and move the tests to a separate file
#[test]
fn test_prng() {
    let mut prng = PRNG::init("seed", "salt");
    let _r = prng.sample_then_update("info");
    let r1 = prng.sample("info");
    let r2 = prng.sample("info");
    println!("{:?}, {:?}, {:?}", _r, r1, r2);
    assert_eq!(r1, r2);
}
