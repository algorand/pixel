/// This file implements the functions that we will be using to, initiate, maintain and update
/// the seeds of random number generators.
// use clear on drop to zero out buffer
use clear_on_drop::ClearOnDrop;
// use hkdf-sha512 to extract and expand a seed
use hkdf::Hkdf;
use sha2::{digest::generic_array, Sha512};
// hash to Fr requires the following traits
use bigint::U512;
use ff::PrimeField;
use pairing::bls12_381::{Fr, FrRepr};
use std::ops::Rem;

/// A PRNG in Pixel is a wrapper of 64 byte array.
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

/// convenient function to compare PRNGs.
/// It is required when we want to check the prngs are zeroed out after cleanning.
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
    pub fn seed(&self) -> &[u8; 64] {
        &self.0
    }

    /// Build a prng from an rngseed.
    pub fn new(rngseed: [u8; 64]) -> Self {
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
            prk: generic_array::GenericArray::clone_from_slice(self.seed()),
        };

        // hkdf-expand(seed, info)
        let mut output_sec = vec![0u8; 128];
        assert!(
            hk_sec.expand(info.as_ref(), &mut output_sec).is_ok(),
            "hkdf expand failed"
        );
        // convert the first 64 bytes of the output to a field element
        // by os2ip(output_sec[0..64]) % p
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
        for (i, e) in new_seed.iter_mut().enumerate() {
            *e = i as u8;
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
            prk: generic_array::GenericArray::clone_from_slice(self.seed()),
        };

        // hkdf-expand(seed, info)
        let mut output_sec = vec![0u8; 64];
        assert!(
            hk_sec.expand(info.as_ref(), &mut output_sec).is_ok(),
            "hkdf expand failed"
        );

        // convert the first 64 bytes of the output to a field element
        // by os2ip(output_sec) % p
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

    /// Mix new entropy into the PRNG.
    pub fn rerandomize<Blob: AsRef<[u8]>>(&mut self, seed: Blob, info: Blob) {
        // expand self into a new 64 array
        // m1 = hkdf-expand(info, 64)
        // re-build the hkdf-sha512 from the PRNG seed
        let mut hk1_sec = Hkdf::<Sha512> {
            prk: generic_array::GenericArray::clone_from_slice(self.seed()),
        };
        // hkdf-expand(seed, info)
        let mut m_sec = vec![0u8; 128];
        assert!(
            hk1_sec.expand(info.as_ref(), &mut m_sec).is_ok(),
            "hkdf expand failed"
        );

        // extract the new prng seed
        // hk2 = hkdf-extract(m[64..128], m[0..64]|seed)
        let mut tmp_sec = [m_sec[0..64].as_ref(), seed.as_ref()].concat();
        let mut hk2_sec = Hkdf::<Sha512>::extract(Some(m_sec[64..128].as_ref()), tmp_sec.as_ref());

        // update self with the new hkdf's key
        self.0.clone_from_slice(&hk2_sec.prk[0..64]);
        // clean up m and k
        {
            let _clear1 = ClearOnDrop::new(&mut m_sec);
            let _clear2 = ClearOnDrop::new(&mut hk1_sec.prk);
            let _clear3 = ClearOnDrop::new(&mut tmp_sec);
            let _clear3 = ClearOnDrop::new(&mut hk2_sec.prk);
        }
        assert_eq!(m_sec, vec![], "Extracted secret not cleared");
        assert_eq!(
            hk1_sec.prk,
            generic_array::GenericArray::default(),
            "HKDF not cleared"
        );
        assert_eq!(tmp_sec, vec![], "Extracted secret not cleared");
        assert_eq!(
            hk2_sec.prk,
            generic_array::GenericArray::default(),
            "HKDF not cleared"
        );
    }
}

/// this is pixel's Octect String to Integer Primitive (os2ip) function
/// https://tools.ietf.org/html/rfc8017#section-4
/// the input is a 64 bytes array, and the output is between 0 and p-1
/// i.e., it performs mod operation by default.
pub fn os2ip_mod_p(oct_str: &[u8]) -> Fr {
    // "For the purposes of this document, and consistent with ASN.1 syntax,
    // an octet string is an ordered sequence of octets (eight-bit bytes).
    // The sequence is indexed from first (conventionally, leftmost) to last
    // (rightmost).  For purposes of conversion to and from integers, the
    // first octet is considered the most significant in the following
    // conversion primitives.
    //
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
    // 3.  Output x. "

    let mut r_sec = U512::from(oct_str);

    // hard coded modulus p
    let p = U512::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39, 0xD8, 0x08, 0x09, 0xA1,
        0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        0x00, 0x00, 0x01,
    ]);
    // t = r % p
    let mut t_sec = r_sec.rem(p);

    // convert t from a U512 into a primefield object s
    let mut tslide: [u8; 64] = [0; 64];
    let bytes: &mut [u8] = tslide.as_mut();
    t_sec.to_big_endian(bytes);

    // the top 32 bytes should be 0s after the mod operation
    assert_eq!(bytes[0..32].to_vec(), vec![0; 32]);

    let s = FrRepr([
        u64::from_be_bytes([
            bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
        ]),
        u64::from_be_bytes([
            bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
        ]),
        u64::from_be_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]),
        u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
    ]);
    // clear r_sec and t_sec
    {
        let _clear1 = ClearOnDrop::new(&mut r_sec);
        let _clear2 = ClearOnDrop::new(&mut t_sec);
    }
    assert_eq!(r_sec, U512::default());
    assert_eq!(t_sec, U512::default());

    // manually clear bytes since Default trait is not implemented for [u8;64]
    for (i, e) in bytes.iter_mut().enumerate().take(64) {
        *e = i as u8;
    }

    // s has to be a Fr element by construction, if not, panic
    match Fr::from_repr(s) {
        Err(e) => panic!(e),
        Ok(p) => p,
    }
}
