/// This file implements the functions that we will be using to, initiate, maintain and update
/// the seeds of random number generators.
// use clear on drop to zero out buffer
use clear_on_drop::ClearOnDrop;
// use hkdf-sha512 to extract and expand a seed
use hkdf::Hkdf;
use sha2::{digest::generic_array, Sha512};
// hash to Fr
use bigint::U512;
use ff::PrimeField;
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

    /// Mix new entropy into the PRNG.
    pub fn rerandomize<Blob: AsRef<[u8]>>(&mut self, seed: Blob, salt: Blob) {
        let mut m_sec = [&self.0.to_vec(), seed.as_ref()].concat();
        let mut k_sec = Hkdf::<Sha512>::extract(Some(salt.as_ref()), m_sec.as_ref());
        self.0.clone_from_slice(&k_sec.prk[0..64]);
        // clean up m and k
        {
            let _clear1 = ClearOnDrop::new(&mut m_sec);
            let _clear2 = ClearOnDrop::new(&mut k_sec.prk);
        }
        assert_eq!(m_sec, vec![], "Extracted secret not cleared");
        assert_eq!(
            k_sec.prk,
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

    // TODO: review and test this function.

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

    Fr::from_repr(s).unwrap()
}

// examples from
// https://crypto.stackexchange.com/questions/37537/what-are-i2osp-os2ip-in-rsa-pkcs1
//  0  ->  00:00
//  1  ->  00:01
// 255  ->  00:FF
// 256  ->  01:00
// 65535  ->  FF:FF
#[test]
fn test_os2ip() {
    assert_eq!(Fr::from_str("0").unwrap(), os2ip_mod_p(&[0u8, 0u8]));
    assert_eq!(Fr::from_str("1").unwrap(), os2ip_mod_p(&[0u8, 1u8]));
    assert_eq!(Fr::from_str("255").unwrap(), os2ip_mod_p(&[0u8, 0xffu8]));
    assert_eq!(Fr::from_str("256").unwrap(), os2ip_mod_p(&[1u8, 0u8]));
    assert_eq!(
        Fr::from_str("65535").unwrap(),
        os2ip_mod_p(&[0xffu8, 0xffu8])
    );
    // 2^128
    assert_eq!(
        Fr::from_str("340282366920938463463374607431768211456").unwrap(),
        // 1 followed by 128/8 = 16 zeros
        os2ip_mod_p(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    // 2^256 % p
    assert_eq!(
        Fr::from_str(
            "10920338887063814464675503992315976177888879664585288394250266608035967270910"
        )
        .unwrap(),
        os2ip_mod_p(&[
            // 1 followed by 256/8 = 32 zeros
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0
        ])
    );
    // 2^384 % p
    assert_eq!(
        Fr::from_str(
            "20690987792304517493546419304065979215229097455316523017309531943206242971949"
        )
        .unwrap(),
        os2ip_mod_p(&[
            // 1 followed by 384/8 = 48 zeros
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ])
    );
}

// TODO: move the tests to a separate file
#[test]
fn test_prng() {
    // test sample then update function
    let mut prng = PRNG::init("seed", "salt");
    assert_eq!(
        prng.get_seed().as_ref(),
        [
            0xde, 0x8, 0xde, 0xe9, 0xf2, 0x71, 0xa6, 0xa0, 0x61, 0xf0, 0xc7, 0x6b, 0x10, 0xb0,
            0xe4, 0xa7, 0x10, 0x7d, 0xa1, 0xeb, 0x84, 0x9f, 0x7e, 0x46, 0xd4, 0x80, 0xf3, 0xab,
            0x93, 0x5b, 0xd5, 0x63, 0x29, 0x75, 0x16, 0x34, 0x8f, 0x3a, 0x4, 0x43, 0x7e, 0x99,
            0x84, 0x80, 0x8a, 0xde, 0xab, 0xc5, 0x40, 0x8f, 0x78, 0xc0, 0x66, 0x7d, 0xd0, 0x15,
            0x7c, 0x6e, 0xcb, 0xf7, 0xa7, 0x4b, 0x69, 0xb7,
        ]
        .as_ref()
    );

    let r = prng.sample_then_update("info");
    assert_eq!(
        prng.get_seed().as_ref(),
        [
            0x41, 0xfa, 0x66, 0x27, 0x76, 0xb3, 0xff, 0x97, 0x54, 0x1f, 0xda, 0xf8, 0xb1, 0xfa,
            0xda, 0xef, 0x55, 0x15, 0x31, 0xcb, 0xb6, 0x2b, 0x23, 0x28, 0x1e, 0xed, 0xc0, 0x37,
            0xa7, 0x77, 0x76, 0xb2, 0xec, 0x3f, 0xe2, 0xa3, 0x3a, 0xde, 0x72, 0x21, 0x76, 0x96,
            0x2b, 0x9c, 0x4f, 0x31, 0x3c, 0xb5, 0xe6, 0xcd, 0x17, 0x7f, 0x33, 0x40, 0xa4, 0xf,
            0x58, 0x7c, 0x12, 0x1d, 0x7, 0xfe, 0x57, 0x69,
        ]
        .as_ref()
    );
    assert_eq!(
        Fr::from_str(
            "43319743699496810973708981086850604276149960407194162211265932872777355818354"
        )
        .unwrap(),
        r
    );

    // test sample function
    let r1 = prng.sample("info");
    let r2 = prng.sample("info");
    assert_eq!(r1, r2);
    assert_eq!(
        Fr::from_str(
            "22074932395097706468768456200905687926580984780754047608537081666156889203804"
        )
        .unwrap(),
        r1
    );

    // test re-rerandomize function
    prng.rerandomize("seed", "salt");
    let r3 = prng.sample_then_update("info");
    assert_eq!(
        Fr::from_str(
            "27132649749439062230068796557891373128664794982284628022370337752841632724936"
        )
        .unwrap(),
        r3
    );
    assert_eq!(
        prng.get_seed().as_ref(),
        [
            0x1a, 0x63, 0x8a, 0x65, 0x6, 0x3b, 0xc7, 0x3e, 0x9a, 0x8d, 0x84, 0x8d, 0x3a, 0x1e,
            0x2e, 0x9d, 0x4a, 0xe3, 0x64, 0x0, 0x73, 0xf8, 0xac, 0x58, 0x80, 0xbb, 0x23, 0x5b,
            0xfc, 0xef, 0x4d, 0x87, 0x83, 0xf8, 0xe1, 0xa6, 0x7a, 0x1, 0x18, 0x16, 0xcd, 0x79,
            0x7b, 0x75, 0xcb, 0x93, 0x8a, 0xd4, 0xd3, 0xb8, 0x82, 0xba, 0xa0, 0x14, 0x1f, 0xde,
            0x4a, 0x2f, 0x33, 0x2e, 0x77, 0xa4, 0xb5, 0x4b,
        ]
        .as_ref()
    );
}
