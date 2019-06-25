/// this file implements the additional utilities that are required by the pixel signature
use bigint::U512;
use ff::PrimeField;
use pairing::bls12_381::{Fq, FqRepr, Fr, FrRepr};
use sha2::Digest;

/// * a list of identifiers for hash functions
/// * only sha256 is supported per curret spec
#[derive(PartialEq, Debug)]
pub enum HashIDs {
    Sha256,
    //    Sha512,
}

pub trait HashToField
where
    Self: std::marker::Sized,
{
    /// this function is defined in
    /// the [draft](https://github.com/pairingwg/bls_standard/blob/master/minutes/spec-v1.md)
    ///
    /// Input parameters:
    ///   - input is an octet string to be hashed.
    ///   - ctr is an integer < 2^8 used to orthogonalize hash functions
    ///   - p and m specify the field as GF(p^m), p is implied by the calling struct
    ///   - hash_fn is a hash function, e.g., SHA256
    ///   - hash_reps is the number of concatenated hash outputs
    ///     used to produce an element of F_p
    ///
    /// Output:
    ///   - a list of m field elements

    // Pseudo code
    // hash_to_field(msg, ctr, p, m, hash_fn, hash_reps) :=
    //     msg' = hash_fn(msg) || I2OSP(ctr, 1)
    //     for i in (1, ..., m):
    //         t = ""  // initialize to the empty string
    //         for j in (1, ..., hash_reps):
    //             t = t || hash_fn( msg' || I2OSP(i, 1) || I2OSP(j, 1) )
    //         e_i = OS2IP(t) mod p
    //     return (e_1, ..., e_m)
    fn hash_to_field(input: &[u8], ctr: u8, m: u8, hashid: HashIDs, hash_reps: u8) -> Vec<Self>;
}

impl HashToField for Fr {
    /// hash into a list of Fr elements
    ///
    /// extern crate pairing;
    /// extern crate ff;
    /// extern crate pixel;
    /// use pairing::bls12_381::{Fr, FrRepr};
    /// use ff::PrimeField;
    /// use pixel::util::{HashToField, HashIDs};
    /// let t: Vec<Fr> = HashToField::hash_to_field(b"11223344556677889900112233445566", 0, 1, HashIDs::Sha256, 2);
    /// assert_eq!(
    ///     t,
    ///     vec![Fr::from_repr(FrRepr([
    ///         0xb7e588b4fe9899e4,
    ///         0x80fe5eb14ff08fe5,
    ///         0xdb70e1c88efa851e,
    ///         0x414e2c2a330cf94e,
    ///     ]))
    ///     .unwrap()]);
    ///
    fn hash_to_field(input: &[u8], ctr: u8, m: u8, hashid: HashIDs, hash_reps: u8) -> Vec<Self> {
        assert_eq!(
            hashid,
            HashIDs::Sha256,
            "currently do not support {:?} other than Sha256",
            hashid
        );

        // hard coded modulus r - group order
        // decimal: 52435875175126190479447740508185965837690552500527637822603658699938581184513
        // hex: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        let r = U512::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39, 0xD8, 0x08, 0x09,
            0xA1, 0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0xFF, 0xFF,
            0xFF, 0x00, 0x00, 0x00, 0x01,
        ]);

        //  tmp = hash_fn(msg)
        let mut hasher = sha2::Sha256::new();
        hasher.input(input);
        let tmp = hasher.result();
        let mut m_prime = tmp.as_ref().to_vec();

        // m_prime = hash(msg) || i2osp(ctr,1)
        m_prime.append(&mut i2osp(ctr, 1));
        let mut out: Vec<Fr> = vec![];
        for i in 1..=m {
            let mut t: Vec<u8> = vec![];
            for j in 1..=hash_reps {
                // hash_fn( msg' || I2OSP(i, 1) || I2OSP(j, 1) )
                let mut tmp = m_prime.clone();
                tmp.append(&mut i2osp(i, 1));
                tmp.append(&mut i2osp(j, 1));

                let mut hasher = sha2::Sha256::new();
                let hashinput = &tmp[..];
                hasher.input(hashinput);
                let tmp = hasher.result();

                // append the hash output to t
                t.append(&mut tmp.as_ref().to_vec());
            }

            // compute e % r
            let mut e = U512::from(&t[..]);
            e = e % r;

            // convert the output into a Fr element
            let mut tslide: [u8; 64] = [0; 64];
            let bytes: &mut [u8] = tslide.as_mut();
            e.to_big_endian(bytes);
            out.push(
                Fr::from_repr(FrRepr([
                    u64::from_be_bytes([
                        bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61],
                        bytes[62], bytes[63],
                    ]),
                    u64::from_be_bytes([
                        bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53],
                        bytes[54], bytes[55],
                    ]),
                    u64::from_be_bytes([
                        bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45],
                        bytes[46], bytes[47],
                    ]),
                    u64::from_be_bytes([
                        bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37],
                        bytes[38], bytes[39],
                    ]),
                ]))
                .unwrap(),
            );
        }

        out
    }
}

impl HashToField for Fq {
    /// hash into a list of Fq elements
    ///
    /// extern crate pairing;
    /// extern crate ff;
    /// extern crate pixel;
    /// use pairing::bls12_381::{Fq, FqRepr};
    /// use ff::PrimeField;
    /// use pixel::util::{HashToField, HashIDs};
    /// let t: Vec<Fq> = HashToField::hash_to_field(b"11223344556677889900112233445566", 0, 1, HashIDs::Sha256, 2);
    /// assert_eq!(
    ///     t,
    ///     vec![Fq::from_repr(FqRepr([
    ///         0xf7da8bd272b3b141,
    ///         0x737d485578864f3e,
    ///         0xb0a45604bd794066,
    ///         0x79a265924aaef8ba,
    ///         0x822e35dde11c0cfb,
    ///         0x04256f4dab6326d7,
    ///     ]))
    ///     .unwrap()]);
    ///
    fn hash_to_field(input: &[u8], ctr: u8, m: u8, hashid: HashIDs, hash_reps: u8) -> Vec<Self> {
        assert_eq!(
            hashid,
            HashIDs::Sha256,
            "currently do not support {:?} other than Sha256",
            hashid
        );

        // hard coded modulus q
        // decimal: 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
        // hex: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
        let q = U512::from([
            0, 0, 0, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f,
            0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84,
            0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab,
            0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
        ]);

        //  tmp = hash_fn(msg)
        let mut hasher = sha2::Sha256::new();
        hasher.input(input);
        let tmp = hasher.result();
        let mut m_prime = tmp.as_ref().to_vec();

        // m_prime = hash(msg) || i2osp(ctr,1)
        m_prime.append(&mut i2osp(ctr, 1));
        let mut out: Vec<Fq> = vec![];
        for i in 1..=m {
            let mut t: Vec<u8> = vec![];
            for j in 1..=hash_reps {
                // hash_fn( msg' || I2OSP(i, 1) || I2OSP(j, 1) )
                let mut tmp = m_prime.clone();
                tmp.append(&mut i2osp(i, 1));
                tmp.append(&mut i2osp(j, 1));

                let mut hasher = sha2::Sha256::new();
                let hashinput = &tmp[..];
                hasher.input(hashinput);
                let tmp = hasher.result();

                // append the hash output to t
                t.append(&mut tmp.as_ref().to_vec());
            }

            // compute e % q
            let mut e = U512::from(&t[..]);
            e = e % q;

            // convert the output into a Fr element
            let mut tslide: [u8; 64] = [0; 64];
            let bytes: &mut [u8] = tslide.as_mut();
            e.to_big_endian(bytes);

            out.push(
                Fq::from_repr(FqRepr([
                    u64::from_be_bytes([
                        bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61],
                        bytes[62], bytes[63],
                    ]),
                    u64::from_be_bytes([
                        bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53],
                        bytes[54], bytes[55],
                    ]),
                    u64::from_be_bytes([
                        bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45],
                        bytes[46], bytes[47],
                    ]),
                    u64::from_be_bytes([
                        bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37],
                        bytes[38], bytes[39],
                    ]),
                    u64::from_be_bytes([
                        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29],
                        bytes[30], bytes[31],
                    ]),
                    u64::from_be_bytes([
                        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
                        bytes[22], bytes[23],
                    ]),
                ]))
                .unwrap(),
            );
        }

        out
    }
}

// converting an u8 integer into i2osp form
// this is a very simple implementation of i2osp function
// with a constraint that the input is only a u8
fn i2osp(int: u8, len: usize) -> Vec<u8> {
    let mut tmp = vec![0u8; len - 1];
    tmp.push(int);
    tmp
}
