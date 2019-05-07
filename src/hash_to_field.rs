use bigint::U512;
use ff::{Field, PrimeField, PrimeFieldDecodingError, PrimeFieldRepr};
use pairing::bls12_381::Fr;
use pairing::bls12_381::FrRepr;
use sha2::Digest;
use std::ops::Rem;

// function is defined in
// https://github.com/pairingwg/bls_standard/blob/master/minutes/spec-v1.md
// hash_to_field(msg, ctr, p, m, hash_fn, hash_reps)
//
// Parameters:
//   - msg is an octet string to be hashed.
//   - ctr is an integer < 2^8 used to orthogonalize hash functions
//   - p and m specify the field as GF(p^m)
//   - hash_fn is a hash function, e.g., SHA256
//   - hash_reps is the number of concatenated hash outputs
//     used to produce an element of F_p
//
// hash_to_field(msg, ctr, p, m, hash_fn, hash_reps) :=
//     msg' = hash_fn(msg) || I2OSP(ctr, 1)
//     for i in (1, ..., m):
//         t = ""  // initialize to the empty string
//         for j in (1, ..., hash_reps):
//             t = t || hash_fn( msg' || I2OSP(i, 1) || I2OSP(j, 1) )
//         e_i = OS2IP(t) mod p
//     return (e_1, ..., e_m)

#[allow(dead_code)]
pub fn hash_to_fr(
    input: &[u8],
    ctr: u8,
    // the modulus is implicitly defined as the group order r
    m: u8,
    // the hash_fn is implicitly defined as sha256
    hash_reps: u8,
) -> Vec<Fr> {
    // hard coded modulus r
    // decimal: 52435875175126190479447740508185965837690552500527637822603658699938581184513
    // hex: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    let r = U512::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39, 0xD8, 0x08, 0x09, 0xA1,
        0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        0x00, 0x00, 0x01,
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
                    bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62],
                    bytes[63],
                ]),
                u64::from_be_bytes([
                    bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54],
                    bytes[55],
                ]),
                u64::from_be_bytes([
                    bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46],
                    bytes[47],
                ]),
                u64::from_be_bytes([
                    bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38],
                    bytes[39],
                ]),
            ]))
            .unwrap(),
        );
    }

    out
}

// converting an u8 integer into i2osp form
#[allow(dead_code)]
fn i2osp(int: u8, len: usize) -> Vec<u8> {
    let mut tmp = vec![0u8; len - 1];
    tmp.push(int);
    tmp
}
