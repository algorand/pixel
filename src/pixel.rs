use ff::{Field, PrimeField};
use keys::{SecretKey, SKAlgorithm};
use pairing::bls12_381::Fr;
use pairing::bls12_381::FrRepr;
use param::PubParam;
use sha2::{Digest, Sha256};
use sign::{Signature, *};
pub struct Pixel;

//impl PixelAlgorithm for Pixel {}
pub fn pixel_sign(
    sk: &SecretKey,
    pp: &PubParam,
    time: &u64,
    msg: &[u8],
    seed: &[u32; 4],
) -> Signature {
    let m = hash_to_fr(msg);
    Sign::sign_with_seed_and_time(&sk.get_fist_ssk(), &pp, time, &m, seed)
}

// try and incremetal method to get an Fr element
pub fn hash_to_fr(msg: &[u8]) -> Fr {
    // iterator
    let mut index = 0u8;
    // domain seperator
    let domain_sep: Vec<u8> = "hash_to_fr".as_bytes().to_vec();
    let result = loop {
        // hash( “hash_to_fr” | msg | index )
        let mut hasher = Sha256::new();
        let mut input = domain_sep.clone();
        input.extend_from_slice(msg);
        input.push(index);
        hasher.input(input);
        index += 1;
        let mut hashresult = hasher.result();

        let mut r = [0u64; 4];
        // r[0] = hashresult[0] ~ hashresult[7]
        // ...
        // r[3] = hashresult[24] ~ hashresult[31]
        // unset the top bit since r < 2^255
        hashresult[24] &= 0x7F;

        for i in 0..4 {
            for j in 0..8 {
                r[i] <<= 8;
                r[i] += hashresult[i * 4 + j] as u64;
            }
        }
        let res = Fr::from_repr(FrRepr(r));
        if res.is_ok() {
            break res;
        }
    };
    result.unwrap()
}
