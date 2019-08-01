//! This is pixel's foreign function interface.
use crate::{PubParam, PublicKey, SecretKey, Signature, PK_LEN, SIG_LEN};
//use std::ffi;
use Pixel;
use PixelSignature;
use SerDes;

#[repr(C)]
pub struct pixel_sk {
    sk: *const u8,
    sk_len: libc::size_t,
}

/// A wrapper that holds the output of key generation function.
#[repr(C)]
pub struct pixel_keys {
    pk: *const u8, // fixed size
    sk: pixel_sk,
    pop: *const u8, // fixed size
}

/// Input a pointer to the seed, and its length.
/// The seed needs to be at least
/// 32 bytes long. Output the key pair.
/// Generate a pair of public keys and secret keys,
/// and a proof of possession of the public key.
#[no_mangle]
pub unsafe extern "C" fn c_keygen(seed: *const u8, seed_len: libc::size_t) -> pixel_keys {
    let pp = PubParam::default();

    // convert a C array `seed` to a rust string `s`
    let s: &[u8] = std::slice::from_raw_parts(seed, seed_len as usize);

    // generate the keys
    let (pk, sk, pop) = match Pixel::key_gen(s, &pp) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: keygen function"),
    };

    // serialize the keys
    let mut pk_buf: Vec<u8> = vec![];
    assert!(
        pk.serialize(&mut pk_buf, true).is_ok(),
        "C wrapper error: keygen function"
    );

    let mut sk_buf: Vec<u8> = vec![];
    assert!(
        sk.serialize(&mut sk_buf, true).is_ok(),
        "C wrapper error: keygen function"
    );

    let mut pop_buf: Vec<u8> = vec![];
    assert!(
        pop.serialize(&mut pop_buf, true).is_ok(),
        "C wrapper error: keygen function"
    );

    // return the pointers to the keys
    pixel_keys {
        pk: pk_buf.as_ptr() as *const u8,
        sk: pixel_sk {
            sk: sk_buf.as_ptr() as *const u8,
            sk_len: sk.get_size(),
        },
        pop: pop_buf.as_ptr() as *const u8,
    }
}

/// Input a secret key, a time stamp that matches the timestamp of the secret key,
/// the public parameter, and a message in the form of a byte string,
/// output a signature. If the time stamp is not the same as the secret key,
/// returns an error
#[no_mangle]
pub unsafe extern "C" fn c_sign_present(
    sk: *const u8,
    sk_len: libc::size_t,
    msg: *const u8,
    msg_len: libc::size_t,
    tar_time: u64,
) -> *const u8 {
    let pp = PubParam::default();

    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msg_len as usize);

    // decompress the secret key
    let mut k_buf: &[u8] = std::slice::from_raw_parts(sk, sk_len as usize);

    let mut k = match SecretKey::deserialize(&mut k_buf) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: key update function"),
    };

    // generate the siganture, and return the pointer
    let sig = match Pixel::sign_present(&mut k, tar_time, &pp, m) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: signing function"),
    };
    let mut sig_buf: Vec<u8> = vec![];
    assert!(
        sig.serialize(&mut sig_buf, true).is_ok(),
        "C wrapper error: signing function"
    );
    sig_buf.as_ptr() as *const u8
}

/// Input a public key, the public parameter, a message in the form of a byte string,
/// and a signature, outputs true if signature is valid w.r.t. the inputs.
#[no_mangle]
pub unsafe extern "C" fn c_verify(
    pk: *const u8,
    msg: *const u8,
    msglen: libc::size_t,
    sig: *const u8,
) -> bool {
    let pp = PubParam::default();

    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msglen as usize);

    // decompress the public key
    let mut k_buf: &[u8] = std::slice::from_raw_parts(pk, PK_LEN as usize);

    let k = match PublicKey::deserialize(&mut k_buf) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: verification function"),
    };

    // decompress the signature
    let mut s_buf: &[u8] = std::slice::from_raw_parts(sig, SIG_LEN as usize);
    let s = match Signature::deserialize(&mut s_buf) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: verification function"),
    };
    Pixel::verify(&k, &pp, m, &s)
}

/// Input a secret key, and a time stamp,
/// return an updated key for that time stamp.
/// Requires a seed for re-randomization.
//
// Ideally we want to be able to mutate the sk as we did
// in the rust implementaion. This is troublesome
// with the wrapper, since in our case sk has
// various length, therefore, we need to pass
// a pointer `p` to the pointer of the secret key blob,
// and set `p` to point to the new secret key after the
// update; and notify the caller the new length of the sk.
// This makes API confusing and complicated.
// So we choose to return the new sk rather than
// mutate the input sk.
#[no_mangle]
pub unsafe extern "C" fn c_sk_update(
    sk: *const u8,
    sk_len: libc::size_t,
    seed: *const u8,
    seed_len: libc::size_t,
    tar_time: u64,
) -> pixel_sk {
    let pp = PubParam::default();
    // convert a C array `seed` to a rust string `s`
    let s: &[u8] = std::slice::from_raw_parts(seed, seed_len as usize);

    // decompress the secret key
    let mut k_buf: &[u8] = std::slice::from_raw_parts(sk, sk_len as usize);
    let mut k = match SecretKey::deserialize(&mut k_buf) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: key update function"),
    };

    // manage the update
    assert!(
        k.update(&pp, tar_time, s).is_ok(),
        "C wrapper error: key update function"
    );

    // serialize the updated sk
    let mut k_buf: Vec<u8> = vec![];
    assert!(
        k.serialize(&mut k_buf, true).is_ok(),
        "C wrapper error: key update function"
    );

    // return the updated sk
    pixel_sk {
        sk: k_buf.as_ptr() as *const u8,
        sk_len: k.get_size(),
    }
}

/// This function aggregates the signatures without checking if a signature is valid or not.
/// It does check that all the signatures are for the same time stamp.
/// It panics if ciphersuite fails or time stamp is not consistent.
#[no_mangle]
pub unsafe extern "C" fn c_aggregation(sig_list: *const u8, sig_num: libc::size_t) -> *const u8 {
    let tmp: &[u8] = std::slice::from_raw_parts(sig_list, sig_num * SIG_LEN);
    let mut sig_buf = tmp.to_vec();

    let mut sig_vec: Vec<Signature> = vec![];

    for i in 0..5 {
        // decompress the signature
        let s = match Signature::deserialize(&mut sig_buf[i * SIG_LEN..(i + 1) * SIG_LEN].as_ref())
        {
            Ok(p) => p,
            Err(_e) => panic!("C wrapper error: signature aggregation function"),
        };

        sig_vec.push(s);
    }
    let agg_sig = match Pixel::aggregate_without_validate(&sig_vec[..]) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: signature aggregation function"),
    };
    let mut sig_buf: Vec<u8> = vec![];
    // serialize the updated sk
    assert!(
        agg_sig.serialize(&mut sig_buf, true).is_ok(),
        "C wrapper error: signature aggregation function"
    );

    // return the aggregated signature
    sig_buf.as_ptr() as *const u8
}
