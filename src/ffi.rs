//! This is pixel's foreign function interface.

// structures
use crate::{Pixel, ProofOfPossession, PubParam, PublicKey, SecretKey, Signature};
// constants
use crate::{CONST_D, PK_LEN, POP_LEN, SIG_LEN};
// traits
use PixelSerDes;
use PixelSignature;

/// A wrapper of sk
#[repr(C)]
#[derive(Debug)]
pub struct pixel_sk {
    data: *mut u8,
    len: libc::size_t,
}

/// A wrapper of pk
#[repr(C)]
pub struct pixel_pk {
    data: [u8; PK_LEN],
}

/// Implement Debug so clippy won't complain.
/// Not really used anywhere.
impl std::fmt::Debug for pixel_pk {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (_i, e) in self.data.iter().enumerate() {
            write!(f, "{:02x}, ", e)?;
        }
        writeln!(f)
    }
}
/// A wrapper of pop
#[repr(C)]
pub struct pixel_pop {
    data: [u8; POP_LEN],
}

/// Implement Debug so clippy won't complain.
/// Not really used anywhere.
impl std::fmt::Debug for pixel_pop {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (_i, e) in self.data.iter().enumerate() {
            write!(f, "{:02x}, ", e)?;
        }
        writeln!(f)
    }
}

/// A wrapper that holds the output of key generation function.
#[repr(C)]
#[derive(Debug)]
pub struct pixel_keys {
    pk: pixel_pk,
    sk: pixel_sk,
    pop: pixel_pop,
}

/// A wrapper of signature
#[repr(C)]
pub struct pixel_sig {
    data: [u8; SIG_LEN],
}

/// Implement Debug so clippy won't complain.
/// Not really used anywhere.
impl std::fmt::Debug for pixel_sig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (_i, e) in self.data.iter().enumerate() {
            write!(f, "{:02x}, ", e)?;
        }
        writeln!(f)
    }
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
        Err(_e) => panic!("C wrapper error: keygen function: key generation"),
    };

    // serialize the keys
    let mut pk_buf: Vec<u8> = vec![];
    assert!(
        pk.serialize(&mut pk_buf, true).is_ok(),
        "C wrapper error: keygen function: serializaing pk"
    );

    let mut sk_buf: Vec<u8> = vec![];
    assert!(
        sk.serialize(&mut sk_buf, true).is_ok(),
        "C wrapper error: keygen function: serializaing sk"
    );

    let mut pop_buf: Vec<u8> = vec![];
    assert!(
        pop.serialize(&mut pop_buf, true).is_ok(),
        "C wrapper error: keygen function: serializaing pop"
    );

    let mut pk_array = [0u8; PK_LEN];
    pk_array.copy_from_slice(&pk_buf);
    let mut pop_array = [0u8; POP_LEN];
    pop_array.copy_from_slice(&pop_buf);

    // shrink the vector sk_buf so that it is encoded
    // as raw memory
    sk_buf.shrink_to_fit();
    assert!(sk_buf.len() == sk_buf.capacity());
    let sk_ptr = sk_buf.as_mut_ptr();
    let sk_len = sk_buf.len();
    // remove the ownership of sk_buf
    // so that when sk_ptr is passed to C
    // rust will not clear the memory
    std::mem::forget(sk_buf);

    // return the keys
    pixel_keys {
        pk: pixel_pk { data: pk_array },
        sk: pixel_sk {
            data: sk_ptr,
            len: sk_len,
        },
        pop: pixel_pop { data: pop_array },
    }
}

/// Input a secret key, a time stamp that matches the timestamp of the secret key,
/// the public parameter, and a message in the form of a byte string,
/// output a signature. If the time stamp is not the same as the secret key,
/// returns an error.
#[no_mangle]
pub unsafe extern "C" fn c_sign_present(
    sk: pixel_sk,
    msg: *const u8,
    msg_len: libc::size_t,
    tar_time: u64,
) -> pixel_sig {
    let pp = PubParam::default();

    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msg_len as usize);

    // load the secret key
    let mut sk_local = std::slice::from_raw_parts(sk.data, sk.len as usize);

    // println!("sk in signature");
    // for i in 0..128 {
    //     print!("{:02x} ", sk_local[i]);
    //     if i % 16 == 15 {
    //         println!();
    //     }
    // }

    let (mut k, _compressed) = match SecretKey::deserialize(&mut sk_local) {
        Ok(p) => p,
        Err(e) => panic!("C wrapper error: signing function: deserialize sk: {}", e),
    };

    // generate the siganture, and return the pointer
    let sig = match Pixel::sign_present(&mut k, tar_time, &pp, m) {
        Ok(p) => p,
        Err(e) => panic!("C wrapper error: signing function: signing: {}", e),
    };

    // serialize the signature
    let mut sig_buf: Vec<u8> = vec![];
    assert!(
        sig.serialize(&mut sig_buf, true).is_ok(),
        "C wrapper error: signing function: serialize signature"
    );
    let mut sig_array = [0u8; SIG_LEN];
    sig_array.copy_from_slice(&sig_buf);
    pixel_sig { data: sig_array }
}

/// Input a public key, the public parameter, a message in the form of a byte string,
/// and a signature, outputs true if signature is valid w.r.t. the inputs.
#[no_mangle]
pub unsafe extern "C" fn c_verify(
    pk: pixel_pk,
    msg: *const u8,
    msglen: libc::size_t,
    sig: pixel_sig,
) -> bool {
    let pp = PubParam::default();

    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msglen as usize);

    // decompress the public key
    let mut k_buf = pk.data.to_vec();

    let (k, _compressed) = match PublicKey::deserialize(&mut k_buf[..].as_ref()) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: verification function: deserialize pk: {}",
            e
        ),
    };

    // decompress the signature
    let mut s_buf = sig.data.to_vec();
    let (s, _compressed) = match Signature::deserialize(&mut s_buf[..].as_ref()) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: verification function: deserialize signature: {}",
            e
        ),
    };
    Pixel::verify(&k, &pp, m, &s)
}

/// Input a secret key, and a time stamp,
/// return an updated key for that time stamp.
/// Requires a seed for re-randomization.
//
#[no_mangle]
pub unsafe extern "C" fn c_sk_update(
    sk: pixel_sk,
    seed: *const u8,
    seed_len: libc::size_t,
    tar_time: u64,
) -> pixel_sk {
    let pp = PubParam::default();
    // convert a C array `seed` to a rust string `s`
    let s: &[u8] = std::slice::from_raw_parts(seed, seed_len as usize);

    // decompress the secret key
    let mut sk_local = std::slice::from_raw_parts(sk.data, sk.len as usize);
    let (mut k, _compressed) = match SecretKey::deserialize(&mut sk_local) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: key update function: deserialize sk: {}",
            e
        ),
    };

    // manage the update
    assert!(
        k.update(&pp, tar_time, s).is_ok(),
        "C wrapper error: key update function: key update"
    );

    // serialize the updated sk
    let mut k_buf: Vec<u8> = vec![];
    assert!(
        k.serialize(&mut k_buf, true).is_ok(),
        "C wrapper error: key update function: serialize sk"
    );
    // for i in 0..128 {
    //     print!("{:02x?}, ", k_buf[i]);
    //     if i % 16 == 15 {
    //         println!();
    //     }
    // }

    // shrink the vector sk_buf so that it is encoded
    // as raw memory
    k_buf.shrink_to_fit();
    assert!(k_buf.len() == k_buf.capacity());
    let sk_ptr = k_buf.as_mut_ptr();
    let sk_len = k_buf.len();
    // remove the ownership of sk_buf
    // so that when sk_ptr is passed to C
    // rust will not clear the memory
    std::mem::forget(k_buf);

    pixel_sk {
        data: sk_ptr,
        len: sk_len,
    }
}

/// This function aggregates the signatures without checking if a signature is valid or not.
/// It does check that all the signatures are for the same time stamp.
/// It panics if ciphersuite fails or time stamp is not consistent.
#[no_mangle]
pub unsafe extern "C" fn c_aggregation(
    sig_list: *mut pixel_sig,
    sig_num: libc::size_t,
) -> pixel_sig {
    let sig_list: &[pixel_sig] = std::slice::from_raw_parts(sig_list as *mut pixel_sig, sig_num);

    let mut sig_vec: Vec<Signature> = vec![];

    for sig in sig_list.iter().take(sig_num) {
        // decompress the signature
        let (s, _compressed) = match Signature::deserialize(&mut sig.data.as_ref()) {
            Ok(p) => p,
            Err(e) => panic!(
                "C wrapper error: signature aggregation function: deserialize signature: {}",
                e
            ),
        };

        sig_vec.push(s);
    }
    let agg_sig = match Pixel::aggregate_without_validate(&sig_vec[..]) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: signature aggregation function: aggregation: {}",
            e
        ),
    };
    let mut sig_buf: Vec<u8> = vec![];
    // serialize the updated sk
    assert!(
        agg_sig.serialize(&mut sig_buf, true).is_ok(),
        "C wrapper error: signature aggregation function: deserialize signature"
    );

    // return the aggregated signature
    let mut sig_array = [0u8; SIG_LEN];
    sig_array.copy_from_slice(&sig_buf);
    pixel_sig { data: sig_array }
}

/// This function verifies the aggregated signature
#[no_mangle]
pub unsafe extern "C" fn c_verify_agg(
    pk_list: *mut pixel_pk,
    pk_num: libc::size_t,
    msg: *const u8,
    msglen: libc::size_t,
    agg_sig: pixel_sig,
) -> bool {
    let pp = PubParam::default();
    let pk_list: &[pixel_pk] = std::slice::from_raw_parts(pk_list as *mut pixel_pk, pk_num);
    let mut pk_vec: Vec<PublicKey> = vec![];

    for pk in pk_list.iter().take(pk_num) {
        // decompress the signature
        let (s, _compressed) = match PublicKey::deserialize(&mut pk.data.as_ref()) {
            Ok(p) => p,
            Err(e) => panic!(
                "C wrapper error: signature aggregation function: deserialize signature: {}",
                e
            ),
        };

        pk_vec.push(s);
    }
    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msglen as usize);

    // decompress the signature
    let mut s_buf = agg_sig.data.to_vec();
    let (sig, _compressed) = match Signature::deserialize(&mut s_buf[..].as_ref()) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: verification function: deserialize signature: {}",
            e
        ),
    };

    Pixel::verify_aggregated(pk_vec[..].as_ref(), &pp, m, &sig)
}

/// This function verifies the public key against the proof of possession
#[no_mangle]
pub extern "C" fn c_verify_pop(pk: pixel_pk, pop: pixel_pop) -> bool {
    // decompress the public key
    let mut k_buf = pk.data.to_vec();

    let (k, _compressed) = match PublicKey::deserialize(&mut k_buf[..].as_ref()) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: PoP verification function: deserialize pk: {}",
            e
        ),
    };

    // decompress the pop
    let mut pop_buf = pop.data.to_vec();

    let (p, _compressed) = match ProofOfPossession::deserialize(&mut pop_buf[..].as_ref()) {
        Ok(p) => p,
        Err(e) => panic!(
            "C wrapper error: PoP verification function: deserialize pop: {}",
            e
        ),
    };

    Pixel::verify_pop(&k, &p)
}

/// This function returns the storage requirement for the secret key
/// for a particular time stamp.
#[no_mangle]
pub extern "C" fn c_estimate_sk_size(time: u64, depth: libc::size_t) -> libc::size_t {
    match SecretKey::estimate_size(time, depth as usize) {
        Ok(p) => p,
        Err(e) => panic!("C wrapper error: estimating sk size: {}", e),
    }
}

/// This function returns the depth of time tree.
#[no_mangle]
pub extern "C" fn c_get_depth() -> libc::size_t {
    CONST_D
}
