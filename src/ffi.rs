//! This is pixel's foreign function interface.
use crate::{PubParam, PublicKey, SecretKey, Signature}; //,PublicKey,SecretKey,ProofOfPossession};
                                                        //use std::convert::TryInto;
use std::ffi;
use Pixel;
use PixelSignature;
use SerDes;
#[repr(C)]
pub struct pixel_keys {
    pk: *mut ffi::c_void,
    sk: *mut ffi::c_void,
    pop: *mut ffi::c_void,
}

/// Input a pointer to the seed, and its length.
/// The seed needs to be at least
/// 32 bytes long. Output the key pair.
/// Generate a pair of public keys and secret keys,
/// and a proof of possession of the public key.
#[no_mangle]
pub unsafe extern "C" fn c_keygen(seed: *const u8, seedlen: libc::size_t) -> pixel_keys {
    let pp = PubParam::default();

    // convert a C array `seed` to a rust string `s`
    let s: &[u8] = std::slice::from_raw_parts(seed, seedlen as usize);

    // generate the keys
    let res = Pixel::key_gen(s, &pp);
    assert!(res.is_ok(), "C wrapper error: keygen function");
    let (pk, sk, pop) = res.unwrap();

    // serialize the keys
    let mut pk_buf: Vec<u8> = vec![];
    assert!(
        pk.serialize(&mut pk_buf, true).is_ok(),
        "C wrapper error: keygen function"
    );

    println!("pk with in rust: {:02x?}", pk_buf[..].as_ref());

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
        pk: Box::into_raw(Box::new(pk_buf)) as *mut ffi::c_void,
        sk: Box::into_raw(Box::new(sk_buf)) as *mut ffi::c_void,
        pop: Box::into_raw(Box::new(pop_buf)) as *mut ffi::c_void,
    }
}

/// Input a secret key, a time stamp that matches the timestamp of the secret key,
/// the public parameter, and a message in the form of a byte string,
/// output a signature. If the time stamp is not the same as the secret key,
/// returns an error
#[no_mangle]
pub unsafe extern "C" fn c_sign_present(
    sk: *mut ffi::c_void,
    msg: *const u8,
    msglen: libc::size_t,
    tar_time: u64,
) -> *mut ffi::c_void {
    let pp = PubParam::default();

    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msglen as usize);

    // decompress the secret key
    let k_buf = &mut *(sk as *mut Vec<u8>);
    let mut k = SecretKey::deserialize(&mut k_buf[..].as_ref()).unwrap();

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
    Box::into_raw(Box::new(sig_buf)) as *mut ffi::c_void
}

/// Input a public key, the public parameter, a message in the form of a byte string,
/// and a signature, outputs true if signature is valid w.r.t. the inputs.
#[no_mangle]
pub unsafe extern "C" fn c_verify(
    pk: *const ffi::c_void,
    msg: *const u8,
    msglen: libc::size_t,
    sig: *const ffi::c_void,
) -> bool {
    let pp = PubParam::default();

    // convert a C array `msg` to a rust string `m`
    let m: &[u8] = std::slice::from_raw_parts(msg, msglen as usize);

    // decompress the secret key
    let k_buf = &mut *(pk as *mut Vec<u8>);
    println!("pk with in rust: {:02x?}", k_buf[..].as_ref());

    let k = match PublicKey::deserialize(&mut k_buf[..].as_ref()) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: verification function"),
    };

    // decompress the signature
    let s_buf = &mut *(sig as *mut Vec<u8>);
    let s = match Signature::deserialize(&mut s_buf[..].as_ref()) {
        Ok(p) => p,
        Err(_e) => panic!("C wrapper error: verification function"),
    };
    Pixel::verify(&k, &pp, m, &s)
}

#[no_mangle]
pub unsafe extern "C" fn c_sk_update(
    mut sk: *mut ffi::c_void,
    seed: *const u8,
    seedlen: libc::size_t,
    tar_time: u64,
) {
    let pp = PubParam::default();
    // convert a C array `seed` to a rust string `s`
    let s: &[u8] = std::slice::from_raw_parts(seed, seedlen as usize);

    // decompress the secret key
    let k_buf = &mut *(sk as *mut Vec<u8>);
    let mut k = SecretKey::deserialize(&mut k_buf[..].as_ref()).unwrap();

    assert!(
        k.update(&pp, tar_time, s).is_ok(),
        "C wrapper error: key update function"
    );
    
    sk = Box::into_raw(Box::new(k)) as *mut ffi::c_void;
}
