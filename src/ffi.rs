//! This is pixel's foreign function interface.
use crate::PubParam; //,PublicKey,SecretKey,ProofOfPossession};
use std::convert::TryInto;
use Pixel;
use PixelSignature;
use SerDes;

/// This function returns the serialized default parameter.
#[no_mangle]
pub unsafe extern "C" fn c_keygen(
    pk_ptr: &mut [u8],
    seed: *const u8, seedlen: libc::size_t) {
    println!("seed: {}", seedlen);
    for i in 0..seedlen {
        print!("{:02x}, ", *seed.offset(i.try_into().unwrap()))
    }
    println!("");

    // make sure the input seed is valid
    assert!(!seed.is_null(), "Null pointer to the seed");
    assert!(seedlen > 0, "Incorrect memory length of seed");

    let pp = PubParam::default();

    // convert a C array `seed` to a rust string `s`
    let s: &[u8] = std::slice::from_raw_parts(seed, seedlen as usize);
    let res = Pixel::key_gen(s, &pp);
    assert!(res.is_ok());
    let (pk, sk, pop) = res.unwrap();

    let mut pk_buf: Vec<u8> = vec![];
    assert!(pk.serialize(&mut pk_buf, true).is_ok());

    let mut sk_buf: Vec<u8> = vec![];
    assert!(sk.serialize(&mut sk_buf, true).is_ok());

    let mut pop_buf: Vec<u8> = vec![];
    assert!(pop.serialize(&mut pop_buf, true).is_ok());

    println!("seed:");
    for i in 0..seedlen {
        print!("{:02x}, ", *seed.offset(i.try_into().unwrap()))
    }
    println!("");
    println!("pk: {:02x?}", pk_buf);

    pk_ptr.copy_from_slice (&pk_buf)

    // [
    //     pk_buf.as_mut_ptr(),
    //     sk_buf.as_mut_ptr(),
    //     pop_buf.as_mut_ptr(),
    // ]
}
