use pixel::{Pixel, PixelSignature, SerDes};
use std::fs::File;
use std::io::prelude::*;

// This function generates test vectors for pixel signature scheme.
// * data in _plain.txt files are stored in plain mode
// * data in _bin.txt files are stored in serialized mode
fn main() -> std::io::Result<()> {
    // default parameter
    let pp = Pixel::param_default();
    let mut file = File::create("test_vector/param_plain.txt")?;
    file.write_all(format!("{:?}", pp).as_ref())?;
    let mut file = File::create("test_vector/param_bin.txt")?;
    pp.serialize(&mut file, false)?;

    // the default seed to generate the keys is
    //  "this is a very long seed for pixel tests"
    let seed = "this is a very long seed for pixel tests";
    let rngseed = "";
    let timestamp = 1;
    let (pk, mut sk, pop) = Pixel::key_gen(seed, &pp).unwrap();
    let sk2 = sk.clone();

    let mut file = File::create("test_vector/pk_plain.txt")?;
    file.write_all(format!("{:?}", pk).as_ref())?;
    let mut file = File::create("test_vector/pk_bin.txt")?;
    pk.serialize(&mut file, true)?;

    let mut file = File::create("test_vector/pop_plain.txt")?;
    file.write_all(format!("{:?}", pop).as_ref())?;
    let mut file = File::create("test_vector/pop_bin.txt")?;
    pop.serialize(&mut file, true)?;

    // generating test vectors for sk updates and signatures
    // we start to generate a sequence of secret keys with an increment of 1
    let mut file = File::create(format!("test_vector/sk_plain_{:02?}.txt", timestamp))?;
    file.write_all(format!("{:?}", sk).as_ref())?;
    let mut file = File::create(format!("test_vector/sk_bin_{:02?}.txt", timestamp))?;
    sk.serialize(&mut file, true)?;

    // now, use the secret key to sign a message
    //  "this is the message we want pixel to sign"
    let msg = "this is the message we want pixel to sign";
    let sig = Pixel::sign_present(&mut sk, 1, &pp, msg).unwrap();
    assert!(Pixel::verify(&pk, &pp, msg, &sig));

    let mut file = File::create(format!("test_vector/sig_plain_{:02?}.txt", timestamp))?;
    file.write_all(format!("{:?}", sig).as_ref())?;
    let mut file = File::create(format!("test_vector/sig_bin_{:02?}.txt", timestamp))?;
    sig.serialize(&mut file, true)?;

    // update the key from time 1 to time 64, sequentially
    // and use the key to sign the message
    for i in 2..64 {
        assert!(Pixel::sk_update(&mut sk, i as u64, &pp, rngseed).is_ok());
        let sig = Pixel::sign_present(&mut sk, i as u64, &pp, msg).unwrap();
        assert!(Pixel::verify(&pk, &pp, msg, &sig));

        let mut file = File::create(format!("test_vector/sk_plain_{:02?}.txt", i))?;
        file.write_all(format!("{:?}", sk).as_ref())?;
        let mut file = File::create(format!("test_vector/sk_bin_{:02?}.txt", i))?;
        sk.serialize(&mut file, true)?;

        let mut file = File::create(format!("test_vector/sig_plain_{:02?}.txt", i))?;
        file.write_all(format!("{:?}", sig).as_ref())?;
        let mut file = File::create(format!("test_vector/sig_bin_{:02?}.txt", i))?;
        sig.serialize(&mut file, true)?;
    }

    // next, we try some deterministic `fast forward` updates
    // by jumping from current sk to sk+i
    // and use the key to sign the message
    let mut sk = sk2.clone();
    for i in 2..64 {

        let cur_time = sk.time();
        let tar_time = cur_time + i as u64;

        assert!(Pixel::sk_update(&mut sk, tar_time, &pp, rngseed).is_ok());
        let sig = Pixel::sign_present(&mut sk, tar_time, &pp, msg).unwrap();
        assert!(Pixel::verify(&pk, &pp, msg, &sig));

        let mut file = File::create(format!("test_vector/sk_plain_ff_{:04?}_{:04}.txt", cur_time,tar_time))?;
        file.write_all(format!("{:?}", sk).as_ref())?;
        let mut file = File::create(format!("test_vector/sk_bin_ff_{:04?}_{:04}.txt", cur_time,tar_time))?;
        sk.serialize(&mut file, true)?;

        let mut file = File::create(format!("test_vector/sig_plain_ff_{:04?}_{:04}.txt", cur_time,tar_time))?;
        file.write_all(format!("{:?}", sig).as_ref())?;
        let mut file = File::create(format!("test_vector/sig_bin_ff_{:04?}_{:04}.txt", cur_time,tar_time))?;
        sig.serialize(&mut file, true)?;
    }

    println!("Hello, world!");
    Ok(())
}
