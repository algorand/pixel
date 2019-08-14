extern crate pixel;

use pixel::{Pixel, PixelSerDes, PixelSignature};
use rand::Rng;
use std::fs::File;
use std::time::Instant;

fn main() -> std::io::Result<()> {
    const SAMPLES: usize = 10000;

    // this benchmark uses the default parameter
    let param = Pixel::param_default();
    let start = Instant::now();

    for i in 0..SAMPLES {
        let seed = rand::thread_rng()
            .gen_ascii_chars()
            .take(32)
            .collect::<String>();

        let (pk, sk, _pop) = Pixel::key_gen(&seed, &param).unwrap();

        let mut file = File::create(format!("data/sk_bin_{:04?}.txt", i))?;
        sk.serialize(&mut file, true)?;

        let mut file = File::create(format!("data/pk_bin_{:04?}.txt", i))?;
        pk.serialize(&mut file, true)?;

        if i % 100 == 99 {
            let cur = Instant::now();
            let dur = cur.duration_since(start);
            println!("generated {} keys within {} seconds", i+1, dur.as_secs());
        }
    }

    println!("Hello, world!");
    Ok(())
}
