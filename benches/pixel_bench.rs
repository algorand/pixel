// this file benchmarks the core operations of Pixel signature scheme

#[macro_use]
extern crate criterion;
extern crate walkdir;

mod benchmarks;

criterion_main!(
    benchmarks::bench_api::api,
    //    benchmarks::bench_keygen::keys
);

//criterion_main!(benches);

// use Pixel;
// use PixelSignature;
// use super::rand::Rng;
// #[bench]
// fn bench_param_gen(b: &mut test::test::Bencher){
//     const SAMPLES: usize = 1000;
//     let seedlist:Vec<String> = vec![];
//     for _i in 0..SAMPLES{
//         let seed = rand::thread_rng()
//                 .gen_ascii_chars()
//                 .take(32)
//                 .collect::<String>();
//                 seedlist.push(seed);
//     }
//     let mut counter =0;
// b.iter(||{
//     assert!(Pixel::param_gen(seedlist[counter], 0).is_ok());
//     counter = (counter + 1) % SAMPLES;
// })
// }
//
// #[bench]
// fn bench_verification(b: &mut test::test::Bencher) {
//     // used to generate some random time stamp
//     let mut rng = rand::thread_rng();
//
//     let res = Pixel::param_gen("this is a very very long seed for parameter testing", 0);
//     assert!(res.is_ok(), "pixel param gen failed");
//     let pp = res.unwrap();
//
//     let res = Pixel::key_gen("this is a very very long seed for key gen testing", &pp);
//     assert!(res.is_ok(), "pixel key gen failed");
//     let (pk, mut sk) = res.unwrap();
//
//     let sk2 = sk.clone();
//
//     // testing basic signings
//     let msg = "message to sign";
//     let t =
//
//     let res = Pixel::sign(&mut sk, 1, &pp, msg);
//     assert!(res.is_ok(), "error in signing algorithm");
//     let sig = res.unwrap();
//     assert!(Pixel::verify(&pk, 1, &pp, msg, sig), "verification failed");
//     // testing update-then-sign for present
//     for j in 2..16 {
//         let res = Pixel::sk_update(&mut sk, j, &pp);
//         assert!(res.is_ok(), "error in key updating");
//         let res = Pixel::sign(&mut sk, j, &pp, msg);
//         assert!(res.is_ok(), "error in signing algorithm");
//         let sig = res.unwrap();
//         assert!(Pixel::verify(&pk, j, &pp, msg, sig), "verification failed");
//     }
//     // testing signing for future
//     for j in 2..16 {
//         let mut sk3 = sk2.clone();
//         let res = Pixel::sign(&mut sk3, j, &pp, msg);
//         assert!(res.is_ok(), "error in signing algorithm");
//         let sig = res.unwrap();
//         assert!(Pixel::verify(&pk, j, &pp, msg, sig), "verification failed");
//     }
// }
