extern crate ff;
extern crate pairing;
extern crate rand;
mod initkey;
mod keys;
mod param;
use ff::{Field, PrimeField};
use initkey::{InitKey, InitKeyAlgorithm};
use keys::Keys;
use keys::{KeysAlgorithm, SSKAlgorithm};
use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine};

use param::SecretKey;
use param::SubSecretKey;
use param::{PubParam, *};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
//use keys::KeysAlgorithm;

//mod sig;
//mod subkeys;
fn main() {
    let pp: PubParam = PubParam::init_with_w_and_seed(&[42; 4]);
    //    let k: (RootSecret, PublicKey) = KeysAlgorithm::key_gen_alpha();
    let k: Keys = KeysAlgorithm::root_key_gen(&pp);
    let rs: InitKey = InitKeyAlgorithm::key_gen_alpha();
    println!("{:#?}", pp);
    println!("{:#?}", k);
    println!("{:#?}", rs);
    println!("Hello, world!");
}
