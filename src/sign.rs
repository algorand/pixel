use pairing::{bls12_381::*, CurveProjective, EncodedPoint, Engine};

use param::PublicKey;
use param::RootSecret;
use param::SecretKey;
use param::SubSecretKey;
use param::{PubParam, CONST_D};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
use subkeys::SSKAlgorithm;




//pub type Signature = [G2; 2];
pub struct Signature {
    sigma1: G1,
    sigma2: G2,
}


pub trait SKAlgorithm {
    fn init() -> Self;

    fn sign<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        vec_t: &Vec<Fr>,
        msg: &Fr,
        rng: &mut R,
    ) -> Signature;

    // this function uses root secret key to sign
//    fn sign_raw<R: ::rand::Rng>(&self, pp: &PubParam, msg: &Fr, rng: &mut R) -> Signature;

    // update a list of secret keys into a new list of public Keys
//    fn update_key<R: ::rand::Rng>(&self, pp: &PubParam, vec_t: &Vec<Fr>, rng: &mut R) -> SecretKey;

    fn print(&self);
}

impl SKAlgorithm for SecretKey {
    fn init() -> Self {
        Vec::new()
    }

    fn sign<R: ::rand::Rng>(
        &self,
        pp: &PubParam,
        vec_t: &Vec<Fr>,
        msg: &Fr,
        rng: &mut R,
    ) -> Signature
    {
        
    }

    // fn sign_raw<R: ::rand::Rng>(&self, pp: &PubParam, msg: &Fr, rng: &mut R) -> Signature {
    //     let s = self[0].partial_delegate(pp, &vec![*msg], rng);
    //     s.two_elements
    // }
    //
    // fn sign<R: ::rand::Rng>(
    //     &self,
    //     pp: &PubParam,
    //     vec_t: &Vec<Fr>,
    //     msg: &Fr,
    //     rng: &mut R,
    // ) -> Signature {
    //     let mut tmp = vec_t.clone();
    //     tmp.push(*msg);
    //     let s = self[0].partial_delegate(pp, &tmp, rng);
    //     s.two_elements
    // }

    // fn update_key<R: ::rand::Rng>(&self, pp: &PubParam, vec_t: &Vec<Fr>, rng: &mut R) -> SecretKey {
    //     let mut newsklist: SecretKey = Vec::new();
    //
    //     for ssk in self {
    //         let gamma_t = gamma_t_fr(vec_t);
    //         for new_vec in gamma_t {
    //             let tmp = ssk.delegate(&pp, &new_vec, rng);
    //             newsklist.push(tmp)
    //         }
    //     }
    //     newsklist
    // }

    fn print(&self) {
        println!("==============");
        println!("==secret key==");
        for ssk in self {
            ssk.print();
        }
        println!("==============\n");
    }
}
