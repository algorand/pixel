
use ff::PrimeField;
use pairing::{bls12_381::Fr, CurveProjective};
use param::PubParam;
use param::CONST_D;
use std::fmt::Error;
use subkeys::SubSecretKey;
use time::{TimeStamp, TimeVec};

use PixelG1;
use PixelG2;

use std::fmt;
use util;

#[cfg(test)]
use pairing::CurveAffine;

#[cfg(test)]
use ff::Field;
#[cfg(test)]
use pairing::{bls12_381::*, Engine};

/// the keypair is a pair of public and secret keys
#[derive(Debug, Clone)]
pub struct KeyPair {
    sk: SecretKey,
    pk: PixelG2,
}

/// the secret key is a list of SubSecretKeys
/// the length is arbitrary
#[derive(Clone)]
pub struct SecretKey {
    /// smallest timestamp for all subkeys
    time: TimeStamp,

    /// the list of the subkeys
    ssk: Vec<SubSecretKey>,
}

impl KeyPair {
    /// generate a pair of public keys and secret keys
    //  todo: decide the right way to hash the seed into master secret
    //        perhaps hash_to_field function?
    pub fn keygen(seed: &[u8], pp: &PubParam) -> Self {
        let (pk, msk) = master_key_gen(seed, &pp);
        let sk = SecretKey::init(&pp, msk);
        Self { sk: sk, pk: pk }
    }
}

impl SecretKey {
    /// initialize the secret key at time stamp = 1
    /// take the root secret alpha as the input
    pub fn init(pp: &PubParam, alpha: PixelG1) -> Self {
        // todo: replace 2 with a (deterministic) random r
        let r = Fr::from_str("2").unwrap();
        let ssk = SubSecretKey::init(&pp, alpha, r);
        SecretKey {
            time: 1,
            ssk: vec![ssk],
        }
    }
    /// return the current time stamp for the key
    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    /// return the number of sub_secret_keys
    pub fn get_ssk_number(&self) -> usize {
        self.ssk.len()
    }

    /// update the secret key
    /// this function mutate the existing secret keys to the time stamp
    /// it panics if the new time stamp is invalid
    pub fn update(&mut self, pp: &PubParam, tar_time: TimeStamp) {
        // max time = 2^d - 1
        let max_time = (1u64 << CONST_D) - 1;
        let cur_time = self.get_time();
        if cur_time >= tar_time || tar_time > max_time {
            panic!("the input time {} is invalid", tar_time);
        }

        // we iterate through all ssk-s, and find the largest time
        // that is samller than the target time
        // e.g.
        //  * d = 4,
        //  * cur_time = 3,
        //  * tar_time = 12
        // ssk_vec must have the ssk-s for time 3, 6, 9,
        // we remove ssk_for_t_2, and use ssk_for_t_9 to delegate to ssk_for_t_12 and ssk_for_t_13

        // step 1. find the right ssk from ssk_vec to delegate from
        // (e.g., find ssk_for_t_9)
        // and update self to that TimeStamp
        let delegator_time = self.get_close_ssk(tar_time);
        self.time = delegator_time;

        // automatically turned off with `build --release`
        #[cfg(debug_assertions)]
        println!(
            "delegating from {} to {} using delegator time {}",
            self.get_time(),
            tar_time,
            delegator_time
        );

        while self.ssk[0].get_time() != delegator_time {
            self.ssk.remove(0);
        }
        assert!(self.ssk.len() > 0, "something is wrong: no ssk left");

        // step 2. if delegator_time == tar_time then we are done
        // the reminder of the sub secret keys happens to form
        // a new secret key for the tar_time
        if delegator_time == tar_time {
            return;
        }

        // step 3. from delegator to target time
        // from a delegator vector, e.g., [1] to a target vector, e.g. [1,1,1]
        // we will need [1,1,1], [1,1,2], [1,2], [2]
        // i.e. all the vectors that [1] is a pre-fix of
        // this was referred to as "gamma list"
        let delegator_time_vec = TimeVec::init(tar_time, CONST_D as u32);
        let gamma_list = delegator_time_vec.gamma_list();

        // step 4. delegate the first ssk in the ssk_vec to the gamma_list
        // note: we don't need to modify other ssks in the current ssk_vec
        'out: for i in 0..gamma_list.len() {
            // if the key already exist, for example, key for [2]
            // we do not delegate
            // since ssk are sorted chronologically
            // we only need to check from i+1 keys for duplications
            for j in i + 1..self.ssk.len() {
                if gamma_list[i] == self.ssk[j].get_time_vec() {
                    continue 'out;
                }
            }

            // delegation
            let mut new_ssk = self.ssk[0].clone();
            new_ssk.delegate(gamma_list[i].get_time());

            // randomize the new ssk unless it is the first one
            // for the first one we reuse the randomness
            if i != 0 {
                // TODO: change to a random field element
                let r = Fr::from_str("2").unwrap();
                new_ssk.randomization(&pp, r)
            }

            // insert the key to the right place so that
            // all ssk-s are sorted chronologically
            self.ssk.insert(i + 1, new_ssk);
        }

        // step 5. remove the first ssk <- this was the ssk for delegator time
        self.ssk.remove(0);

    }

    /// iterate through the existing sub secret keys, find the one for which
    /// 1. the time stamp is the greatest within existing sub_secret_keys
    /// 2. the time stamp is no greater than tar_time
    /// e.g.:
    ///     sk {time: 2, ssks: {omited}}
    ///     sk.get_close_ssk(2, 12) = 9
    /// returns a pointer to this subsecretkey
    fn get_close_ssk(&self, tar_time: TimeStamp) -> TimeStamp {
        let mut res = &self.ssk[0];
        if res.get_time() >= tar_time {
            panic!("the input time {} is invalid", tar_time);
        }

        for i in 0..self.ssk.len() - 1 {
            if self.ssk[i + 1].get_time() <= tar_time {
                res = &self.ssk[i + 1];
            }
        }
        res.get_time()
    }
}

/// this function generates the master key pair from a seed
/// this function is private -- it should be used only as a subroutine to key gen function
//  todo: decide the right way to hash the seed into master secret
//        perhaps hash_to_field function?
fn master_key_gen(seed: &[u8], pp: &PubParam) -> (PixelG2, PixelG1) {
    // make sure we have enough entropy
    assert!(
        seed.len() > 31,
        "the seed length {} is not long enough (required as least 32 bytes)",
        seed.len()
    );
    // hash_to_field(msg, ctr, p, m, hash_fn, hash_reps)
    //  msg         <- seed
    //  ctr         <- incremantal from 0
    //  p           <- group order, implied
    //  m           <- 1; since we are working on F_{r^1}
    //  hash_fn     <- Sha256
    //  hash_reps   <- 2; requires two sha256 runs to get uniform mod p elements

    let r: Vec<Fr> = util::HashToField::hash_to_field(seed, 0, 1, util::HashIDs::Sha256, 2);

    // pk = g2^r
    // sk = h^r
    let mut pk = pp.get_g2();
    let mut sk = pp.get_h();
    pk.mul_assign(r[0]);
    sk.mul_assign(r[0]);
    (pk, sk)
}

/// this function tests if a public key and a master secret key has a same exponent
#[cfg(test)]
fn validate_master_key(pk: &PixelG2, sk: &PixelG1, pp: &PubParam) -> bool {
    let mut g2 = pp.get_g2();
    g2.negate();
    let h = pp.get_h();

    // check e(pk, h) ?= e(g2, sk)
    // which is e(pk,h) * e(-g2,sk) == 1
    #[cfg(feature = "pk_in_g2")]
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (&(sk.into_affine().prepare()), &(g2.into_affine().prepare())),
            (&(h.into_affine().prepare()), &(pk.into_affine().prepare())),
        ]
        .into_iter(),
    ))
    .unwrap();
    #[cfg(not(feature = "pk_in_g2"))]
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (&(g2.into_affine().prepare()), &(sk.into_affine().prepare())),
            (&(pk.into_affine().prepare()), &(h.into_affine().prepare())),
        ]
        .into_iter(),
    ))
    .unwrap();

    // verification is successful if
    //   pairingproduct == 1
    pairingproduct
        == Fq12 {
            c0: Fq6::one(),
            c1: Fq6::zero(),
        }
}

#[test]
fn test_master_key() {
    let pp = PubParam::init_without_seed();
    let (pk, sk) = master_key_gen(b"this is a very very long seed for testing", &pp);
    assert!(validate_master_key(&pk, &sk, &pp), "master key is invalid")
}

#[test]
fn test_keypair() {
    let pp = PubParam::init_without_seed();
    let keypair = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    println!("{:?}", keypair);
}

#[test]
fn test_key_update() {
    let pp = PubParam::init_without_seed();
    let keypair = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
    let sk = keypair.sk;

    // this double loop
    // 1. performs key updates with all possible `start_time` and `finish_time`
    // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
    for j in 2..16 {
        let mut sk2 = sk.clone();
        sk2.update(&pp, j);
        for i in j + 1..16 {
            let mut sk3 = sk2.clone();
            sk3.update(&pp, i);

            #[cfg(long_tests)]
            for ssk in sk3.ssk {
                assert!(ssk.validate(&keypair.pk, &pp), "validation failed");
            }
        }

        #[cfg(long_tests)]
        for ssk in sk2.ssk {
            assert!(ssk.validate(&keypair.pk, &pp), "validation failed");
        }
    }
}

/// convenient function to output a subsecretkey object
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "================================\ntime:{:?}", self.time)?;
        for i in 0..self.ssk.len() {
            write!(
                f,
                "========{}-th subkey============\n{:#?}\n",
                i, self.ssk[i]
            )?;
        }
        write!(f, "================================\n")
    }
}
