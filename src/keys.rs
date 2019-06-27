// functions for
//  * the key pair
//  * the public key
//  * the secret key <- the sub secret keys are defined seperately in subkeys module

use ff::PrimeField;
use pairing::{bls12_381::Fr, CurveProjective};
use param::PubParam;
use std::fmt;
pub use subkeys::SubSecretKey;
use time::{TimeStamp, TimeVec};
use util;
use PixelG1;
use PixelG2;

/// The public key structure is a wrapper of PixelG2 group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone)]
pub struct PublicKey {
    pk: PixelG2,
}

impl PublicKey {
    /// Initialize the PublicKey with a given pk.
    pub fn init(pk: PixelG2) -> Self {
        PublicKey { pk: pk }
    }

    /// Set self to the new public key.
    pub fn set_pk(&mut self, pk: PixelG2) {
        self.pk = pk
    }

    /// Returns the public key element this structure contains.
    pub fn get_pk(&self) -> PixelG2 {
        self.pk
    }
}
// pub type PublicKey = PixelG2;

/// The keypair is a pair of public and secret keys.
#[derive(Debug, Clone)]
pub struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

/// The secret key is a list of SubSecretKeys;
/// the length of the list can be arbitrary;
/// they are arranged in a chronological order.
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
    pub fn keygen(seed: &[u8], pp: &PubParam) -> Result<Self, String> {
        let (pk, msk) = match master_key_gen(seed, &pp) {
            Err(e) => return Err(e),
            Ok(f) => f,
        };
        let sk = SecretKey::init(&pp, msk);
        let pk = PublicKey::init(pk);
        Ok(Self { sk: sk, pk: pk })
    }

    /// Returns the public key in a `KeyPair`
    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }

    /// Returns the secret key in a `KeyPair`
    pub fn get_sk(&self) -> SecretKey {
        self.sk.clone()
    }
}

impl SecretKey {
    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` as the input.
    pub fn init(pp: &PubParam, alpha: PixelG1) -> Self {
        // todo: replace 2 with a (deterministic) random r
        let r = Fr::from_str("2").unwrap();
        let ssk = SubSecretKey::init(&pp, alpha, r);
        SecretKey {
            time: 1,
            ssk: vec![ssk],
        }
    }

    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` and a field element `r` as inputs.
    /// Currently this function is used by testing only.
    #[cfg(test)]
    pub fn init_det(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
        let ssk = SubSecretKey::init(&pp, alpha, r);
        SecretKey {
            time: 1,
            ssk: vec![ssk],
        }
    }

    /// Returns the current time stamp for the key.
    pub fn get_time(&self) -> TimeStamp {
        self.time
    }

    /// Returns the number of sub_secret_keys.
    pub fn get_ssk_number(&self) -> usize {
        self.ssk.len()
    }

    /// Returns the first sub secret key on the list.
    /// Panics if the list is empty.
    pub fn get_first_ssk(&self) -> SubSecretKey {
        assert!(self.ssk.len() > 0, "sub secret key list is empty!");
        self.ssk[0].clone()
    }

    #[cfg(test)]
    /// Returns the whole list of the sub secret keys.
    /// This function is only used for testing.
    pub fn get_ssk_vec(&self) -> Vec<SubSecretKey> {
        self.ssk.clone()
    }

    /// Updates the secret key into the corresponding time stamp.
    /// This function mutate the existing secret keys to the time stamp.
    /// It panics if the new time stamp is invalid (either smaller than
    /// current time or larger than maximum time stamp).
    pub fn update<'a>(&'a mut self, pp: &PubParam, tar_time: TimeStamp) -> Result<(), String> {
        // make a clone of self, in case an error is raised, we do not want to mutate the key
        // the new_sk has a same life time as the old key
        let mut new_sk = self.clone();

        // max time = 2^d - 1
        let depth = pp.get_d();
        let max_time = (1u64 << depth) - 1;
        let cur_time = new_sk.get_time();
        if cur_time >= tar_time || tar_time > max_time {
            #[cfg(debug_assertions)]
            println!("the input time {} is invalid", tar_time);

            return Err("the input time is invalid".to_owned());
        }

        // an example of sk-s with depth = 4:
        //  sk_1 = {1, [ssk_for_t_1]}                                   // time vector = []
        //  sk_2 = {2, [ssk_for_t_2, ssk_for_t_9]}                      // time vector = [1], [2]
        //  sk_3 = {3, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9]}         // time vector = [1,1], [1,2], [2]
        //  sk_4 = {4, [ssk_for_t_4, ssk_for_t_5, ssk_for_t_6,          // time vector = [1,1,1], [1,1,2], [1,2], [2]
        //              ssk_for_t_9]}
        //  sk_5 = {5, [ssk_for_t_5, ssk_for_t_6, ssk_for_t_9]}         // time vector = [1,1,2], [1,2], [2]
        //  sk_6 = {6, [ssk_for_t_6, ssk_for_t_9]}                      // time vector = [1,2], [2]
        //  sk_7 = {7, [ssk_for_t_7, ssk_for_t_8, ssk_for_t_9]}         // time vector = [1,2,1], [1,2,2], [2]
        //  sk_8 = {8, [ssk_for_t_8, ssk_for_t_9]}                      // time vector = [1,2,2], [2]
        //  sk_9 = {9, [ssk_for_t_9]}                                   // time vector = [2]
        //  sk_10 = {10, [ssk_for_t_10, ssk_for_t_13]}                  // time vector = [2,1], [2,2]
        //  sk_11 = {11, [ssk_for_t_11, ssk_for_t_12, ssk_for_t_13]}    // time vector = [2,1,1], [2,1,2], [2,2]
        //  sk_12 = {12, [ssk_for_t_12, ssk_for_t_13]}                  // time vector = [2,1,2], [2,2]
        //  sk_13 = {13, [ssk_for_t_13]}                                // time vector = [2,2]
        //  sk_14 = {14, [ssk_for_t_14, ssk_for_t_15]}                  // time vector = [2,2,1], [2,2,2]
        //  sk_15 = {15, [ssk_for_t_15]}                                // time vector = [2,2,2]

        //
        // we iterate through all ssk-s, and find the largest time
        // that is samller than the target time, this ssk will be the ancestor node
        // to the target time
        //
        // Example 1, at a high level
        //  * d = 4,
        //  * cur_time = 3,
        //  * tar_time = 12
        // the current sk is
        //
        //  ### new_sk = {3, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9]}  // time vector = [1,1], [1,2], [2] ###
        //
        // the ancestor node of 12 ([2,1,2]) will be 9 ([2])
        // therefore, we remove ssk_for_t_3, ssk_for_t_6 from new_sk
        // and use ssk_for_t_9 to delegate to ssk_for_t_12 and ssk_for_t_13
        //
        // step 1. find the ancestor ssk from ssk_vec to delegate from
        // e.g., find ssk_for_t_9 from the list [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9].
        // this is because 9 ([2]) is an ancestor (a.k.a. pre-fix) of 12 ([2,1,2]).
        // we update new_sk from sk3 = {3, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9] to
        //
        // ### new_sk = {9, [ssk_for_t_9]}   // time vector = [2] ###
        //
        // as follows
        let delegator_time = match new_sk.find_ancestor(tar_time) {
            Err(e) => return Err(e),
            Ok(p) => p,
        };
        // step 1.1 update new_sk's time stamp
        // the current sk is ### new_sk = {9, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9]} ###
        new_sk.time = delegator_time;

        #[cfg(debug_assertions)]
        println!(
            "delegating from {} to {} using delegator time {}",
            new_sk.get_time(),
            tar_time,
            delegator_time
        );

        // step 1.2 udpate sk to delegator_time by removing all ssk-s
        // whose time stamp is less than delegator's time
        // this effectively sets the new_sk to the secret key for time stamp = delegator_time
        // i.e. we remove ssk_for_t_3, ssk_for_t_6 from new_sk
        // now
        //
        // ### new_sk = {9, [ssk_for_t_9]} ###
        //
        // which is indeed sk_9
        while new_sk.ssk[0].get_time() != delegator_time {
            new_sk.ssk.remove(0);
        }

        // there should always be at least one key left
        #[cfg(debug_assertions)]
        assert!(new_sk.ssk.len() > 0, "something is wrong: no ssk left");
        if new_sk.ssk.len() == 0 {
            return Err("something is wrong: no ssk left".to_owned());
        }

        // step 2. if delegator_time == tar_time then we are done
        // the reminder of the sub secret keys happens to form
        // a new secret key for the tar_time
        // i.e., if we were to delegate to sk_9 then we can simply return
        //
        // ### new_sk = {9, [ssk_for_t_9]}  // time vector = [2] ###
        //
        if delegator_time == tar_time {
            // assign new_sk to self, and return successful
            // here we rely on Rust's memory safety feature to ensure the old key is erased
            *self = new_sk;
            return Ok(());
        }

        // step 3. from delegator to target time
        //
        // Example 1:
        // this is what happens with the running example.
        // we have
        //
        // ### new_sk = sk_9 = {9,[ssk_for_t_9]}    // time vector = [2] ###
        //
        // we get the gamma list of t = 12, which is {[2,1,2], [2,2]}
        // we use ssk_for_t_9 to delegate to ssk_for_t_12 and ssk_for_t_13 via
        //
        //  [2] -> [2,1,2]  with randomness reuse
        //  [2] -> [2,2]    with new randomness
        //
        //
        // Example 2:
        // we use a slightly different example here to show that some ssk-s remains unchanged
        // suppose we want to delegate from time = 2 to time = 4 where
        //
        //  sk_2 = {2, [ssk_for_t_2, ssk_for_t_9]}                      // time vector = [1], [2]
        //  sk_4 = {4, [ssk_for_t_4, ssk_for_t_5, ssk_for_t_6,          // time vector = [1,1,1], [1,1,2], [1,2], [2]
        //
        // the delegation will happen as follows, where the randomness is always reused for the
        // first delegation
        //  [1] -> [1,1,1]  with randomness reuse
        //  [1] -> [1,1,2]  with new randomness
        //  [1] -> [1,2]    with new randomness
        // the ssk for [2] already exists in current sk; it remains unchanged
        let target_time_vec = TimeVec::init(tar_time, depth);
        let gamma_list = target_time_vec.gamma_list(depth);

        // step 4. delegate the first ssk in the ssk_vec to the gamma_list
        // note: we don't need to modify other ssks in the current ssk_vec
        'out: for i in 0..gamma_list.len() {
            // this loop applies to example 2
            // if the ssk already exists in current sk, for example, ssk_for_t_9, i.e. time vec = [2]
            // we do not delegate
            //
            // since ssk are sorted chronologically
            // the first i ssks are the delegator and the fresh inserted new ssk-s
            // therefore we only need to check from i+1 keys for duplications
            // and if we have found a duplicate, it means we have already finished
            // delegation, so we can break the loop
            for j in i + 1..new_sk.ssk.len() {
                if gamma_list[i] == new_sk.ssk[j].get_time_vec(depth) {
                    // this happens for time vec  = [2]
                    // no further delegation will happen
                    break 'out;
                }
            }

            // delegation -- this does not re-randomize the ssk
            // it makes sure delegation is successful,
            // or else, pass through the error message
            //
            // in example 1
            //  i = 0, new_ssk = ssk_for_t_12
            //  i = 1, new_ssk = ssk_for_t_13
            let mut new_ssk = new_sk.ssk[0].clone();
            let () = match new_ssk.delegate(gamma_list[i].get_time(), depth) {
                Err(e) => return Err(e),
                Ok(()) => (),
            };

            // re-randomization
            // randomize the new ssk unless it is the first one
            // for the first one we reuse the randomness from the delegator
            if i != 0 {
                // TODO: change to a random field element
                let r = Fr::from_str("2").unwrap();
                new_ssk.randomization(&pp, r)
            }

            // insert the key to the right place so that
            // all ssk-s are sorted chronologically
            new_sk.ssk.insert(i + 1, new_ssk);
            // in example 1
            // for i = 0, ### new_sk = {9, [ssk_for_t_9, ssk_for_t_12]}                 //  [2], [2,1,1] ###
            // for i = 1, ### new_sk = {9, [ssk_for_t_9, ssk_for_t_12, ssk_for_t_13]}   //  [2], [2,1,1], [2,1,2] ###
        }

        // step 5. remove the first ssk <- this was the ssk for delegator
        // and update the time stamp
        new_sk.ssk.remove(0);
        new_sk.time = new_sk.ssk[0].get_time();
        // in example 1,
        //
        // ### new_sk = {12, [ssk_for_t_12, ssk_for_t_13]}                // [2,1,1], [2,1,2] ###
        //
        
        // assign new_sk to self, and return successful
        // here we rely on Rust's memory safety feature to ensure the old key is erased
        *self = new_sk;

        Ok(())
    }

    /// This function iterates through the existing sub secret keys, find the one for which
    /// 1. the time stamp is the greatest within existing sub_secret_keys
    /// 2. the time stamp is no greater than tar_time
    /// It returns this subsecretkey's time stamp
    /// e.g.:
    ///     sk {time: 2, ssks: {omited}}
    ///     sk.find_ancestor(12) = 9
    /// This is an ancestor node for the target time.
    fn find_ancestor(&self, tar_time: TimeStamp) -> Result<TimeStamp, String> {
        let mut res = &self.ssk[0];
        if res.get_time() >= tar_time {
            #[cfg(debug_assertions)]
            println!("the input time {} is invalid", tar_time);

            return Err("The input time is invalid for the closest ssk function.".to_owned());
        }

        for i in 0..self.ssk.len() - 1 {
            if self.ssk[i + 1].get_time() <= tar_time {
                res = &self.ssk[i + 1];
            }
        }
        Ok(res.get_time())
    }
}

/// this function generates the master key pair from a seed
/// this function is private -- it should be used only as a subroutine to key gen function
//  todo: decide the right way to hash the seed into master secret
//        perhaps hash_to_field function?
fn master_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PixelG2, PixelG1), String> {
    // make sure we have enough entropy
    if seed.len() < 32 {
        #[cfg(debug_assertions)]
        println!(
            "the seed length {} is not long enough (required as least 32 bytes)",
            seed.len()
        );
        return Err("The seed length is too short".to_owned());
    }

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
    Ok((pk, sk))
}

/// this function tests if a public key and a master secret key has a same exponent
#[cfg(test)]
fn validate_master_key(pk: &PixelG2, sk: &PixelG1, pp: &PubParam) -> bool {
    use ff::Field;
    use pairing::{bls12_381::*, CurveAffine, Engine};

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

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_master_key() {
        let pp = PubParam::init_without_seed();
        let res = master_key_gen(b"this is a very very long seed for testing", &pp);
        assert!(res.is_ok(), "master key gen failed");
        let (pk, sk) = res.unwrap();
        assert!(
            super::validate_master_key(&pk, &sk, &pp),
            "master key is invalid"
        )
    }

    #[test]
    fn test_keypair() {
        let pp = PubParam::init_without_seed();
        let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        assert!(res.is_ok(), "key gen failed");
        let keypair = res.unwrap();
        println!("{:?}", keypair);
    }

    #[test]
    fn test_quick_key_update() {
        let pp = PubParam::init_without_seed();
        let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        assert!(res.is_ok(), "key gen failed");
        let keypair = res.unwrap();
        let sk = keypair.sk;

        // this double loop
        // 1. performs key updates with all possible `start_time` and `finish_time`
        // 2. for each updated key, check the validity of its subkeys (with --long_tests flag)
        for j in 2..16 {
            let mut sk2 = sk.clone();
            let res = sk2.update(&pp, j);
            assert!(res.is_ok(), "update failed");
            for ssk in sk2.ssk {
                assert!(ssk.validate(&keypair.pk, &pp), "validation failed");
            }
        }
    }

    #[ignore]
    #[test]
    fn test_long_key_update() {
        let pp = PubParam::init_without_seed();
        let res = KeyPair::keygen(b"this is a very very long seed for testing", &pp);
        assert!(res.is_ok(), "key gen failed");
        let keypair = res.unwrap();
        let sk = keypair.sk;

        // this double loop
        // 1. performs key updates with all possible `start_time` and `finish_time`
        // 2. for each updated key, checks the validity of its subkeys
        for j in 2..16 {
            let mut sk2 = sk.clone();
            let res = sk2.update(&pp, j);
            assert!(res.is_ok(), "update failed");
            for i in j + 1..16 {
                let mut sk3 = sk2.clone();
                let res = sk3.update(&pp, i);
                assert!(res.is_ok(), "update failed");
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

}
