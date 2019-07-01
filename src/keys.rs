// functions for
//  * the key pair
//  * the public key
//  * the secret key <- the sub secret keys are defined seperately in subkeys module

use bls_sigs_ref_rs::FromRO;
use pairing::{bls12_381::Fr, CurveProjective};
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use std::fmt;
pub use subkeys::SubSecretKey;
use time::{TimeStamp, TimeVec};
use PixelG1;
use PixelG2;

/// The public key structure is a wrapper of PixelG2 group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// ciphersuite id
    ciphersuite: u8,
    /// the actual public key element
    pk: PixelG2,
}

impl PublicKey {
    /// Initialize the PublicKey with a given pk.
    /// Returns an error if the ciphersuite id (in parameter) is not valid
    pub fn init(pp: &PubParam, pk: PixelG2) -> Result<Self, String> {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        Ok(PublicKey {
            ciphersuite: pp.get_ciphersuite(),
            pk,
        })
    }

    pub fn construct(ciphersuite: u8, pk: PixelG2) -> Self {
        PublicKey { ciphersuite, pk }
    }

    /// Set self to the new public key.
    /// Returns an error if the ciphersuite is not supported.
    pub fn set_pk(&mut self, pp: &PubParam, pk: PixelG2) -> Result<(), String> {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        self.ciphersuite = pp.get_ciphersuite();
        self.pk = pk;
        Ok(())
    }

    /// Returns the public key element this structure contains.
    pub fn get_pk(&self) -> PixelG2 {
        self.pk
    }

    /// Returns the public key element this structure contains.
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
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
/// There are two extra fields, the ciphersuite id,
/// and the time stamp.
#[derive(Clone)]
pub struct SecretKey {
    /// ciphersuite id
    ciphersuite: u8,
    /// smallest timestamp for all subkeys
    time: TimeStamp,
    /// the list of the subkeys
    ssk: Vec<SubSecretKey>,
}

impl KeyPair {
    /// Generate a pair of public keys and secret keys.
    /// Returns an error if
    /// * the seed is not long enough
    /// * the ciphersuite is not supported
    pub fn keygen(seed: &[u8], pp: &PubParam) -> Result<Self, String> {
        // this may fail if the seed is too short or
        // the ciphersuite is not supported
        let (pk, msk) = master_key_gen(seed, &pp)?;

        // this may fail if the ciphersuite is not supported
        let sk = SecretKey::init(&pp, msk)?;

        // this may fail if the ciphersuite is not supported
        let pk = PublicKey::init(&pp, pk)?;
        Ok(Self { sk, pk })
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
    /// Build a secret key from the given inputs. Does not check
    /// if the validity of the key.
    pub fn construct(ciphersuite: u8, time: TimeStamp, ssk: Vec<SubSecretKey>) -> Self {
        SecretKey {
            ciphersuite,
            time,
            ssk,
        }
    }

    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` as the input.
    /// It may returns an error if the ciphersuite is not supported.
    pub fn init(pp: &PubParam, alpha: PixelG1) -> Result<Self, String> {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        // TODO: think about seed -- set seed as hash of alpha?
        let r = Fr::from_ro("seed", 0);
        let ssk = SubSecretKey::init(&pp, alpha, r);
        Ok(SecretKey {
            ciphersuite: pp.get_ciphersuite(),
            time: 1,
            ssk: vec![ssk],
        })
    }

    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` and a field element `r` as inputs.
    /// Currently this function is used by testing only.
    #[cfg(test)]
    pub fn init_det(pp: &PubParam, alpha: PixelG1, r: Fr) -> Self {
        let ssk = SubSecretKey::init(&pp, alpha, r);
        SecretKey {
            ciphersuite: pp.get_ciphersuite(),
            time: 1,
            ssk: vec![ssk],
        }
    }

    /// Returns the ciphersuite id of the secret key
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
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
    /// Returns an error if the list is empty.
    pub fn get_first_ssk(&self) -> Result<SubSecretKey, String> {
        if self.ssk.is_empty() {
            #[cfg(debug_assertions)]
            println!("Error to find the first key: {}", ERR_SSK_EMPTY);
            return Err(ERR_SSK_EMPTY.to_owned());
        }

        Ok(self.ssk[0].clone())
    }

    /// Returns the whole list of the sub secret keys.
    pub fn get_ssk_vec(&self) -> Vec<SubSecretKey> {
        self.ssk.clone()
    }

    /// Updates the secret key into the corresponding time stamp.
    /// This function mutate the existing secret keys to the time stamp.
    /// It propogates an error if
    /// the new time stamp is invalid (either smaller than
    /// current time or larger than maximum time stamp)
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

            return Err(ERR_TIME_STAMP.to_owned());
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
        let delegator_time = new_sk.find_ancestor(tar_time)?;
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

        // there should always be at least one key left\
        if new_sk.ssk.is_empty() {
            #[cfg(debug_assertions)]
            println!("Error in key unpdating: {:?}", ERR_SSK_EMPTY);
            return Err(ERR_SSK_EMPTY.to_owned());
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
        let target_time_vec = TimeVec::init(tar_time, depth)?;
        let gamma_list = target_time_vec.gamma_list(depth)?;

        // step 4. delegate the first ssk in the ssk_vec to the gamma_list
        // note: we don't need to modify other ssks in the current ssk_vec
        'out: for (i, tmptime) in gamma_list.iter().enumerate() {
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
                let tmp_time_vec = new_sk.ssk[j].get_time_vec(depth)?;
                if tmptime == &tmp_time_vec {
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
            new_ssk.delegate(tmptime.get_time(), depth)?;

            // re-randomization
            // randomize the new ssk unless it is the first one
            // for the first one we reuse the randomness from the delegator
            if i != 0 {
                // TODO: think about seed -- set seed as previous sk?
                let r = Fr::from_ro("seed", i as u8);
                new_ssk.randomization(&pp, r)?;
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
    /// It returns this subsecretkey's time stamp; or an error if ...
    /// * there is no ssk in the secret key
    /// * the target time stamp is invalid for the curret time stamp
    /// e.g.:
    ///     sk {time: 2, ssks: {omited}}
    ///     sk.find_ancestor(12) = 9
    /// This is an ancestor node for the target time.
    //  Running example from key update:
    //    example 1: ancestor of time stamp 12, a.k.a. [2,1,2]
    //      within the sk = {3, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9]} // [1,1], [1,2], [2]
    //      is 9, corresponding to time vector [2], i.e., a pre-fix of [2,1,2]
    //    example 2: ancestor of time stamp 4, a.k.a. [1,1,1]
    //      within the sk = {2, [ssk_for_t_2, ssk_for_t_9]}              // [1], [2]
    //      is 2, corresponding to time vector [1], i.e., a pre-fix of [1,1,1]
    fn find_ancestor(&self, tar_time: TimeStamp) -> Result<TimeStamp, String> {
        // make sure there is at least one ssk left
        if self.ssk.is_empty() {
            #[cfg(debug_assertions)]
            println!("Error in finding ancestor: {}", ERR_SSK_EMPTY);
            return Err(ERR_SSK_EMPTY.to_owned());
        }

        let mut res = &self.ssk[0];

        // make sure that the time stamp is valid
        if res.get_time() >= tar_time {
            #[cfg(debug_assertions)]
            println!(
                "Error in finding ancestor: the target time {} is invalid for current time {}",
                tar_time,
                res.get_time(),
            );
            return Err(ERR_TIME_STAMP.to_owned());
        }

        // find the ancestor
        for i in 0..self.ssk.len() - 1 {
            if self.ssk[i + 1].get_time() <= tar_time {
                res = &self.ssk[i + 1];
            }
        }
        Ok(res.get_time())
    }

    /// This function checks if the secret key valid w.r.t the
    /// public key, the parameters and the time stamp. A secret key is valid if ...
    ///  * sk.ciphersuite == pk.ciphersuite == pp.ciphersuite
    ///  * sk.ssk.validate(pk, pp)
    ///  * sk.TimeStamp's gamma list form ssk.TimeVec
    pub fn validate(&self, pk: &PublicKey, pp: &PubParam) -> bool {
        // validate the ciphersuite ids
        if self.get_ciphersuite() != pk.get_ciphersuite()
            || self.get_ciphersuite() != pp.get_ciphersuite()
        {
            #[cfg(debug_assertions)]
            println!("Ciphersuite does not match");
            #[cfg(feature = "verbose")]
            #[cfg(debug_assertions)]
            println!(
                "pk's ciphersuite: {}\n\
                 sk's ciphersuite: {}\n\
                 pp's ciphersuite: {}",
                pk.get_ciphersuite(),
                self.get_ciphersuite(),
                pp.get_ciphersuite()
            );
            return false;
        }

        // get the gamma list of the current sk
        let depth = pp.get_d();
        let time_stamp = self.get_time();
        // returns false if the time stamp or depth is not valid
        let time_vec = match TimeVec::init(time_stamp, depth) {
            Err(_e) => {
                #[cfg(debug_assertions)]
                println!("Error in sk validation: {}", _e);
                return false;
            }
            Ok(p) => p,
        };
        let gamma_list = match time_vec.gamma_list(depth) {
            Err(_e) => {
                #[cfg(debug_assertions)]
                println!("Error in sk validation: {}", _e);
                return false;
            }
            Ok(p) => p,
        };

        let ssk = self.get_ssk_vec();
        for i in 0..ssk.len() {
            // checks that each ssk is valid
            if !ssk[i].validate(&pk, &pp) {
                #[cfg(debug_assertions)]
                println!("Validation failed for {}th SubSecretKey", i);
                return false;
            }
            // checks that the time for each ssk is valid w.r.t gamma list
            if ssk[i].get_time() != gamma_list[i].get_time() {
                #[cfg(debug_assertions)]
                println!("Validation failed: time does not match the gamma_list");
                #[cfg(feature = "verbose")]
                #[cfg(debug_assertions)]
                println!(
                    "Current time: {}\n\
                     time from gamma list: {}",
                    ssk[i].get_time(),
                    gamma_list[i].get_time()
                );
                return false;
            }
        }
        true
    }
}

/// This function generates the master key pair from a seed.
/// Input a seed, it uses hash_to_field function to generate a field element x.
/// The public/secret key is then set to g2^x and h^x
/// This function is private -- it should be used only as a subroutine to key gen function
fn master_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PixelG2, PixelG1), String> {
    // make sure we have enough entropy
    if seed.len() < 32 {
        #[cfg(debug_assertions)]
        println!(
            "the seed length {} is not long enough (required as least 32 bytes)",
            seed.len()
        );
        return Err(ERR_SEED_TOO_SHORT.to_owned());
    }

    // check that the ciphersuite identifier is correct
    if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
        #[cfg(debug_assertions)]
        println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
        return Err(ERR_CIPHERSUITE.to_owned());
    }

    // use hash_to_field function to generate a random field element
    // the counter will always be 0 because we only generate one field element
    let r = Fr::from_ro(seed, 0);

    // pk = g2^r
    // sk = h^r
    let mut pk = pp.get_g2();
    let mut sk = pp.get_h();
    pk.mul_assign(r);
    sk.mul_assign(r);
    Ok((pk, sk))
}

/// This function tests if a public key and a master secret key has a same exponent.
/// This function is private, and test only, since by default no one shall have the master secret key.
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
        .iter(),
    ))
    .unwrap();
    #[cfg(not(feature = "pk_in_g2"))]
    let pairingproduct = Bls12::final_exponentiation(&Bls12::miller_loop(
        [
            (&(g2.into_affine().prepare()), &(sk.into_affine().prepare())),
            (&(pk.into_affine().prepare()), &(h.into_affine().prepare())),
        ]
        .iter(),
    ))
    .unwrap();

    // verification is successful if
    //   pairingproduct == 1
    pairingproduct == Fq12::one()
}

/// convenient function to output a secret key object
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
        writeln!(f, "================================")
    }
}

/// convenient function to compare secret key objects
impl std::cmp::PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        if self.ciphersuite != other.ciphersuite {
            return false;
        }
        if self.time != other.time {
            return false;
        }
        if self.get_ssk_number() != other.get_ssk_number() {
            return false;
        }
        for i in 0..self.get_ssk_number() {
            if self.ssk[i] != other.ssk[i] {
                return false;
            }
        }
        true
    }
}

/// convenient function to compare secret key objects
impl std::cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite && self.pk == other.pk
    }
}

#[test]
fn test_master_key() {
    let pp = PubParam::init_without_seed();
    let res = master_key_gen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "master key gen failed");
    let (pk, sk) = res.unwrap();
    assert!(validate_master_key(&pk, &sk, &pp), "master key is invalid")
}
