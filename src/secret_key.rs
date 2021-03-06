use crate::{PixelG1, PublicKey, SerDes, SubSecretKey};

use domain_sep;
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use prng::PRNG;
use sha2::Digest;
use std::fmt;
use time::{TimeStamp, TimeVec};
use zeroize::*;
/// The secret key consists of ...
/// * a list of SubSecretKeys;
///     the length of the list can be arbitrary;
///     they are arranged in a chronological order.
/// * the ciphersuite id,
/// * time stamp,
/// * and a prng.
#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    /// ciphersuite id
    ciphersuite: u8,
    /// smallest timestamp for all subkeys
    time: TimeStamp,
    /// the list of the subkeys
    ssk: Vec<SubSecretKey>,
    /// a seed that is used to generate the randomness during key updating
    prng: PRNG,
}

impl SecretKey {
    /// Build a secret key from the given inputs. Does not check
    /// if the validity of the key.
    pub fn new(ciphersuite: u8, time: TimeStamp, ssk: Vec<SubSecretKey>, prng: PRNG) -> Self {
        SecretKey {
            ciphersuite,
            time,
            ssk,
            prng,
        }
    }

    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` as the input.
    /// It may returns an error if the ciphersuite is not supported.
    pub fn init(pp: &PubParam, alpha: PixelG1, mut prng: PRNG) -> Result<Self, String> {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // info = domain_sep::DOM_SEP_SK_INIT | time = 1
        let info = [
            domain_sep::DOM_SEP_SK_INIT.as_ref(),
            [0, 0, 0, 1u8].as_ref(),
        ]
        .concat();
        // r is a local secret, and need to be cleared after use
        let mut r_sec = prng.sample_then_update(info);

        // ssk is passed to the caller
        let ssk = SubSecretKey::init(&pp, alpha, r_sec);

        // zero out the temporary r_sec
        r_sec.zeroize();

        Ok(SecretKey {
            ciphersuite: pp.ciphersuite(),
            time: 1,
            ssk: vec![ssk],
            prng,
        })
    }

    /// Returns the ciphersuite id of the secret key
    pub fn ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// Returns the current time stamp for the key.
    pub fn time(&self) -> TimeStamp {
        self.time
    }

    /// Returns the number of sub_secret_keys.
    pub fn ssk_number(&self) -> usize {
        self.ssk.len()
    }

    /// Returns the prng seed.
    pub fn prng(&self) -> PRNG {
        self.prng.clone()
    }

    /// Clone the first sub secret key on the list.
    /// Returns an error if the list is empty.
    /// Warning!!!
    /// There will be two copies of the ssk\[0\] in the
    /// memory once this function is called.
    /// Make sure it is handled properly.
    pub fn first_ssk(&self) -> Result<SubSecretKey, String> {
        if self.ssk.is_empty() {
            #[cfg(debug_assertions)]
            println!("Error to find the first key: {}", ERR_SSK_EMPTY);
            return Err(ERR_SSK_EMPTY.to_owned());
        }

        Ok(self.ssk[0].clone())
    }

    /// Returns the whole list of the sub secret keys.
    /// Warning!!!
    /// There will be two copies of the ssk vector in the
    /// memory once this function is called.
    /// Make sure it is handled properly.
    pub fn ssk_vec(&self) -> Vec<SubSecretKey> {
        self.ssk.clone()
    }

    /// Serialize an sk into a blob and then use sha256
    /// to generate a digest of the blob.
    /// * `digest = sha512(sk.serialize())`.
    /// This function turns out to be a bit slow because
    /// it converts all the group elements into
    /// their affine coordinates before serialize them.
    /// And because the size is big, so the hash function
    /// will have quite a lot of iterations.
    /// This function is not used by any pixel interal calls.
    pub fn digest(&self) -> Result<Vec<u8>, String> {
        let mut hashinput = vec![0u8; self.size()];
        // serializae a sk into buffer
        if self.serialize(&mut hashinput, true).is_err() {
            return Err(ERR_SERIAL.to_owned());
        };

        let mut hasher = sha2::Sha512::new();
        hasher.input(hashinput);
        Ok(hasher.result().to_vec())
    }

    /// Updates the secret key into the corresponding time stamp.
    /// This function mutate the existing secret keys to the time stamp.
    /// The randomness is generated via sample_then_update function.
    ///
    /// It propogates an error if
    ///  * the new time stamp is invalid (either smaller than
    /// current time or larger than maximum time stamp)
    ///  * serialization error
    pub fn update<'a>(
        &'a mut self,
        pp: &PubParam,
        tar_time: TimeStamp,
        seed: &[u8],
    ) -> Result<(), String> {
        // check the ciphersuites match
        if self.ciphersuite() != pp.ciphersuite() {
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // max time = 2^d - 1
        let depth = pp.depth();
        let max_time = (1u64 << depth) - 1;
        let cur_time = self.time();
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
        let delegator_time = self.find_ancestor(tar_time)?;

        // make a clone of self, in case an error is raised, we do not want to mutate the key
        // the new_sk has a same life time as the old key
        // note: since we will replace self with new_sk by the end of this function,
        // we will need to clear either `self` or new_sk
        // to ensure only one copy lives in the memory
        let mut new_sk = self.clone();

        // step 0. always re-randomize the prng
        // info = domain_sep::DOM_SEP_SK_RERANDOMIZE_INFO | I2OSP(time,4)
        let time_tmp = [
            (cur_time >> 24 & 0xFF) as u8,
            (cur_time >> 16 & 0xFF) as u8,
            (cur_time >> 8 & 0xFF) as u8,
            (cur_time & 0xFF) as u8,
        ];
        let info = [
            domain_sep::DOM_SEP_SK_RERANDOMIZE_INFO.as_ref(),
            time_tmp.as_ref(),
        ]
        .concat();
        new_sk.prng.rerandomize(seed, info.as_ref());

        // step 1.1 update new_sk's time stamp
        // the current sk is ### new_sk = {9, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9]} ###
        new_sk.time = delegator_time;

        #[cfg(debug_assertions)]
        #[cfg(test)]
        println!(
            "delegating from {} to {} using delegator time {}",
            new_sk.time(),
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
        while new_sk.ssk[0].time() != delegator_time {
            // new_sk.ssk[0] is zeorized automatically
            // we can safely remove the ssk
            new_sk.ssk.remove(0);
        }

        // there should always be at least one key left
        if new_sk.ssk.is_empty() {
            #[cfg(debug_assertions)]
            println!("Error in key unpdating: {:?}", ERR_SSK_EMPTY);

            // new_sk is cleared automatically
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
            // old sk is cleared automatically
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
        let target_time_vec = match TimeVec::init(tar_time, depth) {
            Err(e) => {
                // new sk is cleared automatically
                return Err(e);
            }
            Ok(p) => p,
        };
        let gamma_list = match target_time_vec.gamma_list(depth) {
            Err(e) => {
                // new sk is cleared automatically
                return Err(e);
            }
            Ok(p) => p,
        };

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
                let tmp_time_vec = match new_sk.ssk[j].time_vec(depth) {
                    Err(e) => {
                        // new sk is cleared automatically
                        return Err(e);
                    }
                    Ok(p) => p,
                };
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
            match new_ssk.delegate(tmptime.time(), depth) {
                Err(e) => {
                    // new sk and ssk are cleared automatically
                    return Err(e);
                }
                Ok(p) => p,
            };

            // re-randomization
            // randomize the new ssk unless it is the first one
            // for the first one we reuse the randomness from the delegator
            if i != 0 {
                // the following code generates r from sk deterministicly
                //  m = HKDF-expand(prngseed, info, 128)
                //  r = hash_to_field(m[0..64], ctr)
                //  prngseed = m[64..128]
                // note that a key update requires zero or one
                // random field element. So the following function
                // shouldn't be called more than once.
                let info = domain_sep::DOM_SEP_SK_UPDATE;
                let mut r_sec = new_sk.prng.sample_then_update(info);

                assert_ne!(new_sk.prng, self.prng, "prng not updated");

                match new_ssk.randomization(&pp, r_sec) {
                    Err(e) => {
                        r_sec.zeroize();
                        // new sk and ssk will be cleared automatically
                        return Err(e);
                    }
                    Ok(p) => p,
                };
                r_sec.zeroize();
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

        // ssk[0] will be removed automatically after drop
        // so we can safely remove the ssk
        new_sk.ssk.remove(0);
        new_sk.time = new_sk.ssk[0].time();
        // in example 1,
        //
        // ### new_sk = {12, [ssk_for_t_12, ssk_for_t_13]}                // [2,1,1], [2,1,2] ###
        //

        // assign new_sk to self, and return successful
        // old sk will be dropped automatically

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
        if res.time() >= tar_time {
            #[cfg(debug_assertions)]
            println!(
                "Error in finding ancestor: the target time {} is invalid for current time {}",
                tar_time,
                res.time(),
            );
            return Err(ERR_TIME_STAMP.to_owned());
        }

        // find the ancestor
        for i in 0..self.ssk.len() - 1 {
            if self.ssk[i + 1].time() <= tar_time {
                res = &self.ssk[i + 1];
            }
        }
        Ok(res.time())
    }

    /// This function checks if the secret key valid w.r.t the
    /// public key, the parameters and the time stamp. A secret key is valid if ...
    ///  * sk.ciphersuite == pk.ciphersuite == pp.ciphersuite
    ///  * sk.ssk.validate(pk, pp) is valid for all ssk-s
    ///  * sk.TimeStamp's gamma list forms ssk.TimeVec for all ssk-s
    pub fn validate(&self, pk: &PublicKey, pp: &PubParam) -> bool {
        // validate the ciphersuite ids
        if self.ciphersuite() != pk.ciphersuite() || self.ciphersuite() != pp.ciphersuite() {
            #[cfg(debug_assertions)]
            println!("Ciphersuite does not match");
            #[cfg(feature = "verbose")]
            #[cfg(debug_assertions)]
            println!(
                "pk's ciphersuite: {}\n\
                 sk's ciphersuite: {}\n\
                 pp's ciphersuite: {}",
                pk.ciphersuite(),
                self.ciphersuite(),
                pp.ciphersuite()
            );
            return false;
        }

        // get the gamma list of the current sk
        let depth = pp.depth();
        let time_stamp = self.time();
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

        let ssk = self.ssk_vec();
        for i in 0..ssk.len() {
            // checks that each ssk is valid
            if !ssk[i].validate(&pk, &pp) {
                // ssk will be cleared automatically
                #[cfg(debug_assertions)]
                println!("Validation failed for {}th SubSecretKey", i);
                return false;
            }
            // checks that the time for each ssk is valid w.r.t gamma list
            if ssk[i].time() != gamma_list[i].time() {
                // ssk will be cleared automatically
                #[cfg(debug_assertions)]
                println!("Validation failed: time does not match the gamma_list");
                #[cfg(debug_assertions)]
                println!(
                    "Current time: {}\n\
                     time from gamma list: {}",
                    ssk[i].time(),
                    gamma_list[i].time()
                );
                return false;
            }
        }
        // ssk will be cleared automatically
        true
    }

    /// This function returns the storage requirement for this secret key. Recall that
    /// each sk is a blob:
    ///
    /// `|ciphersuite id| prng_seed | number_of_ssk-s | serial(first ssk) | serial(second ssk)| ...`,
    ///
    /// where ...
    /// * ciphersuite is 1 byte
    /// * prng_seed is 64 bytes
    /// * number of ssk-s is 1 byte - there cannot be more than const_d number of ssk-s
    /// * each ssk is
    ///
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`.
    ///
    /// So the output will be 66 + size of eash ssk.
    pub fn size(&self) -> usize {
        let mut len = 66;
        let ssk = self.ssk_vec();
        for e in ssk {
            len += e.size();
        }
        len
    }

    /// This function estimates the storage requirement for this secret key. Recall that
    /// each sk is a blob:
    ///
    /// `|ciphersuite id| prng_seed | number_of_ssk-s | serial(first ssk) | serial(second ssk)| ...`,
    ///
    /// where ...
    /// * ciphersuite is 1 byte
    /// * prng_seed is 64 bytes
    /// * number of ssk-s is 1 byte - there cannot be more than const_d number of ssk-s
    /// * each ssk is
    ///
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`.
    ///
    /// So the output will be 66 + size of eash ssk.
    pub fn estimate_size(time: u64, depth: usize) -> Result<usize, String> {
        let time_vec = TimeVec::init(time, depth)?;
        let gamma_list = time_vec.gamma_list(depth)?;
        // * ciphersuite is 1 byte
        // * prng_seed is 64 bytes
        // * number of ssk-s is 1 byte - there cannot be more than const_d number of ssk-s
        let mut res = 66;
        for e in gamma_list {
            // * each ssk is
            //
            // `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`.
            //
            // that is
            //     * 4 bytes for time stamp
            //     * 1 byte for hvlength
            //     * 144 bytes for g2r and hpoly
            //     * (d + 1 - |tmp+time+vec|) * 48 for h_|tmp+time+vec| ... h_d
            res = res + 149 + (depth - e.vector_len()) * 96;
        }
        Ok(res)
    }
}

/// convenient function to output a secret key object
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "================================\ntime:{:?}", self.time)?;
        writeln!(f, "seed: \n{:?}", self.prng)?;
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
        if self.ssk_number() != other.ssk_number() {
            return false;
        }
        for i in 0..self.ssk_number() {
            if self.ssk[i] != other.ssk[i] {
                return false;
            }
        }
        self.ciphersuite() == other.ciphersuite()
            && self.time() == other.time()
            && self.prng == other.prng
    }
}
