// functions for
//  * the key pair
//  * the public key
//  * the secret key <- the sub secret keys are defined seperately in subkeys module

use bls_sigs_ref_rs::{BLSSignature, FromRO};
use clear_on_drop::ClearOnDrop;
use domain_sep;
use ff::Field;
use pairing::{bls12_381::Fr, CurveProjective};
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use serdes::SerDes;
use sha2::Digest;
use std::fmt;
pub use subkeys::SubSecretKey;
use time::{TimeStamp, TimeVec};
use PixelG1;
use PixelG2;
use PK_LEN;

/// The public key structure is a wrapper of `PixelG2` group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone, Default)]
pub struct PublicKey {
    /// ciphersuite id
    ciphersuite: u8,
    /// the actual public key element
    pk: PixelG2,
}

/// The public key structure is a wrapper of `PixelG2` group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone, Default)]
pub struct ProofOfPossession {
    /// ciphersuite id
    ciphersuite: u8,
    /// the actual public key element
    pop: PixelG1,
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

    /// Constructing a PublicKey object.
    pub fn construct(ciphersuite: u8, pk: PixelG2) -> Self {
        PublicKey { ciphersuite, pk }
    }

    /// This function returns the storage requirement for this Public Key
    pub fn get_size(&self) -> usize {
        PK_LEN
    }

    // /// Set self to the new public key.
    // /// Returns an error if the ciphersuite is not supported.
    // pub fn set_pk(&mut self, pp: &PubParam, pk: PixelG2) -> Result<(), String> {
    //     // check that the ciphersuite identifier is correct
    //     if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
    //         #[cfg(debug_assertions)]
    //         println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
    //         return Err(ERR_CIPHERSUITE.to_owned());
    //     }
    //     self.ciphersuite = pp.get_ciphersuite();
    //     self.pk = pk;
    //     Ok(())
    // }

    /// Returns the public key element this structure contains.
    pub fn get_pk(&self) -> PixelG2 {
        self.pk
    }

    /// Returns the public key element this structure contains.
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// This function validates the public key against the
    /// proof_of_possession using BLS verification algorithm.
    pub fn validate(&self, pop: &ProofOfPossession) -> bool {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", self.get_ciphersuite());
            return false;
        }
        // buf = DOM_SEP_POP | serial (PK)
        let mut buf = domain_sep::DOM_SEP_POP.as_bytes().to_vec();
        if self.get_pk().serialize(&mut buf, true).is_err() {
            #[cfg(debug_assertions)]
            println!("Serialization failure on public key");
            return false;
        };
        // return the output of verification
        BLSSignature::verify(self.get_pk(), pop.pop, buf, self.get_ciphersuite())
    }
}

/// The keypair is a pair of public and secret keys,
/// and a proof of possesion of the public key.
#[derive(Debug, Clone, Default)]
pub struct KeyPair;
// pub struct KeyPair {
//     sk: SecretKey,
//     pk: PublicKey,
//     pop: ProofOfPossession,
// }

/// The secret key is a list of SubSecretKeys;
/// the length of the list can be arbitrary;
/// they are arranged in a chronological order.
/// There are two extra fields, the ciphersuite id,
/// and the time stamp.
#[derive(Clone, Default)]
pub struct SecretKey {
    /// ciphersuite id
    ciphersuite: u8,
    /// smallest timestamp for all subkeys
    time: TimeStamp,
    /// the list of the subkeys
    ssk: Vec<SubSecretKey>,
    /// a seed that is used to generate the randomness during key updating
    rngseed: [u8; 32],
}

impl KeyPair {
    /// Generate a pair of public keys and secret keys,
    /// and a proof of possession of the public key.
    /// This function does NOT return the master secret
    /// therefore this is the only method that generates POP.
    /// This function does NOT destroy the seed.
    /// Returns an error if
    /// * the seed is not long enough
    /// * the ciphersuite is not supported
    pub fn keygen(
        seed: &[u8],
        pp: &PubParam,
    ) -> Result<(PublicKey, SecretKey, ProofOfPossession), String> {
        // update then extract the seed
        // make sure we have enough entropy
        let seed_len = seed.len();
        if seed_len < 32 {
            #[cfg(debug_assertions)]
            println!(
                "the seed length {} is not long enough (required as least 32 bytes)",
                seed_len
            );
            return Err(ERR_SEED_TOO_SHORT.to_owned());
        }

        // this may fail if the seed is too short or
        // the ciphersuite is not supported

        // inside master_key_gen:
        // extract the a secret from the seed using the HKDF-SHA512-Extract
        //  m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)
        // then expand the secret with HKDF-SHA512-Expand
        //  t = HKDF-Expand(m, info, 64)
        // with info = "key initialization"
        // use the first 32 bytes as the input to hash_to_field
        // use the last 32 bytes as the rngseed
        let (pk, mut sec_msk, pop, mut sec_rngseed) = master_key_gen(seed, &pp)?;

        // this may fail if the ciphersuite is not supported
        // it should also erase the msk
        let sec_sk = SecretKey::init(&pp, sec_msk, &mut sec_rngseed)?;
        // makes sure the seed and msk are distroyed
        // the seed shold always be cleared
        // so if not, we should panic rather than return errors
        assert_eq!(
            sec_rngseed, [0u8; 32],
            "seed not cleared after secret key initialization"
        );
        {
            let _clear = ClearOnDrop::new(&mut sec_msk);
        }
        assert_eq!(
            sec_msk,
            PixelG1::default(),
            "msk not cleared after secret key initialization"
        );

        // this may fail if the ciphersuite is not supported
        let pk = PublicKey::init(&pp, pk)?;

        // return the keys and the proof of possession
        Ok((
            pk,
            // momery for sec_sk is not cleared -- it is passed to the called
            sec_sk,
            ProofOfPossession {
                ciphersuite: pp.get_ciphersuite(),
                pop,
            },
        ))
    }

    // /// Returns the public key in a `KeyPair`
    // pub fn get_pk(&self) -> PublicKey {
    //     self.pk.clone()
    // }
    //
    // /// Returns the secret key in a `KeyPair`
    // pub fn get_sk(&self) -> SecretKey {
    //     self.sk.clone()
    // }
    //
    // /// Returns the secret key in a `KeyPair`
    // pub fn get_pop(&self) -> ProofOfPossession {
    //     self.pop.clone()
    // }
}

impl SecretKey {
    /// Build a secret key from the given inputs. Does not check
    /// if the validity of the key.
    pub fn construct(
        ciphersuite: u8,
        time: TimeStamp,
        ssk: Vec<SubSecretKey>,
        rngseed: [u8; 32],
    ) -> Self {
        SecretKey {
            ciphersuite,
            time,
            ssk,
            rngseed,
        }
    }

    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` as the input.
    /// It clears the rngseed by setting it to 0s, and
    /// removes the root secret key alpha.
    /// It may returns an error if the ciphersuite is not supported.
    pub fn init(
        pp: &PubParam,
        mut sec_alpha: PixelG1,
        mut rngseed: &mut [u8; 32],
    ) -> Result<Self, String> {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // now: extract the a secret from the seed using the HKDF-SHA512-Extract
        //  m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)
        // then expand the secret with HKDF-SHA512-Expand
        //  t = HKDF-Expand(m, info, 64)
        // with info = "key initialization"
        // use the first 32 bytes as the input to hash_to_field
        // use the last 32 bytes as the rngseed
        let (extract, updated) = rngseed_extract_and_update(&mut rngseed);
        assert_eq!(
            rngseed, &[0u8; 32],
            "rngseed not cleared during key initiation"
        );

        // set up the input to hash to field
        let input = [
            domain_sep::DOM_SEP_KEY_INIT.as_bytes(),
            [pp.get_ciphersuite()].as_ref(),
            &extract,
        ]
        .concat();
        let mut sec_r = Fr::from_ro(input, 0);
        let ssk = SubSecretKey::init(&pp, sec_alpha, sec_r);

        // zero out the master secret alpha using ClearOnDrop
        // this function sets the rng to 0s (and disable compiler optimization)
        // once it is out of the scope
        {
            let _clear1 = ClearOnDrop::new(&mut sec_alpha);
            let _clear2 = ClearOnDrop::new(&mut sec_r);
        }
        // panic if the alpha or r is not cleared
        assert_eq!(
            sec_alpha,
            PixelG1::zero(),
            "alpha is not cleared during key initiation"
        );
        // panic if the alpha is not cleared
        assert_eq!(
            sec_r,
            Fr::zero(),
            "alpha is not cleared during key initiation"
        );

        Ok(SecretKey {
            ciphersuite: pp.get_ciphersuite(),
            time: 1,
            ssk: vec![ssk],
            rngseed: updated,
        })
    }

    /// This function initializes the secret key at time stamp = 1.
    /// It takes the root secret `alpha` and a field element `r` as inputs.
    /// Currently this function is used by testing only.
    #[cfg(test)]
    pub fn init_det(pp: &PubParam, alpha: PixelG1, r: Fr, rngseed: &[u8; 32]) -> Self {
        let ssk = SubSecretKey::init(&pp, alpha, r);
        SecretKey {
            ciphersuite: pp.get_ciphersuite(),
            time: 1,
            ssk: vec![ssk],
            rngseed: *rngseed,
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

    /// Returns the prng seed.
    pub fn get_rngseed(&self) -> [u8; 32] {
        self.rngseed
    }

    /// Clone the first sub secret key on the list.
    /// Returns an error if the list is empty.
    /// Warning!!!
    /// There will be two copies of the ssk[0] in the
    /// memory once this function is called.
    /// Make sure it is handled properly.
    pub fn get_first_ssk(&self) -> Result<SubSecretKey, String> {
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
    pub fn get_ssk_vec(&self) -> Vec<SubSecretKey> {
        self.ssk.clone()
    }

    /// Serialize an sk into a blob and then use sha256
    /// to generate a digest of the blob.
    /// * `digest = sha256(sk.serialize())`.
    /// This function turns out to be a bit slow because
    /// it converts all the group elements into
    /// their affine coordinates before serialize them.
    /// And because the size is big, so the hash function
    /// will have quite a lot of iterations.
    pub fn digest(&self) -> Result<Vec<u8>, String> {
        let mut hashinput = vec![0u8; self.get_size()];
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
    /// The randomness is generated via
    ///  * `digest = sha256(sk.serialize())`
    ///  * `hash_to_field(DOM_SEP_KEY_UPDATE|ciphersuite|digest, ctr)`
    ///
    /// It propogates an error if
    ///  * the new time stamp is invalid (either smaller than
    /// current time or larger than maximum time stamp)
    ///  * serialization error
    pub fn update<'a>(&'a mut self, pp: &PubParam, tar_time: TimeStamp) -> Result<(), String> {
        // make a clone of self, in case an error is raised, we do not want to mutate the key
        // the new_sk has a same life time as the old key
        let mut new_sk = self.clone();

        // check the ciphersuites match
        if self.get_ciphersuite() != pp.get_ciphersuite() {
            return Err(ERR_CIPHERSUITE.to_owned());
        }

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
            // we use ClearOnDrop to safely remove the ssk[0]
            {
                let _clear = ClearOnDrop::new(&mut new_sk.ssk[0]);
            }
            // makes sure that the ssk[0] has been removed
            // panic if this fails
            assert_eq!(
                new_sk.ssk[0],
                SubSecretKey::default(),
                "Subsecret key is not zeroed before removing"
            );

            // now we can safely remove the ssk
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
            // we use ClearOnDrop to safely remove the old sk
            // {
            //     let _clear = ClearOnDrop::new(self);
            // }
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

        // originally: digest sk into a shorter blob, and use it for hash_to_field
        // now: expand the rngseed into two parts, use 1st part for hash_to_field,
        // update rngseed to the second part
        let (extract, updated) = rngseed_extract_and_update(&mut self.rngseed);

        // makes sure the seed is distroyed
        // the seed should always be cleared
        // so if not, we should panic rather than returning errors
        assert_eq!(
            self.rngseed, [0u8; 32],
            "seed not cleared within secret key update"
        );

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
                // the following code generates r from sk deterministicly
                // r = hash_to_field(DOM_SEP_KEY_UPDATE|ciphersuite| sk_digest, ctr)
                let input = [
                    domain_sep::DOM_SEP_KEY_UPDATE.as_bytes(),
                    [self.get_ciphersuite()].as_ref(),
                    &extract,
                ]
                .concat();
                let r = Fr::from_ro(input, (i - 1) as u8);

                // TODO: decide what about non-deterministic version?

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

        // we use ClearOnDrop to safely remove the ssk[0]
        {
            let _clear = ClearOnDrop::new(&mut new_sk.ssk[0]);
        }
        // makes sure that the ssk[0] has been removed
        // panic if this fails
        assert_eq!(
            new_sk.ssk[0],
            SubSecretKey::default(),
            "Subsecret key is not zeroed before removing"
        );

        // now we can safely remove the ssk
        new_sk.ssk.remove(0);
        new_sk.time = new_sk.ssk[0].get_time();
        // in example 1,
        //
        // ### new_sk = {12, [ssk_for_t_12, ssk_for_t_13]}                // [2,1,1], [2,1,2] ###
        //

        // assign new_sk to self, and return successful
        *self = new_sk;
        self.rngseed = updated;
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
    ///  * sk.ssk.validate(pk, pp) is valid for all ssk-s
    ///  * sk.TimeStamp's gamma list forms ssk.TimeVec for all ssk-s
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

        let mut ssk = self.get_ssk_vec();
        for i in 0..ssk.len() {
            // checks that each ssk is valid
            if !ssk[i].validate(&pk, &pp) {
                // clear ssk before exit
                {
                    let _clear = ClearOnDrop::new(&mut ssk);
                }
                assert_eq!(ssk, Vec::default(), "ssk not cleared");
                #[cfg(debug_assertions)]
                println!("Validation failed for {}th SubSecretKey", i);
                return false;
            }
            // checks that the time for each ssk is valid w.r.t gamma list
            if ssk[i].get_time() != gamma_list[i].get_time() {
                // clear ssk before exit
                {
                    let _clear = ClearOnDrop::new(&mut ssk);
                }
                assert_eq!(ssk, Vec::default(), "ssk not cleared");
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
        // clear ssk before exit
        {
            let _clear = ClearOnDrop::new(&mut ssk);
        }
        assert_eq!(ssk, Vec::default(), "ssk not cleared");
        true
    }

    /// This function returns the storage requirement for this secret key. Recall that
    /// each sk is a blob:
    ///
    /// `|ciphersuite id| seed | number_of_ssk-s | serial(first ssk) | serial(second ssk)| ...`,
    ///
    /// where ...
    /// * ciphersuite is 1 byte
    /// * number of ssk-s is 1 byte - there cannot be more than const_d number of ssk-s
    /// * each ssk is
    ///
    /// `| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`.
    ///
    /// So the output will be 34 + size of eash ssk.
    pub fn get_size(&self) -> usize {
        let mut len = 34;
        let ssk = self.get_ssk_vec();
        for e in ssk {
            len += e.get_size();
        }
        len
    }

    // /// TODO: description
    // pub fn to_bytes(&self) -> String {
    //     let mut res = format!(
    //         //        "ciphersuite {}, number of ssk {}, ",
    //         "{}{}",
    //         self.get_ciphersuite(),
    //         self.get_ssk_number()
    //     );
    //     //        let ssk_list = self.get_ssk_vec();
    //     for e in &self.ssk {
    //         res.push_str(&e.to_bytes());
    //     }
    //     res
    // }
}

/// This function generates the master key pair from a seed.
/// Input a seed,
/// extract the a secret from the seed using the HKDF-SHA512-Extract
///  `m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)`
/// then expand the secret with HKDF-SHA512-Expand
///  `t = HKDF-Expand(m, info, 64)`
/// with info = "key initialization"
/// Use the first 32 bytes as the input to hash_to_field.
/// Use the last 32 bytes as the rngseed.
/// The public/secret key is then set to g2^x and h^x
/// It also generate a proof of possesion which is a BLS signature on g2^x.
/// This function is private -- it should be used only as a subroutine to key gen function
fn master_key_gen(
    seed: &[u8],
    pp: &PubParam,
) -> Result<(PixelG2, PixelG1, PixelG1, [u8; 32]), String> {
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
    let mut sec_r = Fr::from_ro(
        [
            domain_sep::DOM_SEP_MASTER_KEY.as_bytes(),
            [pp.get_ciphersuite()].as_ref(),
            seed,
        ]
        .concat(),
        0,
    );
    let mut rngseed = [0u8; 32];
    let hashinput = [
        domain_sep::DOM_SEP_SEED_INIT.as_ref(),
        [pp.get_ciphersuite()].as_ref(),
        seed,
    ]
    .concat();
    let mut hasher = sha2::Sha256::new();
    hasher.input(hashinput);
    rngseed.clone_from_slice(&hasher.result());
    // pk = g2^r
    // sk = h^r
    let mut pk = pp.get_g2();
    let mut sk = pp.get_h();
    pk.mul_assign(sec_r);
    sk.mul_assign(sec_r);
    let pop = proof_of_possession(sec_r, pk, pp.get_ciphersuite())?;

    // clear temporary data
    {
        let _clear = ClearOnDrop::new(&mut sec_r);
    }
    assert_eq!(sec_r, Fr::zero(), "Random r is not cleared!");

    Ok((pk, sk, pop, rngseed))
}

/// This function generate a proof of possesion of the master secret.
/// This function is a subroutine of the key generation function, and
/// should not be called anywhere else -- the master secret key is
/// destroyed after key generation.
fn proof_of_possession(msk: Fr, pk: PixelG2, ciphersuite: u8) -> Result<PixelG1, String> {
    // buf = DOM_SEP_POP | serial (PK)
    let mut buf = domain_sep::DOM_SEP_POP.as_bytes().to_vec();
    if pk.serialize(&mut buf, true).is_err() {
        return Err(ERR_SERIAL.to_owned());
    };
    // the pop is a signature on the buf
    let sig = BLSSignature::sign(msk, buf, ciphersuite);
    Ok(sig)
}

/// TODO: replace with HKDF
/// Input a seed, this function extract and then update the seed as follows:
///     rngseed_updated      =  sha256 (DOM_SEP_SEED_UPDATE|rngseed)
///     rngseed_extracted    =  sha256 (DOM_SEP_SEED_EXTRACT|rngseed)
/// The extracted seed is returned; the original seed is mutated to the updated one.
fn rngseed_extract_and_update(rngseed: &mut [u8; 32]) -> ([u8; 32], [u8; 32]) {
    // the extracted seed
    let mut extracted = [0u8; 32];
    // the updated seed
    let mut updated = [0u8; 32];

    // extract =  (DOM_SEP_SEED_EXTRACT|rngseed)
    let hashinput = [domain_sep::DOM_SEP_SEED_EXTRACT.as_ref(), rngseed.as_ref()].concat();
    let mut hasher = sha2::Sha256::new();
    hasher.input(hashinput);
    extracted.clone_from_slice(&hasher.result());

    // update =  (DOM_SEP_SEED_EXTRACT|rngseed)
    let hashinput = [domain_sep::DOM_SEP_SEED_UPDATE.as_ref(), rngseed.as_ref()].concat();
    let mut hasher = sha2::Sha256::new();
    hasher.input(hashinput);
    updated.clone_from_slice(&hasher.result());

    // zero out the old seed using ClearOnDrop
    // this function sets the rng to 0s (and disable compiler optimization)
    // once it is out of the scope
    {
        let _clear = ClearOnDrop::new(rngseed);
    }

    // return the new seeds
    (extracted, updated)
}

/// This function tests if a public key and a master secret key has a same exponent.
/// This function is private, and test only, since by default no one shall have the master secret key.
#[cfg(test)]
fn validate_master_key(pk: &PixelG2, sk: &PixelG1, pp: &PubParam) -> bool {
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
        writeln!(f, "================================\ntime:{:?}", self.time)?;
        writeln!(f, "seed: {:?}", self.rngseed)?;
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
        if self.get_ssk_number() != other.get_ssk_number() {
            return false;
        }
        for i in 0..self.get_ssk_number() {
            if self.ssk[i] != other.ssk[i] {
                return false;
            }
        }
        self.get_ciphersuite() == other.get_ciphersuite() && self.get_time() == other.get_time()
    }
}

impl std::cmp::PartialEq for PublicKey {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite && self.pk == other.pk
    }
}

#[test]
fn test_master_key() {
    let pp = PubParam::init_without_seed();
    let res = master_key_gen(b"this is a very very long seed for testing", &pp);
    assert!(res.is_ok(), "master key gen failed");
    let (pk, sk, _pop, _seed) = res.unwrap();
    assert!(validate_master_key(&pk, &sk, &pp), "master key is invalid")
}
