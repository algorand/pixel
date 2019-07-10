# Pixel Signature
<!---
This file is still under construction
--->



<!--
CREDIT: http://patorjk.com/software/taag
.______    __  ___   ___  _______  __
|   _  \  |  | \  \ /  / |   ____||  |
|  |_)  | |  |  \  V  /  |  |__   |  |
|   ___/  |  |   >   <   |   __|  |  |
|  |      |  |  /  .  \  |  |____ |  `----.
| _|      |__| /__/ \__\ |_______||_______|
-->

## Parameter

### Ciphersuite  
  * Currently supports `0x00` and `0x01`.
  * The maps between ciphersuite IDs and actual parameters are TBD.
  * Additional ciphersuite identifiers may be added later.

### Depth of time tree
  * `CONST_D`: A constant set to `32`. This allows for `780` years of time stamps if
  we use a timestamp every `5` second.

### Public Parameter
* Structure
  ``` rust
  struct PubParam {
      d:            usize,              // the depth of the time vector
      ciphersuite:  u8,                 // ciphersuite id
      g2:           PixelG2,            // generator for PixelG2 group
      h:            PixelG1,            // h
      hlist:        [PixelG1; d + 1],   // h_0, h_1, ..., h_d
  }
  ```
* Construct a public parameter object from some input:

  ``` rust
  fn construct(d: usize, ciphersuite: u8, g2: PixelG2, h: PixelG1, hlist: Vec<PixelG1>) -> PublicParam
  ```

* Get various elements from the public parameter:
  ``` rust
  fn get_d(&self) -> usize;
  fn get_ciphersuite(&self) -> u8;
  fn get_g2(&self) -> PixelG2 ;
  fn get_h(&self) -> PixelG1;
  fn get_hlist(&self) -> Hlist;
  ```

* Serialization:
  * each a public parameter is a blob: `|ciphersuite id| depth | g2 | h | hlist |`

  ``` rust
  const PP_LEN;                   // size in bytes of public parameter
  fn get_size(&self) -> usize;    // same as above
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<PubParam>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.


* Initialization:
  ``` rust
  fn init(seed: &[u8], ciphersuite: u8) -> Result<PubParam, String> ;
  ```
  * Input: a seed of adequate length
  * Input: ciphersuite ID
  * Output: public parameter
  * Error: ERR_SEED_TOO_SHORT, ERR_CIPHERSUITE
  * Steps:
    1. check seed length and ciphersuite id, return an error if seed is too short or ciphersuite id is not supported.
    2. set `counter = 0`
    2. if `use_rand_generators`
        1. `g2 = hash_to_group(DOM_SEP_PARAM_GEN | ciphersuite | seed | counter, ciphersuite)`
        2. `counter += 1`  
    2. else `g2 = PixelG2::one()`    
    2. `h = hash_to_group(DOM_SEP_PARAM_GEN | ciphersuite | seed | counter, ciphersuite)`
    2. `counter += 1`
    2. for `i` in `0..d+1`
          1. `hlist[i] = hash_to_group(DOM_SEP_PARAM_GEN | ciphersuite | seed | counter, ciphersuite)`
          2. `counter += 1`
    2. return `construct(CONST_D, ciphersuite, g2, h, hlist)`    

## Time
* TimeStamp is a wrapper of `u64`.
  ``` Rust
  type TimeStamp = u64;
  ```
* structure  
  ``` rust
  struct TimeVec {
      time: TimeStamp,    // the actual time stamp, for example 2
      vec: Vec<u64>,      // the path the this time stamp, for example [1, 1]
  }
  ```
* Get various elements from the TimeVec
  ``` rust
  fn get_time(&self) -> TimeStamp ;
  fn get_vector(&self) -> Vec<u64> ;
  fn get_vector_len(&self) -> usize ;
  ```
* Additional functionalities
  ``` Rust
  fn gamma_list(&self, depth: usize) -> Result<Vec<TimeVec>, String> ;
  ```
  It converts a time vector to a list of time vectors,
  so that any future time stamp greater than self is either with in the gamma list,
  or is a posterity of the elements in the list.
    And propagates error messages if the conversion fails.

  Example: for time vector `[1, 1, 1]` and `d = 4`, the list consists
    `[1,1,1], [1,1,2], [1,2], [2]`.
## Master secret key
  * Initialization
    ``` rust
    fn master_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PixelG2, PixelG1), String>
    ```

    * Input: a seed of adequate length
    * Input: public parameter
    * Output: a public key and secret key pair
    * Error: ERR_SEED_TOO_SHORT, ERR_CIPHERSUITE
    * Steps:
      1. check seed length and ciphersuite id, return an error if seed is too short or ciphersuite id is not supported.
      2. `r = hash_to_field(DOM_SEP_MASTER_KEY| ciphersuite | seed, 0)`
      3. `pk = pp.get_g2() ^ r`
      4. `sk = pp.get_h() ^ r`
      5. return `(pk, sk)`



## Public Key

* Structure
  ``` rust
  struct PublicKey {
      ciphersuite:  u8,           // ciphersuite id
      pk:           PixelG2,      // the actual public key element
  }
  ```
* Construct a public key object from some input:
  ``` rust
  fn construct(ciphersuite: u8, pk: PixelG2) -> PublicKey
  ```

* Get various elements from the public key:
  ``` rust
  fn get_pk(&self) -> PixelG2;
  fn get_ciphersuite(&self) -> u8 ;
  ```
* Serialization:  
  ``` rust
  const PK_LEN;                   // size in bytes of public key
  fn get_size(&self) -> usize;    // same as above
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<PublicKey>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.

* Initialization
  ``` rust
  fn init(pp: &PubParam, pk: PixelG2) -> Result<Self, String>
  ```
  * Input: public parameter
  * Input: `pk` generated from `master_key_gen`
  * Output: a public key struct
  * Error: ERR_CIPHERSUITE
  * Steps:
    1. returns an error is `pp.get_ciphersuite()` is not supported.
    2. returns `construct(pp.get_ciphersuite(), pk)`


## Secret Key

* Structure
  ``` rust
  struct SecretKey {
      ciphersuite:  u8,                 // ciphersuite id
      time:         TimeStamp,          // smallest timestamp for all subkeys
      ssk:          Vec<SubSecretKey>,  // the list of the subsecretkeys that are
                                        // stored chronologically based on time stamp
      rngseed:      [u8; 32],           // a seed that is used to generate the randomness
                                        // during key updating
  }
  ```
* Construct a secret key object from some input:
  ``` rust
  fn construct(ciphersuite: u8, time: TimeStamp, ssk: Vec<SubSecretKey>, rngseed: [u8;32]) -> SecretKey
  ```
* Get various elements from the secret key:
  ``` rust
  fn get_ciphersuite(&self) -> u8;
  fn get_time(&self) -> TimeStamp;
  fn get_ssk_number(&self) -> usize;                        // the number of subsecretkeys
  fn get_first_ssk(&self) -> Result<SubSecretKey, String>;  // the first ssk
  fn get_ssk_vec(&self) -> Vec<SubSecretKey>;               // the whole ssk vector
  fn get_rngseed(&self) -> [u8; 32];                        // the seed
  ```
* Serialization:  
  ``` rust
  fn get_size(&self) -> usize;                              // get the storage requirement
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<SecretKey>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.

* Initialization:
  * Each SecretKey is a blob of `|ciphersuite id| number_of_ssk-s | seed | serial(first ssk) | serial(second ssk)| ...`

  ``` Rust
  fn init(pp: &PubParam, alpha: PixelG1) -> Result<SecretKey, String>
  ```
  * Input: public parameter
  * Input: `alpha` generated from `master_key_gen`
  * Output: a secret key struct
  * Error: ERR_CIPHERSUITE, ERR_SERIAL
  * Steps:
    1. returns an error is `pp.get_ciphersuite()` is not supported.
    2. `alpha.serialize(buf, true)`, returns an error is serialization fails
    2. `(extract, updated) = rngseed_extract_and_update(rngseed)`
    3. `r = hash_to_field(DOM_SEP_KEY_INIT|pp.get_ciphersuite()|extract, 0)`
    4. `ssk = SubSecretKey::init(pp, alpha, r)`
    5. return `construct(pp.get_ciphersuite(), 1, [ssk], updated)`

* Update:

  ``` Rust
  fn update(&mut self, pp: &PubParam, tar_time: TimeStamp) -> Result<(), String>
  ```
  * Input: self: a secret key
  * Input: public parameter
  * Input: target time
  * Output: mutate self to an sk for target time
  * Error: ERR_CIPHERSUITE, ERR_SERIAL, ERR_TIME_STAMP
  * Steps:
    1. If the time or ciphersuite is not correct, returns an error
    2. Find the ancestor node `delegator = sk.find_ancestor(tar_time)`, returns an error if time is not correct
    3. Update self to an sk for delegator's time by removing SubSecretKeys whose time stamps are smaller than delegator's time, returns an error if no SubSecretKey is left after removal
    4. If delegator's time equals target time, return success
    5. Generate a gamma list from target time `GammaList = target_time.gamma_list(pp.get_d())`, returns an error if time stamp is invalid
    6. `(extract, updated) = rngseed_extract_and_update(self.get_rngseed())`
    6. Use the first ssk to delegate `delegator_ssk = sk.get_first_ssk()`
    6. for (i, TimeStamp) in Gammalist
        1. if delegator's time is a prefix of TimeStamp
            * `new_ssk = delegator_ssk.delegate(TimeStamp, pp.get_d())`
            * if `i!=0`
              * `r = hash_to_field(DOM_SEP_KEY_UPDATE | ciphersuite | extract,i-1)`
              * re-randomize the ssk via `new_ssk.randomization(pp, r)`
            * `sk.ssk.insert(i+ 1, new_ssk)` so that ssk remains sorted
    6. Remove the delegator's ssk via `sk.ssk.remove(0)`
    7. Update sk's time stamp `sk.time = sk.ssk[0].time`
    7. Update sk's seed `sk.rngseed = updated`        
    6. Return success

* Additional functionalities:
  ``` rust
  fn find_ancestor(&self, tar_time: TimeStamp) -> Result<TimeStamp, String>
  ```
  This function iterates through the existing sub secret keys, find the one for which
  1. the time stamp is the greatest within existing sub_secret_keys
  2. the time stamp is no greater than tar_time

  It returns this subsecretkey's time stamp; or an error if ...
  * there is no ssk in the secret key
  * the target time stamp is invalid for the current time stamp

  Example: suppose we have `sk =  {time: 2, ssks: {omited}}`, and `depth = 4` then
  `sk.find_ancestor(12) = 9`.
  This is an ancestor node for the target time.

  More examples are available in the source code.

  ``` rust
  fn digest(&self) -> Result<Vec<u8>, String>
  ```
  * Input: secret key
  * Output: a secret key digest
  * Error: ERR_SERIAL
  * Steps:
    1. `sk.serilaize(buf, true)`; returns an error if serialization fails
    2. returns `sha256(buf)`

  ``` Rust
  fn validate(&self, pk: &PublicKey, pp: &PubParam) -> bool
  ```
   This function checks if the secret key valid w.r.t the
     public key, the parameters and the sk's time stamp. A secret key is valid if
    * `sk.ciphersuite == pk.ciphersuite == pp.ciphersuite`
    * `sk.ssk.validate(pk, pp)` is valid for all ssk-s (see ssk section)
    * `sk.TimeStamp`'s gamma list forms `ssk.TimeVec` for all ssk-s

## SubSecretKey
* Structure
  ``` rust
  struct SubSecretKey {

      time: TimeStamp,        // timestamp for the current subkey
      g2r: PixelG2,           // randomization on g2: g2^r
      hpoly: PixelG1,         //  h^{alpha + f(x) r}
      hvector: Vec<PixelG1>,  // the randomization of the public parameter hlist
                              // excluding 0 elements
  }
  ```
* Construct a sub secret key object from some input:
  ``` rust
  fn construct(time: TimeStamp, g2r: PixelG2, hpoly: PixelG1, hvector: Vec<PixelG1>) -> SubSecretKey;
  ```
* Get various elements from the sub secret key:
  ``` rust
  fn get_time(&self) -> TimeStamp;
  // Returns the time vector associated with the time stamp.
  fn get_time_vec(&self, depth: usize) -> Result<TimeVec, String>;   
  fn get_g2r(&self) -> PixelG2;
  fn get_hpoly(&self) -> PixelG1;
  fn get_hvector(&self) -> Vec<PixelG1>;
  // Returns the last coefficient of the h_vector.
  fn get_last_hvector_coeff(&self) -> Result<PixelG1, String>;
  ```

* Serialization:
  * Each  ssk into a blob:
`| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
  ``` rust
  fn get_size(&self) -> usize;                              // get the storage requirement
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<SecretKey>;
  ```
The compressed flag will always be `true`. The `reader` and `writer` is assumed
to have allocated sufficient memory, or an error will be returned.

* Initialization:
  ``` rust
  fn init(pp: &PubParam, alpha: PixelG1, r: Fr) -> SubSecretKey
  ```
  * Input: public parameters.
  * Input: a master secret `alpha`.
  * Output: root secret key `[g2^r, h^alpha*h0^r, h1^r, ..., hd^r]` at time stamp = 1.

* Delegation:
  ```Rust
  fn delegate(&mut SubSecretKey, tar_time: TimeStamp, depth: usize) -> Result<(), String> ;
  ```
  Delegate the key into TimeStamp time.
This function does NOT handle re-randomizations.
  * Input: `sk = [g, hpoly, h_{|t|+1}, ..., h_D]`, and a target time `tn`,
  * Output(mutate): `sk = [g, hpoly*\prod_{i=|t|}^|tn| hi^tn[i], h_{|tn|+1}, ..., h_D]`.
  * Error: ERR_TIME_STAMP if
    * the ssk's time vector is not a prefix of the target time,  
    * the ssk's or target time stamp is invalid w.r.t. depth.

* Randomization:

  ```Rust
  fn randomization(&mut SubSecretKey, pp: &PubParam, r: Fr) -> Result<(), String>
  ```
  * Input: subsecrerkey `sk = [g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r]`,
  * Input: re-randomization field element `r`,
  * Output(mutate): `g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r`.
  * Error: ERR_TIME_STAMP if the ssk's time stamp is invalid w.r.t the depth in the public parameter.


* Additional functionalities:
  ``` Rust
  fn validate(&SubSecretKey, pk: &PublicKey, pp: &PubParam) -> bool
  ```

  This function is used to verify if a subsecretkey is valid
for some public key by checking         ` e(hpoly, g2) ?= e(h, pk) * e(h0*\prod hi^ti, g2r)`
  where `ti` are elements in ssk's time vector.


## Signature

* Structure
  ``` rust
  struct Signature {
      ciphersuite: u8,  
      time: TimeStamp,
      sigma1: PixelG2,
      sigma2: PixelG1,
  }
  ```
* Construct a signature object from some input:
  ``` rust
  fn construct(ciphersuite: u8, time: TimeStamp, sigma1: PixelG2, sigma2: PixelG1) -> Signature;
  ```
* Get various elements from the secret key:
  ``` rust
  fn get_ciphersuite(&self) -> u8;
  fn get_time(&self) -> TimeStamp;
  fn get_sigma1(&self) -> PixelG2 ;
  fn get_sigma2(&self) -> PixelG1 ;
  ```
* Serialization:  
  * A signature is a blob `|ciphersuite id| time | sigma1 | sigma2 |`

  ``` rust
  cosnt SIG_LEN;                             // a signature is 149 bytes
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<SecretKey>;
  ```

* Sign:
  ``` rust
  fn sign_bytes(
        sk: &SecretKey,
        tar_time: TimeStamp,
        pp: &PubParam,
        msg: &[u8],
        seed: &[u8],
    ) -> Result<Self, String>
  ```
  * Input: secret key, target time, public parameter, message to sign, seed for randomness
  * Output: a signature
  * Error: ERR_TIME_STAMP, ERR_CIPHERSUITE
  * Steps:
    1. returns an error if secret key's time stamp is greater than target time
    1. returns an error if the ciphersuite in pp or sk doesn't match.
    1. hash message to a field element `m = hash_to_field(DOM_SEP_HASH_TO_MSG| ciphersuite |msg, 0)`
    1. hash seed to a field element `r = hash_to_field(DOM_SEP_SIG| ciphersuite |seed, 0)`
    2. use the first SubSecretKey for signing `ssk = sk.get_first_ssk()`
    2. re-randomizing sigma1: `sig1 = ssk.g2r + g2^r`
    2. re-randomizing sigma2
        1. `tmp = h0 * \prod h_i ^ t_i * h_d^m`
        2. `sig2 = ssk.hpoly * hv[d]^m * tmp^r`
    3. return `Signature{pp.ciphersuite(), tar_time, sig1, sig2}`


* Verify (TODO)

* Signature aggregation (TODO)




* Verify aggregated signature (TODO)



## Misc
* Extract and update the seed
  ``` Rust
  fn rngseed_extract_and_update(rngseed: &[u8; 32]) -> ([u8; 32], [u8; 32]);
  ```
  * Input: a seed
  * Output: `rngseed_updated      =  sha256 (DOM_SEP_SEED_UPDATE|rngseed)`
  * Output: `rngseed_extracted    =  sha256 (DOM_SEP_SEED_EXTRACT|rngseed)`


# Seed and rng

This section describes how randomness and seed are handled. A tentative definition of domain separators are available in src/domain_sep.rs. `|` is the concatenation of the byte strings.

* The parameter generation function takes a seed as one of the inputs. This seed is provided by the caller (our go library). The rust code checks if the seed is longer than 32 bytes. It does not perform any extra operations over the seed. The caller needs to make sure that the seed is well formed and has enough entropy, etc.
Then, the generators in the parameters are generated from `hash_to_group(input, ciphersuite)`
function, where the input is
`DOM_SEP_PARAM_GEN | ciphersuite | seed | ctr`. The `ctr` is incremental for multiple group elements.
The `ctr` does not reset if when we generate generators for different groups. (It seems redundant to have a ciphersuite id in both `input` and `ciphersuite` fields. But this is only one byte and should not
  affect the performance in most cases. It is also consistent with the rest of the inputs for `hash_to_field`.)

* The key generation function also takes a seed as one of the inputs. This seed is also provided by the caller. Same check on the seed is done as in parameter generation.
  * A master secret (`x`, or `alpha`, i.e., the exponent for the pk) is generated from
  `hash_to_field(input, 0)`, where the input is `DOM_SEP_MASTER_KEY | ciphersuite | seed`.
  * A rngseed is generated from `sha256(DOM_SEP_SEED_INIT | ciphersuite | seed)`. This rngseed is part of the secret key, and will be used for deterministic updating and signing.
  * During a (fast) key updating, the random field elements are generated from
  `hash_to_field(input, ctr)`, where `input = DOM_SEP_KEY_UPDATE | ciphersuite | extracted_seed`, and
  `ctr` is incremental in case multiple field elements are required.
  Every time an extracted_seed is extracted during key updating, the rngseed will be updated.
   The extraction (and seed updating) is done as follows:
    * `extracted_seed = sha256(DOM_SEP_SEED_EXTRACT | rngseed)`
    * `rngseed = sha256(DOM_SEP_SEED_UPDATE | rngseed)`   

* During the signing procedure, the random field element is generated from
`hash_to_field(input, ctr)`, where `input = DOM_SEP_SIG | ciphersuite | rngseed | message | time stamp`.
The rngseed will __NOT__ be updated during signing, so that for the same message and time stamp, we
will always generate a same signature.
