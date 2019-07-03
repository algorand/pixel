# Pixel Signature

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
* Structure
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
  * associated functions

  ``` rust
  const PP_LEN;                   // size in bytes of public parameter
  fn get_size(&self) -> usize;    // same as above
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<PubParam>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.


* Initialization:
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
### TimeStamp
  ``` Rust
  type TimeStamp = u64;
  ```
### TimeVec  
  ``` rust
  struct TimeVec {
      time: TimeStamp,
      vec: Vec<u64>,
  }
  ```

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

* structure
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
  }
  ```
* Construct a secret key object from some input:
  ``` rust
  fn construct(ciphersuite: u8, time: TimeStamp, ssk: Vec<SubSecretKey>) -> SecretKey
  ```
* Get various elements from the secret key:
  ``` rust
  fn get_ciphersuite(&self) -> u8;
  fn get_time(&self) -> TimeStamp;
  fn get_ssk_number(&self) -> usize;                        // the number of subsecretkeys
  fn get_first_ssk(&self) -> Result<SubSecretKey, String>;  // the first ssk
  fn get_ssk_vec(&self) -> Vec<SubSecretKey>;               // the whole ssk vector
  ```
* Serialization:  
  ``` rust
  fn get_size(&self) -> usize;    // get the storage requirement
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<SecretKey>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.

* Initialization:
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
    3. `r = hash_to_field(DOM_SEP_KEY_INIT|pp.get_ciphersuite()|buf, 0)
    4. `ssk = SubSecretKey::init(pp, alpha, r)`
    5. return `construct(pp.get_ciphersuite(), 1, [ssk])`

* Update:

  ``` Rust
  fn update<'a>(&'a mut self, pp: &PubParam, tar_time: TimeStamp) -> Result<(), String>
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
    6. Digest the sk into a shorter blob `sk_digest = sk.digest()`
    6. Use the first ssk to delegate `delegator_ssk = sk.get_first_ssk()`
    6. for (i, TimeStamp) in Gammalist
        1. if delegator's time is a prefix of TimeStamp
            * `new_ssk = delegator_ssk.delegate(TimeStamp, pp.get_d())`
            * if `i!=0`
              * `r = hash_to_field(DOM_SEP_KEY_UPDATE | ciphersuite | sk_digest,i-1)`
              * re-randomize the ssk via `new_ssk.randomization(pp, r)`
            * `sk.ssk.insert(i+ 1, new_ssk)` so that ssk remains sorted
    6. Remove the delegator's ssk via `sk.ssk.remove(0)`
    7. Update sk's time stamp `sk.time = sk.ssk[0].time`        
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


## SubSecretKey

## Signature
