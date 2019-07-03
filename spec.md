# Pixel Signature



## Parameter

### Ciphersuite  
  * Currently supports `0x00` and `0x01`.
  * The maps between ciphersuite IDs and actual parameters are TBD.
  * Additional ciphersuite identifiers may be added later.

### Depth of time tree
  * `CONST_D`: A constant set to `30`. This allows for `170` years of time stamps if
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
      ssk:          Vec<SubSecretKey>,  // the list of the subsecretkeys
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
