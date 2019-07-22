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
* The parameters are defined and generated in a separate crate [pixel_param](https://github.com/algorand/pixel_param).
Pixel will use the __default__ parameter set from pixel_param.
The default parameter set was generated with a seed = SHA512's initial vector.
The parameter set can be accessed via

  ```rust
  PubParam::default();  // access the fault parameter set
  ```

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


## Pseudo random generators

* Structure
  ``` Rust
  struct PRNG([u8; 64]);  // PRNG is a wrapper of 64 bytes array
  ```

* Initialization
  ``` Rust
  // initialize the prng with a seed and a salt
  fn init<Blob: AsRef<[u8]>>(seed: Blob, salt: Blob) -> PRNG;

  ```
  * Input: a seed of adequate length
  * Input: a (public) salt
  * Output: a PRNG
  * Steps:
    1. `m = HKDF-SHA512-extract(seed, salt)`
    2. `return PRNG(m)`

* Sample and update
  ``` rust
  // sample a field element from PRNG, and update the internal state
  fn sample_then_update<Blob: AsRef<[u8]>>(&mut self, info: Blob, ctr: u8) -> Fr;
  ```
  * Input: the prng
  * Input: public info
  * Input: ctr
  * Output: a field element
  * Output: update self's state
  * Steps:
    1. `tmp = HKDF-SHA512-expand(prng, info, 128)`
    2. `prng = PRNG(tmp[64:128])`
    3.  return `hash_to_field(tmp[0:64], ctr)`

* Sample (without update)
  ``` rust
  // sample a field element from PRNG
  fn sample<Blob: AsRef<[u8]>>(&self, info: Blob, ctr: u8) -> Fr;
  ```
  * Input: the prng
  * Input: public info
  * Input: ctr
  * Output: a field element
  * Steps:
    1. `tmp = HKDF-SHA512-expand(prng, info, 64)`
    2. return `hash_to_field(tmp[0:64], ctr)`


## Master secret key

* Initialization
  ``` rust
  fn master_key_gen(seed: &[u8], pp: &PubParam) -> Result<(PixelG2, PixelG1, PixelG1, PRNG), String>
  ```

  * Input: a seed of adequate length
  * Input: public parameter
  * Output: a public key, a master secret key, a proof of possession of the public key and a seed for PRNG
  * Error: ERR_SEED_TOO_SHORT, ERR_CIPHERSUITE
  * Steps:
    1. check seed length and ciphersuite id, return an error if seed is too short or ciphersuite id is not supported.
    2. `salt = DOM_SEP_MASTER_KEY| ciphersuite`
    3. `prng = PRNG::init(seed, salt)`
    3. `info = "key initialization"`
    3. `x = prng.sample_then_update(info, 0)`
    3. `pk = pp.get_g2() ^ x`
    4. `sk = pp.get_h() ^ x`
    5. `pop = proof_of_possession(x, pk, pp.ciphersuite)`
    5. return `(pk, sk, pop, prng)`

## Proof of possession

* Struct
  ``` rust
  struct ProofOfPossession {
      ciphersuite: u8,  /// ciphersuite id
      pop: PixelG1,     /// the actual public key element
  }
  ```

* Get various elements from the PoP:
  ``` rust
  fn get_pop(&self) -> PixelG1;
  fn get_ciphersuite(&self) -> u8 ;
  ```
* Serialization:  
  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<PublicKey>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.

* Generate PoP
  ``` Rust
  fn proof_of_possession(msk: Fr, pk: PixelG2, ciphersuite: u8) -> Result<PixelG1, String>
  ```
  * Input: the exponent of the public key
  * Input: public key
  * Input: ciphersuit id
  * Output: a proof of possession for the public key
  * Error: ERR_SERIAL
  * Steps:
    1. `msg = DOM_SEP_POP | pk.serial()`  
    2. `pop = BLSSignature::sign(msk, buf, ciphersuite)`
    3. return `ProofOfPossession{ciphersuite, pop}`


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

* Verify pk against PoP
  ``` Rust
  fn validate(&self, pop: &ProofOfPossession) -> bool
  ```
  * Input: public key
  * Input: the pop
  * Output: true if pop is a proof of possession for pk
  * Error: ERR_SERIAL, ERR_CIPHERSUITE
  * Steps:
    1. return false if ciphersuites of pop and pk don't match
    1. `msg = DOM_SEP_POP | pk.serial()`  
    2. `sig = pop.get_pop()`
    3. return `BLSSignature::verify(pk, sig, msg, pk.get_ciphersuite())`


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
  fn construct(ciphersuite: u8, time: TimeStamp, ssk: Vec<SubSecretKey>, prng: PRNG) -> SecretKey
  ```
* Get various elements from the secret key:
  ``` rust
  fn get_ciphersuite(&self) -> u8;
  fn get_time(&self) -> TimeStamp;
  fn get_ssk_number(&self) -> usize;                        // the number of subsecretkeys
  fn get_first_ssk(&self) -> Result<SubSecretKey, String>;  // the first ssk
  fn get_ssk_vec(&self) -> Vec<SubSecretKey>;               // the whole ssk vector
  fn get_prng(&self) -> PRNG;                               // the seed
  ```
* Serialization:  
  * Each SecretKey is a blob of `|ciphersuite id| number_of_ssk-s | prng | serial(first ssk) | serial(second ssk)| ...`

  ``` rust
  fn get_size(&self) -> usize;                              // get the storage requirement
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<SecretKey>;
  ```
  The compressed flag will always be `true`. The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.

* Initialization:

  ``` Rust
  fn init(pp: &PubParam, alpha: PixelG1, prng: PRNG) -> Result<SecretKey, String>
  ```
  * Input: public parameter
  * Input: `alpha` generated from `master_key_gen`
  * Output: a secret key struct
  * Error: ERR_CIPHERSUITE, ERR_SERIAL
  * Steps:
    1. returns an error is `pp.get_ciphersuite()` is not supported.
    2. info = "key initialization"
    3. `r = prng.sample_then_update(info, 0)`
    4. `ssk = SubSecretKey::init(pp, alpha, r)`
    5. return `construct(pp.get_ciphersuite(), 1, [ssk], prng)`

* Update:

  ``` Rust
  fn update(&mut self, pp: &PubParam, tar_time: TimeStamp) -> Result<(), String>
  ```
  * Input: self, a secret key
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
    6. Use the first ssk to delegate `delegator_ssk = sk.get_first_ssk()`
    6. for (i, TimeStamp) in Gammalist
        1. if delegator's time is a prefix of TimeStamp
            * `new_ssk = delegator_ssk.delegate(TimeStamp, pp.get_d())`
            * if `i!=0`
              * info = "key updating"
              * `r = sk.sample_then_update(info, i-1)`
              * re-randomize the ssk via `new_ssk.randomization(pp, r)`
            * `sk.ssk.insert(i + 1, new_ssk)` so that ssk remains sorted
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

  Example: suppose we have `sk =  {time: 2, ssks: {omitted}}`, and `depth = 4` then
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
    1. `sk.serialize(buf, true)`; returns an error if serialization fails
    2. returns `sha512(buf)`

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
      sigma1: PixelG1,
      sigma2: PixelG2,
  }
  ```
* Construct a signature object from some input:
  ``` rust
  fn construct(ciphersuite: u8, time: TimeStamp, sigma1: PixelG1, sigma2: PixelG2) -> Signature;
  ```
* Get various elements from the secret key:
  ``` rust
  fn get_ciphersuite(&self) -> u8;
  fn get_time(&self) -> TimeStamp;
  fn get_sigma1(&self) -> PixelG1 ;
  fn get_sigma2(&self) -> PixelG2 ;
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
    ) -> Result<Self, String>
  ```
  * Input: secret key, target time, public parameter, message to sign
  * Output: a signature
  * Error: ERR_TIME_STAMP, ERR_CIPHERSUITE
  * Steps:
    1. returns an error if secret key's time stamp is greater than target time
    1. returns an error if the ciphersuite in pp or sk doesn't match.
    1. info = DOM_SEP_SIG | msg
    1. sample `r = sk.prng.sample(info, 0)`
    2. set `m = hash_msg_into_fr(msg, ciphersuite)`
    2. use the first SubSecretKey for signing `ssk = sk.get_first_ssk()`
    2. re-randomizing sigma2: `sig1 = ssk.g2r * g2^r`
    2. re-randomizing sigma1
        1. `tmp = h0 * \prod h_i ^ t_i * h_d^m`
        2. `sig2 = ssk.hpoly * hv[d]^m * tmp^r`
    3. return `Signature{pp.ciphersuite(), tar_time, sig1, sig2}`


* Verify
  ``` rust
  fn verify_bytes(&self, pk: &PublicKey, pp: &PubParam, msg: &[u8]) -> bool
  ```
  * Input: signature, public key, public parameter and message
  * Output: true if the signature is valid w.r.t. the message and public key
  * Steps:
    1. returns an error if the ciphersuite in pp or sk doesn't match.
    2. returns an error if either sig1 or sig2 is not in the right prime subgroup
    3. set `m = hash_msg_into_fr(msg, ciphersuite)`
    4. set `t = self.tar_time`
    5. compute `hfx = h0 * h_i ^ t_i * h_d ^ m`
    6. return `e(1/g2, sigma1) * e( sigma2, hfx) * e(pk, h) == 1`

* hash message to a field element
  ``` Rust
  fn hash_msg_into_fr(msg: &[u8], ciphersuite: u8) -> Fr
  ```
  * Input: a message, a ciphersuite
  * Output: a field element
  * Steps:
    1. `m = DOM_SEP_HASH_TO_MSG | ciphersuite | msg`
    2. return `hash_to_field(m, 0)`

* Signature aggregation
  ``` Rust
  fn aggregate_without_validate(sig_list: &[Self]) -> Result<Self, String>
  ```
  * Input: a list of signatures
  * Output: an aggregated signature
  * Error: time stamps not consistent; ERR_CIPHERSUITE
  * Steps:
    1. if the ciphersuites are not consistent, return error
    2. if the time stamps are not consistent, return error
    3. sig = sig_list[0]
    4. for i in 1..sig_list.len()
        * `sig.sigma1 *= sig_list[i].sigma1`
        * `sig.sigma2 *= sig_list[i].sigma2`
    5. return sig

* Verify aggregated signature
  ```rust
  verify_bytes_aggregated(&self,
        pk_list: &[PublicKey],
        pp: &PubParam,
        msg: &[u8],
    ) -> bool
  ```  
  * Input: self, an aggregated signature
  * Input: a list of public keys
  * Input: public parameters
  * Input: a message
  * Output: true if the signature is a valid aggregated signature w.r.t. public keys and parameters
  * Steps:
    1. return error if signature's ciphersuite does not match the public keys' or the public parameters
    2. `agg_pk = pk_list[0]`
    3. for for i in 1..pk_list.len()
        * `agg_pk.pk *= pk_list[i].pk`
    4. return `verify(sig, pk, pp, msg)`


# Seed and rng

This section describes how randomness and seed are handled. A tentative definition of domain separators are available in src/domain_sep.rs. `|` is the concatenation of the byte strings.
We will be using the following functions

    * HKDF-Extract(salt , seed) -> secret
    * HKDF-Expand(secret, public_info, length_of_new_secret) -> new_secret
    * hash_to_group(input, ciphersuite) -> group element
    * hash_to_field(input, ctr = 0) -> field element


* The parameter generation function takes a seed as one of the inputs. This seed is provided by the caller (our go library). The rust code checks if the seed is longer than 32 bytes.
Rust code does not perform any extra checks over the seed. The caller needs to make sure that the seed is well formed and has enough entropy, etc. We use SHA512's IV as the seed.
Then, we generate the generators as follows:
  * Input: `seed`
  * Output: `param = [g2, h, h0, ... hd]`
  * Steps:
    1. set `g2 = PixelG2::one`; this is the default generator of bls12-381 curve
    2. extract the randomness from the seed:
    `m = HKDF-Extract(DOM_SEP_PARAM_GEN , seed)`
    3. generate `h` as follows
        * `info = "H2G_h"`
        * `t = HKDF-Expand(m, info, 32)`
        * `h = hash_to_group(t, ciphersuite)`
    4. generate `h_0 ... h_d` as follows:
        * `info = "H2G_h" | I2OSP(i)`
        * `t = HKDF-Expand(m, info, 32)`
        * `h_i = hash_to_group(t, ciphersuite)`
    5. output   
    `[g2, h, h_0 ... h_d]`


<!--
`DOM_SEP_PARAM_GEN | ciphersuite | seed | ctr`. The `ctr` is incremental for multiple group elements.
The `ctr` does not reset if when we generate generators for different groups. (It seems redundant to have a ciphersuite id in both `input` and `ciphersuite` fields. But this is only one byte and should not
  affect the performance in most cases. It is also consistent with the rest of the inputs for `hash_to_field`.) -->


* The master key generation function also takes a seed as one of the inputs. This seed is also provided by the caller. Same check on the seed is done as in parameter generation.
The field element is generated as follows:
  * Input: `seed`, parameter set
  * Output: the secret exponent `x` and an rngseed
  * Steps:
    * `m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)`
    * `info = "key initialization"`
    * `t = HKDF-Expand(m, info, 64)`
    * `x = hash_to_field(t[0..31], 0)`
    * initialize the rng seed as `rngseed = t[32..63]`

<!--
  * A master secret (`x`, or `alpha`, i.e., the exponent for the pk) is generated from
  `hash_to_field(input, 0)`, where the input is `DOM_SEP_MASTER_KEY | ciphersuite | seed`.
  * A rngseed is generated from `sha256(DOM_SEP_SEED_INIT | ciphersuite | seed)`. This rngseed is part of the secret key, and will be used for deterministic updating and signing. -->


* During a (fast) key updating, a random field element is generated
as follows:
  * Input: `rngseed` from the secret key
  * Output: a field element `r`
  * Steps:
    * `info = "key updating"`
    * `t = HKDF-Expand(m, info, 128)`
    * `r = hash_to_field(t[0..64], 0)`
    * update the rngseed as `rngseed = t[64..128]`


<!-- from
  `hash_to_field(input, ctr)`, where `input = DOM_SEP_KEY_UPDATE | ciphersuite | extracted_seed`, and
  `ctr` is incremental in case multiple field elements are required.
  Every time an extracted_seed is extracted during key updating, the rngseed will be updated.
   The extraction (and seed updating) is done as follows:
    * `extracted_seed = sha256(DOM_SEP_SEED_EXTRACT | rngseed)`
    * `rngseed = sha256(DOM_SEP_SEED_UPDATE | rngseed)`    -->

* During the signing procedure, a random field element is generated as follows:
  * Input: `rngseed` from the secret key
  * Output: a field element `r`
  * Steps:
    * `info = "signing" | message`
    * `t = HKDF-Expand(m, info, 64)`
    * `r = hash_to_field(t[0..64], 0)`

The rngseed is not updated, so that for a same message, we
will always generate a same signature.


<!-- from
`hash_to_field(input, ctr)`, where `input = DOM_SEP_SIG | ciphersuite | rngseed | message | time stamp`.
The rngseed will __NOT__ be updated during signing, so that for the same message and time stamp, we
will always generate a same signature. -->
