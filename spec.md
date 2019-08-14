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
  we use a timestamp every `5` seconds.

### Pairing group

  * `PixelG1` defines the G1 group in the paper; it is mapped to BLS12-381 G2 group.
  * `PixelG2` defines the G2 group in the paper; it is mapped to BLS12-381 G1 group.

### Public Parameter
* Structure
  ``` rust
  struct PubParam {
      depth:        usize,              // the depth of the time vector
      ciphersuite:  u8,                 // ciphersuite id
      g2:           PixelG2,            // generator for PixelG2 group
      h:            PixelG1,            // h
      hlist:        [PixelG1; d + 1],   // h_0, h_1, ..., h_d
  }
  ```
* The parameters are defined and generated in a separate crate [pixel_param](https://github.com/algorand/pixel_param).
Pixel will use the __default__, pre-computed parameter set from pixel_param.
The default parameter set was generated with a seed = SHA512's initial vector.
The parameter set can be accessed via

  ```rust
  PubParam::default();    // access the fault parameter set
  ```

## Time
* TimeStamp is a wrapper of `u64`.
  ``` Rust
  type TimeStamp = u64;
  ```
* Structure  
  ``` rust
  struct TimeVec {
      time: TimeStamp,    // the actual time stamp, for example 2
      vec: Vec<u64>,      // the path to this time stamp, for example [1, 1]
  }
  ```
* Get various elements from the TimeVec
  ``` rust
  fn time(&self) -> TimeStamp ;
  fn vector(&self) -> Vec<u64> ;
  fn vector_len(&self) -> usize ;
  ```
* Additional functionalities
  ``` Rust
  fn gamma_list(&self, depth: usize) -> Result<Vec<TimeVec>, String> ;
  ```
  It converts a time vector to a list of time vectors,
  so that any future time stamp greater than self is either with in the gamma list,
  or is a posterity of the elements in the list.
    And propagates error messages if the conversion fails.

  Example: for time vector `[1, 1, 1]` and `depth = 4`, the list consists
    `[1,1,1], [1,1,2], [1,2], [2]`.


## Pseudo random generators
NOTE: this part of the spec is NOT documented in the paper.
It is the result of a serial of internal discussion.

* Structure
  ``` Rust
  struct PRNG([u8; 64]);  // PRNG is a wrapper of a 64 bytes array
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
  fn sample_then_update<Blob: AsRef<[u8]>>(&mut self, info: Blob) -> Fr;
  ```
  * Input: the prng
  * Input: public info
  * Output: a field element
  * Output: update self's state
  * Steps:
    1. `tmp = HKDF-SHA512-expand(prng, info, 128)`
    2. update self: `prng = PRNG(tmp[64:128])`
    3.  return `OS2IP(tmp[0:64]) mod p`

* Sample (without update)
  ``` rust
  // sample a field element from PRNG
  fn sample<Blob: AsRef<[u8]>>(&self, info: Blob) -> Fr;
  ```
  * Input: the prng
  * Input: public info
  * Output: a field element
  * Steps:
    1. `tmp = HKDF-SHA512-expand(prng, info, 64)`
    2. return `OS2IP(tmp[0:64]) mod p`

* Re-randomization
  ``` rust
  // re_randomize the prng with a new seed and some salt
  fn re_randomize<Blob: AsRef<[u8]>>(&mut self, seed: Blob, salt: Blob, info: Blob);
  ```
  * Input: the prng
  * Input: a seed, a salt, and a info for re-randomization
  * Output: update self's state
  * Steps:
    1. `m1 = HKDF-SHA512-Expand(prng, info, 64)`
    1. `m = HKDF-SHA512-Extract(m1|seed, salt)`
    2. Updated self with `PRNG(m)`


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
    3. `info = "Pixel master key"`
    3. `x = prng.sample_then_update(info)`
    3. `pk = pp.g2() ^ x`
    4. `sk = pp.h() ^ x`
    5. `pop = proof_of_possession(x, pk, pp.ciphersuite)`
    5. return `(pk, sk, pop, prng)`

## Proof of possession

* Structure
  ``` rust
  struct ProofOfPossession {
      ciphersuite: u8,  /// ciphersuite id
      pop: PixelG1,     /// the actual pop element
  }
  ```

* Get various elements from the PoP:
  ``` rust
  fn pop(&self) -> PixelG1;
  fn ciphersuite(&self) -> u8 ;
  ```
* Serialization:  
  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<(ProofOfPossession, bool)>;
  ```
  * The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
  * `Deserialize` function will also return a flag that wether the `reader` is
  in compressed format or not.
  The compressed flag will always be `true`, as a requirement of strong
  unforgeability. An error will be returned if the `reader` is not compressed.

* Generate PoP
  ``` Rust
  fn proof_of_possession(msk: Fr, pk: PixelG2, ciphersuite: u8) -> Result<PixelG1, String>
  ```
  * Input: the exponent of the public key
  * Input: the actual public key group element
  * Input: ciphersuit id
  * Output: a proof of possession for the public key
  * Error: ERR_SERIAL
  * Steps:
    1. `msg = DOM_SEP_POP | pk.serialize()`  
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
  fn new(ciphersuite: u8, pk: PixelG2) -> PublicKey
  ```

* Get various elements from the public key:
  ``` rust
  fn pk(&self) -> PixelG2;
  fn ciphersuite(&self) -> u8 ;
  ```
* Serialization:  
  ``` rust
  const PK_LEN;                   // size in bytes of public key
  fn size(&self) -> usize;    // same as above
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<(PublicKey, bool)>;
  ```
  * The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
  * `Deserialize` function will also return a flag that wether the `reader` is
  in compressed format or not.
  The compressed flag can be either `true` or `false`.

* Initialization
  ``` rust
  fn init(pp: &PubParam, pk: PixelG2) -> Result<Self, String>
  ```
  * Input: public parameter
  * Input: `pk` generated from `master_key_gen`
  * Output: a public key struct
  * Error: ERR_CIPHERSUITE
  * Steps:
    1. returns an error is `pp.ciphersuite()` is not supported.
    2. returns `new(pp.ciphersuite(), pk)`

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
    2. `sig = pop.pop()`
    3. return `BLSSignature::verify(pk, sig, msg, pk.ciphersuite())`


## Secret Key

* Structure
  ``` rust
  struct SecretKey {
      ciphersuite:  u8,                 // ciphersuite id
      time:         TimeStamp,          // smallest timestamp for all subkeys
      ssk:          Vec<SubSecretKey>,  // the list of the subsecretkeys that are
                                        // stored chronologically based on time stamp
      rngseed:      [u8; 64],           // a seed that is used to generate the randomness
                                        // during key updating
  }
  ```
* Construct a secret key object from some input:
  ``` rust
  fn new(ciphersuite: u8, time: TimeStamp, ssk: Vec<SubSecretKey>, prng: PRNG) -> SecretKey
  ```
* Get various elements from the secret key:
  ``` rust
  fn ciphersuite(&self) -> u8;
  fn time(&self) -> TimeStamp;
  fn ssk_number(&self) -> usize;                        // the number of subsecretkeys
  fn first_ssk(&self) -> Result<SubSecretKey, String>;  // the first ssk
  fn ssk_vec(&self) -> Vec<SubSecretKey>;               // the whole ssk vector
  fn prng(&self) -> PRNG;                               // the seed
  ```
* Serialization:  
  * Each SecretKey is a blob of `|ciphersuite id| number_of_ssk-s | prng | serial(first ssk) | serial(second ssk)| ...`

  ``` rust
  fn size(&self) -> usize;                              // get the storage requirement
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<(SecretKey, bool)>;
  ```
  * The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
  * `Deserialize` function will also return a flag that wether the `reader` is
  in compressed format or not.
  The compressed flag can be either `true` or `false`. However, the flag needs to
  be consistent for all its components.

* Initialization:

  ``` Rust
  fn init(pp: &PubParam, alpha: PixelG1, prng: PRNG) -> Result<SecretKey, String>
  ```
  * Input: public parameter
  * Input: `alpha` generated from `master_key_gen`
  * Output: a secret key struct
  * Error: ERR_CIPHERSUITE, ERR_SERIAL
  * Steps:
    1. returns an error is `pp.ciphersuite()` is not supported.
    2. `time = 1`
    2. `info = "Pixel secret key init" | time`
    3. `r = prng.sample_then_update(info)`
    4. `ssk = SubSecretKey::init(pp, alpha, r)`
    5. return `construct(pp.ciphersuite(), 1, [ssk], prng)`

* Update:

  ``` Rust
  fn update<Blob: AsRef<[u8]>>(&mut self, pp: &PubParam, tar_time: TimeStamp, seed: Blob) -> Result<(), String>
  ```
  * Input: self, a secret key
  * Input: public parameter
  * Input: target time
  * Input: a seed to re-randomize the prng
  * Output: mutate self to an sk for target time
  * Error: ERR_CIPHERSUITE, ERR_SERIAL, ERR_TIME_STAMP
  * Steps:
    1. If the time or ciphersuite is not correct, returns an error
    4. Re-randomize sk's prng: `sk.prng.re-randomize(seed, info)` where
        * `info = "Pixel secret key rerandomize expand" | self.time()`
    2. Find the ancestor node `delegator = sk.find_ancestor(tar_time)`, returns an error if time is not correct
    3. Update self to an sk for delegator's time by removing SubSecretKeys whose time stamps are smaller than delegator's time, returns an error if no SubSecretKey is left after removal


    4. If delegator's time equals target time, return success

    5. Generate a gamma list from target time `GammaList = tartime.gamma_list(pp.depth())`, returns an error if time stamp is invalid
    6. Use the first ssk to delegate `delegator_ssk = sk.first_ssk()`
    6. for (i, TimeStamp) in Gammalist
        1. if delegator's time is a prefix of TimeStamp
            * `new_ssk = delegator_ssk.delegate(TimeStamp, pp.depth())`
            * if `i!=0`
              * `info = "Pixel secret key update" | self.time()`
              * `r = sk.prng.sample_then_update(info)`
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
   This function checks if the secret key is valid w.r.t the
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
  fn new(time: TimeStamp, g2r: PixelG2, hpoly: PixelG1, hvector: Vec<PixelG1>) -> SubSecretKey;
  ```
* Get various elements from the sub secret key:
  ``` rust
  fn time(&self) -> TimeStamp;
  // Returns the time vector associated with the time stamp.
  fn time_vec(&self, depth: usize) -> Result<TimeVec, String>;   
  fn g2r(&self) -> PixelG2;
  fn hpoly(&self) -> PixelG1;
  fn hvector(&self) -> Vec<PixelG1>;
  // Returns the last coefficient of the h_vector.
  fn last_hvector_coeff(&self) -> Result<PixelG1, String>;
  ```

* Serialization:
  * Each  ssk is a blob:
`| time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |`
  ``` rust
  fn size(&self) -> usize;                              // get the storage requirement
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<(SubSecretKey, bool)>;
  ```
  * The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
  * `Deserialize` function will also return a flag that wether the `reader` is
  in compressed format or not.
  The compressed flag can be `true` or `false`. However, the flag needs to
  be consistent for all its components.

* Initialization:
  ``` rust
  fn init(pp: &PubParam, alpha: PixelG1, r: Fr) -> SubSecretKey
  ```
  * Input: public parameters.
  * Input: a master secret `alpha`.
  * Output: root secret key `[g2^r, h^alpha*h0^r, h1^r, ..., hd^r]` at time stamp = 1.
  * Steps:
    1. `g2r = pp.g2()^r`
    2. `hpoly = pp.h()^alpha * pp.hlist()[0]^r`
    3. for i in `[1..=d]`:
      * `hvector[i-1] = pp.hlist()[i]^r`
    5. return `SubSecretKey{pp.ciphersuit, 1, g2r, hpoly, hvector}`

* Delegation:
  ```Rust
  fn delegate(&mut SubSecretKey, tar_time: TimeStamp, depth: usize) -> Result<(), String> ;
  ```
  Delegate the key into TimeStamp time.
This function does NOT handle re-randomizations.
  * Input: `sk = [g, hpoly, h_{|t|+1}, ..., h_D]`, and a target time `tn`,
  * Output: update sk to `sk = [g, hpoly*\prod_{i=|t|}^|tn| hi^tn[i], h_{|tn|+1}, ..., h_D]`.
  * Error: ERR_TIME_STAMP if
    * the ssk's time vector is not a prefix of the target time,  
    * the ssk's or target time stamp is invalid w.r.t. depth.
  * Steps:
    1. `cur_tv = time_to_vec(sk.time, depth)`
    2. `tar_tv = time_to_vec(tar_time, depth)`
    2. if `cur_tv` is not a prefix of `tar_tv`, return `ERR_TIME_STAMP`
    3. for i in `0..tar_tv.len()-cur_tv.len()`  
        * `sk.hpoly *= sk.hlist[i]^tar_tv[i+cur_tv.len()]`
    4. for i in `0..tar_tv.len()-cur_tv.len()`  
        * del `sk.hlist[0]`


* Randomization:

  ```Rust
  fn randomization(&mut SubSecretKey, pp: &PubParam, r: Fr) -> Result<(), String>
  ```
  * Input: subsecrerkey `sk = [g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r]`,
  * Input: re-randomization field element `r`,
  * Output(mutate): `g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r`.
  * Error: ERR_TIME_STAMP if the ssk's time stamp is invalid w.r.t the depth in the public parameter.
  * Steps:

    1. `tv = ssk.time_vec()`
    1. `hlist = pp.hlist()`
    1. `sk.g2r *= pp.g2()^r`
    2. `hpoly_base =  hlist[0]`
    2. for i in range(tv.len())
        * `hpoly_base *= hlist[i+1]^tv[i]`
    3 `sk.hpoly *= hpoly_base^r`
    4. for i in range(sk.hvector.len())
          * `sk.hvector[i] *= hlsit[i+tv.len()+1]^r`
    5. mutate self to `SubSecretKey{pp.ciphersuite, sk.time, sk.g2r, sk.hpoly, sk.hvector}`    

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
  This follows the [python code](https://github.com/hoeteck/pixel/blob/2dfc15c6b3bcd47fd2061cccf358ff685b7ed03e/pixel.py#L354)  by having sigma1 in PixelG2 and sigma2 in PixelG1.
  Note that it is the opposite in the paper: sigma1 and sigma2 are switched.

* Construct a signature object from some input:
  ``` rust
  fn construct(ciphersuite: u8, time: TimeStamp, sigma1: PixelG2, sigma2: PixelG1) -> Signature;
  ```
* Get various elements from the secret key:
  ``` rust
  fn ciphersuite(&self) -> u8;
  fn time(&self) -> TimeStamp;
  fn sigma1(&self) -> PixelG2 ;
  fn sigma2(&self) -> PixelG1 ;
  ```
* Serialization:  
  * A signature is a blob `|ciphersuite id| time | sigma1 | sigma2 |`

  ``` rust
  cosnt SIG_LEN;                             // a signature is 149 bytes
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<(Signature, bool)>;
  ```
  * The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
  * `Deserialize` function will also return a flag that wether the `reader` is
  in compressed format or not.
  The compressed flag will always be `true`, as a requirement of strong
  unforgeability. An error will be returned if the `reader` is not compressed.

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
    1. info = DOM_SEP_SIG | msg | tar_time
    1. sample `r = sk.prng.sample(info)`
    2. set `m = hash_msg_into_fr(msg, ciphersuite)`
    2. use the first SubSecretKey for signing `ssk = sk.first_ssk()`
    2. re-randomizing sigma1: `sig1 = ssk.g2r * g2^r`
    2. re-randomizing sigma2
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
    6. return `e(1/g2, sigma2) * e(sigma1, hfx) * e(pk, h) == 1`

* hash message to a field element
  ``` Rust
  fn hash_msg_into_fr(msg: &[u8], ciphersuite: u8) -> Fr
  ```
  * Input: a message, a ciphersuite
  * Output: a field element
  * Steps:
    1. `m = DOM_SEP_HASH_TO_MSG | ciphersuite | msg`
    2. return `SHA512(m) mod p`

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
  fn verify_bytes_aggregated(&self,
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
    1. return `false` if signature's ciphersuite does not match the public keys' or the public parameters
    1. return `false` if all signatures' time stamps do not match
    2. `agg_pk = pk_list[0]`
    3. for for i in 1..pk_list.len()
        * `agg_pk.pk *= pk_list[i].pk`
    4. return `verify(sig, pk, pp, msg)`

    Note: if the `pk_list` contains multiple copies of a same public key, then this
    public key needs to be `multiplied` multiple times during public key aggregation, i.e.,
    they are treated as if they were distinct public keys.

# Seed and rng

This section describes how randomness and seed are handled in general. A tentative definition of domain separators are available in src/domain_sep.rs. `|` is the concatenation of the byte strings.
We will be using the following functions

    * HKDF-Extract(salt , seed) -> secret
    * HKDF-Expand(secret, public_info, length_of_new_secret) -> new_secret
    * hash_to_group(input, ciphersuite) -> group element

## Parameter generation
* The parameter generation function takes a seed as one of the inputs. This seed is provided by the caller (our go library). The rust code checks if the seed is longer than 32 bytes.
Rust code does not perform any extra checks over the seed. The caller needs to make sure that the seed is well formed and has enough entropy, etc. For default parameters we use SHA512's IV as the seed.
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

## Key Generation
* The master key generation function also takes a seed as one of the inputs. This seed is also provided by the caller. Same check on the seed is done as in parameter generation.
The field element is generated as follows:
  * Input: `seed`, parameter set
  * Output: the secret exponent `x`, the randomness `r` and an rngseed
  * Steps:
    * `m = HKDF-Extract(DOM_SEP_MASTER_KEY | ciphersuite, seed)`
    * `info = "key initialization"`
    * `t = HKDF-Expand(m, info, 128)`
    * `x = OS2IP(t[0..64]) mod p`
    * initialize the prng seed as `rngseed = t[64..128]`
    * `time = 1`
    * `info = "Pixel secret key init" | time`
    * `t = HKDF-Expand(rngseed, info, 128)`
    * `r = OS2IP(t[0..64]) mod p`
    * update the prng seed as `rngseed = t[64..128]`

<!--
  * A master secret (`x`, or `alpha`, i.e., the exponent for the pk) is generated from
  `hash_to_field(input, 0)`, where the input is `DOM_SEP_MASTER_KEY | ciphersuite | seed`.
  * A rngseed is generated from `sha256(DOM_SEP_SEED_INIT | ciphersuite | seed)`. This rngseed is part of the secret key, and will be used for deterministic updating and signing. -->

## Key Updates
* During a (fast) key updating, random field elements are generated
as follows:
  * Input: `rngseed` from the secret key
  * Input: `newseed` from the `key_update()` API to re-randomize the seed
  * Input: `time`, the time stamp from the secret key
  * Output: `n` field elements `r[0..n-1]`
  * Output: update secret key's prng seed
  * Steps:
    * `info = "Pixel secret key rerandomize expand" | time`
    * `rngseed = prng_rerandomize(rngseed, newseed, info)`
    * `info = "Pixel secret key update" | time`
    * `for i in 0..n-1`
      * `t = HKDF-Expand(rngseed, info, 128)`
      * `r[i] = OS2IP(t[0..64]) mod p`
      * update the rngseed as `rngseed = t[64..128]`

* The `prng_rerandomize` subroutine is as follows:
  * Input: `rngseed`, `newseed`, `info`
  * Output: a new `rngseed`
  * Steps:
    * `m = HKDF-Expand(rngseed, info, 128)`
    * `m1 = m[0..64]`
    * `m2 = m[64..128]`
    * return `rngseed = HKDF-Extract(m1 | newseed, m2)`



<!-- from
  `hash_to_field(input, ctr)`, where `input = DOM_SEP_KEY_UPDATE | ciphersuite | extracted_seed`, and
  `ctr` is incremental in case multiple field elements are required.
  Every time an extracted_seed is extracted during key updating, the rngseed will be updated.
   The extraction (and seed updating) is done as follows:
    * `extracted_seed = sha256(DOM_SEP_SEED_EXTRACT | rngseed)`
    * `rngseed = sha256(DOM_SEP_SEED_UPDATE | rngseed)`    -->

## Signing
* During the signing procedure, a random field element is generated as follows:
  * Input: `rngseed` from the secret key
  * Input: the `message` blob
  * Output: a field element `r`
  * Steps:
    * `info = "Pixel randomness for signing" | message | time`
    * `t = HKDF-Expand(rngseed, info, 64)`
    * `r = OS2IP(t[0..64]) mod p`

The rngseed is not updated, so that for a same message, we
will always generate a same signature.


<!-- from
`hash_to_field(input, ctr)`, where `input = DOM_SEP_SIG | ciphersuite | rngseed | message | time stamp`.
The rngseed will __NOT__ be updated during signing, so that for the same message and time stamp, we
will always generate a same signature. -->
