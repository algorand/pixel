# Pixel signature scheme

## Data structure
* maximum depth for timestamps: a constant `d`
* message: an arbitrary array of `u8`
* public key: an `G2` element
  * __Q: membership tests?__
* secret key:
  * smallest timestamp for the subsecret key, stored as an `u64`
  * a list of subsecret keys, with `d + 1` `G1` elements and `1` G2 element.
    * note: `G1` elements will have a lot leading `0`s
* signature:
  * a pair of `G1` and `G2` elements
  * __Q: membership tests?__


## ParamGen
* Input: (_optional_) a seed
* Output: Public parameters `h0,...,hd : [G1; d+1]`
* Method:
  * Option 1:
    * Generate `r = [Fr; d + 1]` uniformly, compute `g1^r[i]`
  * Option 2:
    * Generate `d + 1` `G1` elements (use hash_and_test method)



## KeyGenAlpha  
* Input: (_optional_) a seed
* Output: `pk = g2^alpha`, `sk0 = g1^alpha`
* Method:
  * Sample a random `alpha`
  * Output `pk = g2^alpha` and `sk0 = g1^alpha`


## KeyGen
* Input: (_optional_) a seed
* Output: `pk = g2^alpha`, `sk` at time `0`
* Method:
  * `pk, sk0 = KeyGenAlpha(seed)`
  * Sample a random `r`
  * `subsk0 = (g2^r, sk0*h0^r, h1^r, ..., hd^r)`
  * return
      ```rust
      sk = SecretKey{
        time: 0,
        ssklist: vec![subsk0]
      }
      ```

## KeyUpdate
* Input:
  * current key: `sk_c`
  * target time: `time_t`
* Output:
  * target key: `sk_t` or `fail`
* Method:
  * if `sk_c.time>time_t` return `fail`
  * `gamma_t = Gamma(time_t)` //  get a list of time vectors
  * for `ssk` in  `sk_c.ssklist`
