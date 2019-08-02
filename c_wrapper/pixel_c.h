/* Text to put at the beginning of the generated file. Testing */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define PK_LEN 49

#define POP_LEN 97

#define SIG_LEN 149

/**
 * A wrapper of signature
 */
typedef struct pixel_sig {
  uint8_t data[SIG_LEN];
} pixel_sig;

/**
 * A wrapper of pk
 */
typedef struct pixel_pk {
  uint8_t data[PK_LEN];
} pixel_pk;

/**
 * A wrapper of sk
 */
typedef struct pixel_sk {
  uint8_t *data;
} pixel_sk;

/**
 * A wrapper of pop
 */
typedef struct pixel_pop {
  uint8_t data[POP_LEN];
} pixel_pop;

/**
 * A wrapper that holds the output of key generation function.
 */
typedef struct pixel_keys {
  pixel_pk pk;
  pixel_sk sk;
  pixel_pop pop;
} pixel_keys;

/**
 * This function aggregates the signatures without checking if a signature is valid or not.
 * It does check that all the signatures are for the same time stamp.
 * It panics if ciphersuite fails or time stamp is not consistent.
 */
pixel_sig c_aggregation(pixel_sig *sig_list, size_t sig_num);

/**
 * This function returns the storage requirement for the secret key
 * for a particular time stamp.
 */
size_t c_estimate_sk_size(uint64_t time, size_t depth);

/**
 * This function returns the depth of time tree.
 */
size_t c_get_depth(void);

/**
 * Input a pointer to the seed, and its length.
 * The seed needs to be at least
 * 32 bytes long. Output the key pair.
 * Generate a pair of public keys and secret keys,
 * and a proof of possession of the public key.
 */
pixel_keys c_keygen(const uint8_t *seed, size_t seed_len);

/**
 * Input a secret key, a time stamp that matches the timestamp of the secret key,
 * the public parameter, and a message in the form of a byte string,
 * output a signature. If the time stamp is not the same as the secret key,
 * returns an error
 */
pixel_sig c_sign_present(pixel_sk sk, const uint8_t *msg, size_t msg_len, uint64_t tar_time);

/**
 * Input a secret key, and a time stamp,
 * return an updated key for that time stamp.
 * Requires a seed for re-randomization.
 */
pixel_sk c_sk_update(pixel_sk sk, uint8_t *seed, size_t seed_len, uint64_t tar_time);

/**
 * Input a public key, the public parameter, a message in the form of a byte string,
 * and a signature, outputs true if signature is valid w.r.t. the inputs.
 */
bool c_verify(pixel_pk pk, const uint8_t *msg, size_t msglen, pixel_sig sig);

/**
 * This function verifies the aggregated signature
 */
bool c_verify_agg(pixel_pk *pk_list,
                  size_t pk_num,
                  const uint8_t *msg,
                  size_t msglen,
                  pixel_sig agg_sig);