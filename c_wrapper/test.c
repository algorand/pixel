#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "pixel_c.h"

// very simple and basic tests on pixel functions
int test()
{

  char seed[] = "this is a very long seed for pixel tests";
  char rngseed[] = "";
  char msg[] = "this is the message we want pixel to sign";

  pixel_keys key;
  void *sk, *sk2, *pk, *sig;

  // generate a tuple of keys
  key = c_keygen((void*)seed, sizeof(seed));

  sk = key.sk;
  pk = key.pk;

  // sign the message with the key
  sig = c_sign_present(sk, (void*)msg, sizeof(msg), 1);

  // verifies the signature
  assert(c_verify(pk, (void*)msg, sizeof(msg), sig) == true);

  // update the key to time 2
  sk2 = c_sk_update(sk, (void*)rngseed, sizeof(rngseed), 2);

  // sign the message with the key
  sig = c_sign_present(sk2, (void*)msg, sizeof(msg), 2);

  // verifies the signature
  assert(c_verify(pk, (void*)msg, sizeof(msg), sig) == true);
  return 0;
}



int main(){

  test();
  printf("Hello Algorand\n");
}
