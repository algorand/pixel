#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "pixel_c.h"


// Credit: https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexDump (const char *desc, const void *addr, const int len);

// very simple and basic tests on pixel functions
int test()
{

  char seed[] = "this is a very long seed for pixel tests";
  char rngseed[] = "";
  char msg[] = "this is the message we want pixel to sign";

  pixel_keys key;
  pixel_sig sig;

  int i;
  printf("\nkey generation\n");
  // generate a tuple of keys
  // always remove the last byte of the string so that the inputs
  // matches rust's
  key = c_keygen((uint8_t*)seed, sizeof(seed)-1);

  // dump the output
  hexDump ("pk", key.pk.data, PK_LEN);

  // sign the message with the key
  printf("\nSigning a message: %s\n", msg);
  sig = c_sign_present(key.sk, (uint8_t*)msg, sizeof(msg)-1, 1);

  // dump the output
  hexDump ("sig", sig.data, SIG_LEN);

  // verifies the signature
  assert(c_verify(key.pk, (void*)msg, sizeof(msg)-1, sig) == true);

  pixel_sk sk2 = c_sk_update(key.sk, (void*)rngseed, sizeof(rngseed)-1, 2);

  // sign the message with the key
  sig = c_sign_present(sk2, (void*)msg, sizeof(msg)-1, 2);

  // dump the output
  hexDump ("sig", sig.data, SIG_LEN);

  // verifies the signature
  assert(c_verify(key.pk, (void*)msg, sizeof(msg)-1, sig) == true);

  int num_agg =5;
  pixel_sig sig_list[num_agg];
  pixel_pk pk_list[num_agg];


  for(i=0;i<num_agg;i++){
    printf("the %d-th signature\n", i);

    // use the first 32+i bytes as the seed
    key = c_keygen((void*)seed, 32+i);
    pk_list[i] = key.pk;

    // dump the output
    hexDump ("pk", key.pk.data, PK_LEN);


    // generate the signature list
    sig_list[i] = c_sign_present(key.sk, (void*)msg, sizeof(msg)-1, 1);

    // dump the output
    hexDump ("sig", sig_list[i].data, SIG_LEN);

    // verifies the signature
    assert(c_verify(key.pk, (void*)msg, sizeof(msg)-1, sig_list[i]) == true);
  }

  pixel_sig agg_sig =  c_aggregation(sig_list, num_agg);
  hexDump("aggregated signature", agg_sig.data, SIG_LEN);

  // verifies the aggregated signature
  assert(c_verify_agg(pk_list, num_agg, (void*)msg, sizeof(msg)-1, agg_sig) == true);

  return 0;
}


int test_vector()
{
  char seed[] = "this is a very long seed for pixel tests";
  char rngseed[] = "";
  char msg[] = "this is the message we want pixel to sign";

  pixel_keys key;
  pixel_sig sig;
  pixel_sk sk, sk2;

  int i;

  // generate a tuple of keys
  // always remove the last byte of the string so that the inputs
  // matches rust's
  key = c_keygen((uint8_t*)seed, sizeof(seed)-1);
  sig = c_sign_present(key.sk, (uint8_t*)msg, sizeof(msg)-1, 1);


  char* a = "test_buf/sig_bin_";
  char* extension = ".txt";
  char fileSpec[strlen(a)+strlen(extension)+3];
  FILE *out;
  snprintf( fileSpec, sizeof( fileSpec ), "%s%02d%s", a, 1, extension );
  out = fopen( fileSpec, "wb" );
  fwrite(sig.data, sizeof(sig.data), 1, out);
  fclose(out);

  sk = key.sk;
  for (i=2;i<64;i++)
  {
    printf("generating %02d-th signature\n", i);
    sk2 = c_sk_update(sk, (void*)rngseed, sizeof(rngseed)-1, i);
    sig = c_sign_present(sk2, (uint8_t*)msg, sizeof(msg)-1, i);
    sk = sk2;
    snprintf( fileSpec, sizeof( fileSpec ), "%s%02d%s", a, i, extension );
    out = fopen( fileSpec, "wb" );
    fwrite(sig.data, sizeof(sig.data), 1, out);
    fclose(out);
  }

  return 0;
}


int main(){

  test();
  test_vector();
  printf("Hello Algorand\n");
}



// Credit: https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexDump (const char *desc, const void *addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char *pc = (const unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}
