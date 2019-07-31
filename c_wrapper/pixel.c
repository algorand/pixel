#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
//#include "pixel.h"
#include "pixel-bind.h"


int keygen(
  // uint8_t *sk,
  // size_t sklen,
  // uint8_t *pk,
  // size_t pklen,
  const uint8_t *seed,
  const size_t seedlen)
{
  int i=0;
  printf("seed:\n");
  for (i=0;i<seedlen;i++)
  {
    printf("%02x, ", seed[i]);
  }
  printf("\n");


  uint8_t *buf;
  uint8_t buf2[1000];
//buf2 = malloc(sizeof(uint8_t)*1000);

  buf = c_keygen(buf2, seed, seedlen);
printf("buf:\n");
  // uint8_t *pk_buf = buf[0];
  // uint8_t *sk_buf = buf[1];
  // uint8_t *pop_buf = buf[2];
  for (i=0;i<40;i++)
  {
    printf("%02x, ", buf2[i]);
    if (i%16==15)
      printf("\n");
  }

  // for (i=0;i<40;i++)
  // {
  //   printf("%02x, ", pk_buf[i]);
  //   if (i%16==15)
  //     printf("\n");
  // }
  //
  // printf("\n");
  // printf("\n");
  //
  // for (i=0;i<128;i++)
  // {
  //   printf("%02x, ", sk_buf[i]);
  //   if (i%16==15)
  //     printf("\n");
  // }
  //
  // printf("\n");
  // printf("\n");
  //
  // for (i=0;i<128;i++)
  // {
  //   printf("%02x, ", pop_buf[i]);
  //   if (i%16==15)
  //     printf("\n");
  // }

    printf("\n");  printf("\n");
//  memcpy(sk, buffer, 32);
//  memcpy(pk, buffer+32, 96);
//  memset(buffer, 0, 128);

  return 0;
}



int main(){

  unsigned char seed[] = "this is a very very long seed to enable rng";

  keygen(seed, 32);
  printf("hello world\n");
}
