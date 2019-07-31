// this is a binding file to expose pixel-signature's API to C

#ifndef PIXEL_BINDING_C_H
#define PIXEL_BINDING_C_H

#include <stdint.h>
#include <stddef.h>


extern uint8_t* c_keygen(
  uint8_t pk_buf[],
  const uint8_t *seed,
  const size_t seedlen);


#endif // PIXEL_BINDING_C_H
