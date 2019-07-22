import sys
sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref-fork/python-impl")

import hkdf
import hashlib
import filecmp

from hashlib import sha512
from consts import q
from hash_to_field import hash_to_field, I2OSP
from util import print_g1_hex, print_g2_hex, prepare_msg
from opt_swu_g1 import map2curve_osswu
from opt_swu_g2 import map2curve_osswu2
from serdes import serialize
from curve_ops import g1gen


# constants
DOM_SEP_PARAM_GEN  = bytes("Pixel public parameter generation", "ascii")

# The seed we will be using for the default public parameter generation
# is set to the same as the SHA512's initial vector.
# see: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=20
#      6a09e667f3bcc908
#      bb67ae8584caa73b
#      3c6ef372fe94f82b
#      a54ff53a5f1d36f1
#      510e527fade682d1
#      9b05688c2b3e6c1f
#      1f83d9abfb41bd6b
#      5be0cd19137e2179
# "Throughout this specification, the “big-endian” convention is used when
#  expressing both 32- and 64-bit words, so that within each word, the most
#  significant bit is stored in the left-most bit position."
# For example, the 32-bit string
#               1010 0001 0000 0011 1111 1110 0010 0011
# can be expressed as “a103fe23”,
# and the 64-bit string
#               1010 0001 0000 0011 1111 1110 0010 0011
#               0011 0010 1110 1111 0011 0000 0001 1010
# can be expressed as “a103fe2332ef301a”.

seed = bytes([
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
    0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
    0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
    0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
])

ciphersuite = 0
d = 32

# extract the secret m
m = hkdf.hkdf_extract(salt=DOM_SEP_PARAM_GEN, input_key_material=seed, hash=hashlib.sha512);

# generate h using hash_to_group
info = bytes("H2G_h", "ascii")
# expand the secret
key = hkdf.hkdf_expand(pseudo_random_key=m, info=info, length=32, hash=hashlib.sha512)
# hash to G2
h = map2curve_osswu2(prepare_msg(key, ciphersuite))

# generate hlistusing hash_to_group
hlist =[]
for i in range(d+1):
    info  = b"H2G_h" + I2OSP(i,1)
    # expand the secret
    key = hkdf.hkdf_expand(pseudo_random_key=m, info=info, length=32, hash=hashlib.sha512)
    # hash to G2
    hi = map2curve_osswu2(prepare_msg(key, ciphersuite))
    hlist.append(hi)

default_param = (g1gen, h, hlist)

# formulate the outputs
buf = b"%c" % ciphersuite
buf = buf + b"%c" % d
buf = buf + serialize(g1gen, False)
buf = buf + serialize(h, False)
for i in range(d+1):
    buf = buf + serialize(hlist[i], False)

# write to the output
f = open("test_vector/param_bin.txt", "wb")
f.write(buf)
f.close()


if __name__ == "__main__":
    def main():
        assert filecmp.cmp("test_vector/param_bin.txt", "../test_vector/test_vector/param_bin.txt")
    main()
