import sys
sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref-fork/python-impl")

import hkdf
import hashlib
import filecmp

from curve_ops import g1gen, point_mul, point_add
from hashlib import sha512, sha256
from hash_to_field import Hr
from util import print_g1_hex, print_g2_hex
from serdesZ import serialize

from param import default_param
from prng import prng_init, prng_sample_then_update


# the key generation function...
# minor difference from rust code: do not generate a POP
def key_gen(seed):

    (pixelg2gen, h, hlist)  = default_param

    # hard code the ciphersuite byte \0 in the salt
    salt = b"Pixel master key\0"
    info = b"key initialization"

    prng = prng_init(seed, salt)
    x, prng = prng_sample_then_update(prng,info)

    # pk = g2^x
    pk = point_mul(x, pixelg2gen)

    # msk = h^x
    msk = point_mul(x, h)

    # r: randomness used in init
    info = b"Pixel secret key init" + b"\1\0\0\0"
    r, prng = prng_sample_then_update(prng,info)
    # g2r = g2^2
    g2r = point_mul(r, pixelg2gen)

    # hpoly = h^x * h0^r
    hpoly = point_mul(r, hlist[0])
    hpoly = point_add(hpoly, msk)

    # hvector = [hi^r] for i!=0
    hvector = []
    for i in range(len(hlist)-1):
        tmp = point_mul(r, hlist[i+1])
        hvector.append(tmp)

    ssk1 = (1,  g2r, hpoly, hvector)
    sk = (prng, [ssk1])
    return (pk, sk)


# | time stamp | hv_length | serial(g2r) | serial(hpoly) | serial(h0) ... | serial(ht) |
def serialize_ssk(ssk):
    (time, g2r, hpoly, hvector) = ssk
    hlen = len(hvector)
    buf = time.to_bytes(4, 'little') + b"%c"% hlen
    buf += serialize(g2r, True)
    buf += serialize(hpoly, True)
    for e in hvector:
        buf += serialize(e, True)
    return buf

# |ciphersuite id| number_of_ssk-s | seed | serial(first ssk) | serial(second ssk)| ...
def serialize_sk(sk):
    csid = 0
    (prng,ssk_vec) = sk
    ssk_num = len(ssk_vec)
    buf = b"%c"%csid + b"%c"% ssk_num + prng
    for e in ssk_vec:
        buf += serialize_ssk(e)
    return buf

# generate test vectors for public/secret keys that match rust code
def key_test_vector_gen():
    seed = b"this is a very long seed for pixel tests"
    pk, sk = key_gen(seed)
    print_sk(sk)

    pk_buf = b"\0" + serialize(pk, True)
    f = open("test_vector/pk_bin.txt", "wb")
    f.write(pk_buf)
    f.close()

    sk_buf = serialize_sk(sk)
    f = open("test_vector/sk_bin_01.txt", "wb")
    f.write(sk_buf)
    f.close()


    fname = "test_vector/sk_plain_01.txt"
    t = sys.stdout
    sys.stdout = open(fname, 'w')
    print_sk(sk)
    sys.stdout = t

def print_sk(sk):
    print("prng:")
    print(sk[0].hex())
    for e in sk[1]:
        print ("time:%d"%e[0])
        print("g2r:")
        print_g1_hex(e[1])
        print("hpoly:")
        print_g2_hex(e[2])
        for i in range(len(e[3])):
            print("h%d"%i)
            print_g2_hex(e[3][i])


if __name__ == "__main__":
    def main():
        key_test_vector_gen()
        assert filecmp.cmp("test_vector/pk_bin.txt", "../test_vector/test_vector/pk_bin.txt")
        assert filecmp.cmp("test_vector/sk_bin_01.txt", "../test_vector/test_vector/sk_bin_01.txt")
    main()
