import sys
sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref/python-impl")

import hkdf
import hashlib

from hashlib import sha512, sha256
from hash_to_field import OS2IP
from consts import q

# a wrapper of the HKDF-SHA512_extract function
def prng_init(seed, salt):
    # extract the secret m
    return hkdf.hkdf_extract(salt, input_key_material=seed, hash=hashlib.sha512);

# sample a field element, update the seed
def prng_sample_then_update(prng_seed, info):
    key = hkdf.hkdf_expand(prng_seed, info, 128)
    hashinput = key[:64]
    new_prng_seed = key[64:]

    # Riad:
    # "The issue is that the Python interface is slightly different than the
    # Rust one. In particular, the Python hash_to_field function does not
    # automatically inject a ciphersuite string, whereas the Rust interface
    # you're using does."

    # Inject \0 for ciphersuite so that the Hr function matches rust's
    # hash_to_field


    r = OS2IP(hashinput) % q
    return r, new_prng_seed

# sample a field element, do not update the seed
def prng_sample(prng_seed, info):
    hashinput = hkdf.hkdf_expand(prng_seed, info, 64)

    # Riad:
    # "The issue is that the Python interface is slightly different than the
    # Rust one. In particular, the Python hash_to_field function does not
    # automatically inject a ciphersuite string, whereas the Rust interface
    # you're using does."

    # Inject \0 for ciphersuite so that the Hr function matches rust's
    # hash_to_field
    r = OS2IP(hashinput) % q
    return r

def prng_rerandomize(prng_seed, newseed,info):
    m1 = hkdf.hkdf_expand(prng_seed, info, 128)
    return hkdf.hkdf_extract(m1[64:], input_key_material=(m1[:64]+newseed), hash=hashlib.sha512);


# basic functionality tests that matches Rust
def prng_test():
    seed = bytes("seed", "ascii")
    info = bytes("info", "ascii")
    salt = bytes("salt", "ascii")
    prng = prng_init(seed, salt)

    # for e in prng:
    #     print ("%s,"%hex(e))
    # print(prng.hex())
    r1, new_prng_seed = prng_sample_then_update(prng, info)

    # for e in new_prng_seed:
    #     print ("%s,"%hex(e))
    # print(prng.hex())
    # print(new_prng_seed.hex())

    # test that the new-seed is not mutated
    r2 = prng_sample(new_prng_seed, info)
    r3 = prng_sample(new_prng_seed, info)

    assert r1 == 0x5fc61b25c385eefe94ee9c8f205eb575e43d41800be63d0f1dd41cab6950f572
    assert r2 == 0x30cdf80e28b7c7391a8a0c2ff8503944f808a1c0cc22efd2f217fe299b51645c
    assert r2 == r3

    new_prng_seed2 = prng_rerandomize(new_prng_seed, seed, info)
    # for e in new_prng_seed2:
    #     print ("%s,"%hex(e))
    # print(prng.hex())
    # print(new_prng_seed2.hex())
    r4, new_prng_seed3 = prng_sample_then_update(new_prng_seed2, info)
    # print(r4)
    # print(hex(r4))
    # for e in new_prng_seed3:
    #     print ("%s,"%hex(e))
    # print(prng.hex())
    # print(new_prng_seed.hex())
    assert r4 == 0x6a4690024f210cf99651fa88f7bfaf892ffb29b6efb5bdded78fbf2de7381b54

if __name__ == "__main__":
    def main():
        prng_test()

    main()
