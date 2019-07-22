import sys
sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref-fork/python-impl")

import hkdf
import hashlib

from hashlib import sha512, sha256
from hash_to_field import Hr

# a wrapper of the HKDF-SHA512_extract function
def prng_init(seed, salt):
    # extract the secret m
    return hkdf.hkdf_extract(salt, input_key_material=seed, hash=hashlib.sha512);

# sample a field element, update the seed
def prng_sample_then_update(prng_seed, info, ctr=0):
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
    r = Hr(b"\0" + hashinput)[0]
    return r, new_prng_seed

# sample a field element, do not update the seed
def prng_sample(prng_seed, info, ctr=0):
    hashinput = hkdf.hkdf_expand(prng_seed, info, 64)

    # Riad:
    # "The issue is that the Python interface is slightly different than the
    # Rust one. In particular, the Python hash_to_field function does not
    # automatically inject a ciphersuite string, whereas the Rust interface
    # you're using does."

    # Inject \0 for ciphersuite so that the Hr function matches rust's
    # hash_to_field
    r = Hr(b"\0" + hashinput)[0]
    return r

# basic functionality tests that matches Rust
def prng_test():
    seed = bytes("seed", "ascii")
    info = bytes("info", "ascii")
    salt = bytes("salt", "ascii")
    prng = prng_init(seed, salt)
    r1, new_prng_seed = prng_sample_then_update(prng, info)
    # test that the new-seed is not mutated
    r2 = prng_sample(new_prng_seed, info)
    r3 = prng_sample(new_prng_seed, info)

    assert r1 == 0x6c007fa36465ea6a2832f035ac884bdd724056b516f816876d576de589d4ba36
    assert r2 == 0x34036972b912c2b7d5f313bf2cac29d555c2d1b18347008f1c071c2621e2e948
    assert r3 == 0x34036972b912c2b7d5f313bf2cac29d555c2d1b18347008f1c071c2621e2e948


if __name__ == "__main__":
    def main():
        prng_test()

    main()
