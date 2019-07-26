import sys
import filecmp
import copy

from param import default_param, d
from prng import prng_init, prng_sample
from keygen import key_gen,serialize_sk,print_sk
from keyupdate import sk_update, time_to_vec


from curve_ops import g1gen, point_mul, point_add
from hashlib import sha512, sha256
from hash_to_field import Hr, OS2IP
from util import print_g1_hex, print_g2_hex
from serdes import serialize
from consts import q





def hash_msg_into_fr(msg):
    m = sha512(b"Pixel hash to message\0" + msg).digest()
    return OS2IP(m) % q

def sign_present(sk, tar_time, pp, msg):

    ssk = sk[1][0]
    assert ssk[0] == tar_time
    timevec = time_to_vec(tar_time, d)

    (pixelg2gen, h, hlist)  = pp


    r = prng_sample(sk[0], b"Pixel randomness for signing" + msg)
    m = hash_msg_into_fr(msg)

    # sig1 = g2^r + ssk.g2r
    sig1 = copy.deepcopy(ssk[1])
    tmp = copy.deepcopy(pixelg2gen)
    tmp = point_mul(r, tmp)
    sig1 = point_add(sig1, tmp)


    # tmp = h0 * \prod h_i ^ t_i * h_d^m
    tmp = copy.deepcopy(hlist[0])
    for i in range(len(timevec)):
        tmp2 = copy.deepcopy(hlist[i+1])
        tmp2 = point_mul(timevec[i], tmp2)
        tmp = point_add(tmp, tmp2)
    tmp2 = copy.deepcopy(hlist[d])
    tmp2 = point_mul(m, tmp2)
    tmp = point_add(tmp, tmp2)

    # sig2 = ssk.hpoly * hv[d]^m * tmp^r
    sig2 = copy.deepcopy(ssk[2])
    tmp3 = copy.deepcopy(ssk[3][len(ssk[3])-1])
    tmp3 = point_mul(m, tmp3)
    sig2 = point_add(sig2, tmp3)
    tmp = point_mul(r, tmp)
    sig2 = point_add(sig2, tmp)


    return (tar_time, sig1, sig2)

# `|ciphersuite id| time | sigma1 | sigma2 |` => bytes
def serialize_sig(sig):
    return b"%c"%0 + sig[0].to_bytes(4, 'little') + serialize(sig[1],True) + serialize(sig[2], True)

def print_sig(sig):
    print("time: %d"%sig[0])
    print_g1_hex(sig[1])
    print_g2_hex(sig[2])

def signature_test_vector_gen():
    seed = b"this is a very long seed for pixel tests"
    msg = b"this is the message we want pixel to sign";
    pk, sk = key_gen(seed)
    sig = sign_present(sk, 1, default_param, msg)
    fname = "test_vector/sig_plain_01.txt"
    t = sys.stdout
    sys.stdout = open(fname, 'w')
    print_sig(sig)
    sys.stdout = t

    sig_buf = serialize_sig(sig)
    f = open("test_vector/sig_bin_01.txt", "wb")
    f.write(sig_buf)
    f.close()
    assert filecmp.cmp("test_vector/sig_bin_01.txt", "../test_vector/test_vector/sig_bin_01.txt")

    for i in range(2,64):
        print(i)
        sk_new = sk_update(sk,default_param,i, b"")
        sig = sign_present(sk_new,i,default_param,msg)

        fname = "test_vector/sig_bin_%02d.txt"%i
        fname2 = "../test_vector/test_vector/sig_bin_%02d.txt"%i
        t = sys.stdout
        sys.stdout = open(fname, 'w')
        print_sig(sig)
        sys.stdout = t
        sk = copy.deepcopy(sk_new)

        sig_buf = serialize_sig(sig)
        f = open(fname, "wb")
        f.write(sig_buf)
        f.close()
        assert filecmp.cmp(fname, fname2)

if __name__ == "__main__":
    def main():
        signature_test_vector_gen()
    main()
