from hash_to_field import hash_to_field
from util import print_iv, get_cmdline_options
from tree_time import *
try:
    from __sage__bls_sig_common import g1suite, g1gen, g2gen, print_test_vector, prepare_msg
    from __sage__g1_common import q, print_g1_hex, print_iv_g1
    from __sage__g2_common import print_g2_hex
    from __sage__opt_sswu_g1 import map2curve_osswu
    from __sage__param import param_gen, const_d, group_order, PubParam, g2zero
except ImportError:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`")


class SubSecretKeys():
    def __init__(self):
        self.g2r = g2zero



# key_gen_alpha takes an input public parameter pp
# outputs a pair of `alpha` keys (pk, sk) where pk = g1^alpha, sk = g2^alpha
def key_gen_alpha(pp):
    alpha = ZZ.random_element(0,group_order)
    return (alpha*g1gen, alpha*g2gen)

# key_gen_alpha takes an input public parameter pp
# outputs a pair of root keys (pk, sk) where
#   pk = g1^alpha,
#   sk = ...
def key_gen_root(pp):
    secret_key = []
    key_alpha = key_gen_alpha(pp)
    r = ZZ.random_element(0,group_order)

    time_stamp = 1
#    sub_secret_key = copy(pp)

    sub_secret_key = subkey_gen(pp, key_alpha[1], time2vec(time_stamp, const_d))

    # sub secret key
        #   g2^r, h0^r+g2^alpha, h1^r, h2^2, ... h_d^r

    # for i in range(const_d+1):
    #     sub_secret_key[i] = r*sub_secret_key[i]
    # sub_secret_key[0] = sub_secret_key[0] + key_alpha[1]
    # sub_secret_key.insert(0, r*g2gen)

    secret_key.append((sub_secret_key, time_stamp))
    return (key_alpha[0], secret_key)

# get the length of the corresponding vector length
# i.e., when the vector is in the form x1,...x_t, 0, 0, ...
# return t
def gen_vec_x_len(sub_secret_key):
    t = 0
    for e in sub_secret_key:
        if e == 0:
            t = t + 1
    return t


def subkey_gen(pp, g2a, time_vec):

    # a sub secret key consist of following items
    # * an G1 element: r * g1gen
    # * d+1 G2 elements, from public param
    # * a time stamp

    sub_secret_key = [None for _ in range (const_d+3)]

    r = ZZ.random_element(0, group_order)

    # first element: g1^r
    sub_secret_key[0] = r * g1gen

    # second element g2poly = g2^{\alpha + f(x)*r}
    g2poly = copy(pp[0])
    for i in range(len(time_vec)):
        tmp = copy(pp[i+1])
        g2poly = g2poly + time_vec[i]*tmp
    g2poly = r* g2poly
    g2poly = g2poly + g2a
    sub_secret_key[1] = g2poly

    # the next |time_vec| elements are null

    # the last elements are hi^r
    for i in range(len(time_vec) + 2, const_d+3):
        sub_secret_key[i] = r*pp[i-3]


    del r
    return sub_secret_key


def subkey_delegate(subkey, pp, time_stamp):
    print "============================"
    print "begin subkey delegation"

    time_vec = time2vec(time_stamp, const_d)
    print "subkey", subkey

    # right side
    rightside = subkey_gen(pp, 0, time_vec)

    print time_vec

    print "right side"
    for i in range (len(rightside)):
        print rightside[i]

    # left side
    leftside = copy(subkey[0])
    xlen = gen_vec_x_len(leftside)

    for i in range(xlen, len(time_vec)):
        tmp= time_vec[i]* pp[i+1]
        leftside[1] = leftside[1] + tmp

    for i in range(len(time_vec)):
        leftside[i+2] = 0*g2gen

    print "left side"
    for i in range (len(leftside)):
        print leftside[i]

    for i in range (len(leftside)):
        if (leftside[i]!= None ) and (rightside[i] != None) :
            leftside[i] = leftside[i] + rightside[i]
    print "final"
    for i in range (len(leftside)):
        print leftside[i]

    print "end subkey delegation"
    print "============================"

    return (leftside, time_stamp)

def sk_delegate(sk, pp, time_stamp):
    print "todo"

if __name__ == "__main__":
    def main():
        # initialize public parameters
        pp = param_gen(const_d)
        # get the alpha keys
        keypair = key_gen_root(pp)
        print "pp:", len(pp), pp
        print "pk:", keypair[0]
        print "sk:", keypair[1]
        newsubkey  = subkey_delegate(keypair[1][0], pp,4)
        print "new subkey:", newsubkey
    main()
