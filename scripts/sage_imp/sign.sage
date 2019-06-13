from hash_to_field import hash_to_field
from util import print_iv, get_cmdline_options
from tree_time import *
try:
    from __sage__bls_sig_common import g1suite, g1gen, g2gen, print_test_vector, prepare_msg
    from __sage__g1_common import q, print_g1_hex, print_iv_g1
    from __sage__g2_common import print_g2_hex
    from __sage__opt_sswu_g1 import map2curve_osswu
    from __sage__param import param_gen, const_d, group_order
    from __sage__key import *
except ImportError:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`")


def sign(subsecretkey, pp, time_stamp, msg):

    print "============================"
    print "begin signing procedure"


    # the time vector is formulated as
    # vec_t | 0 ,....,0 | msg
    time_vec = time2vec(time_stamp, const_d)
    length = len(time_vec)
    for i in range(length, const_d-1):
        time_vec.append(0)
    time_vec.append(msg)

    sig_full = subkey_delegate(subsecretkey, pp, vec2time(time_vec, const_d))

    print "end signing procedure"
    print "============================"
    return (sig_full[0][0], sig_full[0][1])


def verify(pk, pp, time, msg, sigma):
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
        msg = 2
        sigma  = sign(keypair[1][0], pp,4, msg)
        print "signature:", sigma
    main()
