from hash_to_field import hash_to_field
from util import print_iv, get_cmdline_options
try:
    from __sage__bls_sig_common import g1suite, g2gen, print_test_vector, prepare_msg
    from __sage__g1_common import q, print_g1_hex, print_iv_g1
    from __sage__g2_common import print_g2_hex
    from __sage__opt_sswu_g1 import map2curve_osswu

except ImportError:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`")


# depth of the tree
const_d = 3


# group order r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
# or decimal 52435875175126190479447740508185965837690552500527637822603658699938581184513
group_order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# param_gen returns a list of random g2 elements are the public parameter
def param_gen(d):
    pp = []
    for i in range(d+1):
        field_element = ZZ.random_element(0, group_order)
        group_element = field_element * g2gen
        pp.append(group_element)
    return pp



if __name__ == "__main__":
    def main():
        pp = param_gen(const_d)
        print "tree depth:", const_d
        print "group order:", group_order
        print "param:"
        for i in range(const_d+1):
            print i, pp[i]
    main()
