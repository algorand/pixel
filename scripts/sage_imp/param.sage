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
const_d = 4


# group order r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
# or decimal 52435875175126190479447740508185965837690552500527637822603658699938581184513
group_order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
# decimal: 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
# hex: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

cofactor = 0x396C8C005555E1568C00AAAB0000AAAB

trace =  modulus-group_order*cofactor+1


g2zero = 0*g2gen

# param_gen returns a list of random g2 elements are the public parameter
def param_gen(d):
    pp = []
    for i in range(d+1):
        field_element = ZZ.random_element(0, group_order)
        group_element = field_element * g2gen
        pp.append(group_element)
    return pp


class PubParam:
    def __init__(self):
        self.h = g2zero
        self.hlist = [g2zero for _ in range (const_d)]

    def gen(self):
        self.h = ZZ.random_element(0, group_order) * g2gen
        self.hlist = [ZZ.random_element(0, group_order) * g2gen for _ in range (const_d)]

    def dump(self):
        print ""
        print "=============================="
        print "printing public param"
        print "h ", self.h
        for i in range (const_d):
            print "h", i, self.hlist[i]
        print "=============================="

if __name__ == "__main__":
    def main():
        pp = param_gen(const_d)
        print "tree depth:", const_d
        print "group order:", group_order
        print "param:"
        for i in range(const_d+1):
            print i, pp[i]
        pp = PubParam()
        print "pubparam", pp.dump()
        pp.gen()
        print "pubparam", pp.dump()
    main()
