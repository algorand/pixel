from hash_to_field import hash_to_field
from util import print_iv, get_cmdline_options
from fields import Fq, Fq2, Fq6, Fq12
try:
    from __sage__bls_sig_common import g1suite, g1gen, g2gen, print_test_vector, prepare_msg
    from __sage__g1_common import q, print_g1_hex, print_iv_g1
    from __sage__g2_common import print_g2_hex
    from __sage__opt_sswu_g1 import map2curve_osswu

except ImportError:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`")


# constants for untwisting
ut_root = Fq12.one(p).root
ut_wsq_inv = ~Fq12(p, ut_root, Fq6.zero(p))
ut_wcu_inv = ~Fq12(p, Fq6.zero(p), ut_root)
del ut_root

def _untwist(R):
    (x,y,z)= R
    return (x * ut_wsq_inv, y * ut_wcu_inv, z)


def pairing (g1, g2):

    return 0


if __name__ == "__main__":
    def main():
        print pairing(g1gen, g2gen)
    main()
