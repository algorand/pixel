from hash_to_field import hash_to_field
from util import print_iv, get_cmdline_options
from tree_time import *
try:
    from __sage__bls_sig_common import g1suite, g1gen, g2gen, print_test_vector, prepare_msg
    from __sage__g1_common import q, print_g1_hex, print_iv_g1
    from __sage__g2_common import print_g2_hex
    from __sage__opt_sswu_g1 import map2curve_osswu
    from __sage__param import param_gen, const_d, group_order, PubParam, g2zero
    from __sage__key import key_gen_root
except ImportError:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`")

P.<x> = PolynomialRing(ZZ)
def print_g1(g1):
    print "G1 element"
    print hex(ZZ(g1[0])), hex(ZZ(g1[1]))


def print_g2(g2):
    print "G2 element"
    t = P(g2[0])
    print hex(t[0]), hex(t[1])
    t = P(g2[1])
    print hex(t[0]), hex(t[1])




rnd = []
file = open("../python_imp/randomness.txt", "r")
for line in file:
    rnd.append(ZZ(line))

print rnd

ctr = 0
g1 = rnd[ctr]*g1gen

ctr +=1
g2 = rnd[ctr]*g2gen

ctr +=1
h = rnd[ctr]*g1gen



print "g1",
print_g1(g1)
print "g2",
print_g2(g2)
print "h",
print_g1(h)

ctr+=1
alpha = rnd[ctr]

const_d = 4

hv = [0 for _ in range (const_d+1)]
for i in range (const_d +1):
    ctr+=1
    hv[i] = rnd[ctr]*g1gen
    print "hv",i,
    print_g1(hv[i])


# key_gen_alpha_with_prng takes an input public parameter pp, and a prng file
# outputs a pair of `alpha` keys (pk, sk) where pk = g1^alpha, sk = g2^alpha
def key_gen_alpha(alpha):
    print alpha,hex(alpha)
    return (alpha*g1, alpha*g2)

pp = []
rsk, pk = key_gen_alpha(alpha)

print "pk",
print_g2(pk)
print "sk",
print_g1(alpha)







# get the alpha keys
keypair = key_gen_root(pp)
print "pp:", len(pp), pp
print "pk:", keypair[0]
print "sk:", keypair[1]
newsubkey  = subkey_delegate(keypair[1][0], pp,4)
print "new subkey:", newsubkey

#
# if __name__ == "__main__":
#     def main():
#
#         # use the following function to generate the parameters
#         # instead of param_gen function
#         # so that pp matches the output from python implementation
#         file = open("../python_imp/randomness.txt", "r")
#         g1r = file.readline()
#         g1 = ZZ(g1r)*g1gen
#
#         g2r = file.readline()
#         g2 = ZZ(g2r)*g2gen
#
#         hr = file.readline()
#         h = ZZ(hr)*g1gen
#
#         print hex(g1[0])
#         print hex(g2)
#         print h
#
#         # get the alpha keys
#         keypair = key_gen_root(pp)
#         print "pp:", len(pp), pp
#         print "pk:", keypair[0]
#         print "sk:", keypair[1]
#         newsubkey  = subkey_delegate(keypair[1][0], pp,4)
#         print "new subkey:", newsubkey
#     main()
file.close()
