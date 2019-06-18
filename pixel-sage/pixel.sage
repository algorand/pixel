from __sage__pixel_util import  bls_curve_path, time2vec, vec2time,\
                                print_ssk, print_sk, print_param, D


## change bls_curve_path to point to your bls_sig_ref's sage code
import sys
sys.path.insert(0, bls_curve_path)

from __sage__g1_common import print_g1_hex, q
from __sage__g2_common import print_g2_hex
from __sage__bls_sig_common import g1gen, g2gen

testvec = 1
## testvec = 0: none test vectors, normal run
## testvec = 1: uses deterministic randomness from hash_1 and hash_2, and print out test vectors
## testvec = 2: uses simple deterministic randomness 1,2,3,4...

# if testvec != 0:
#     from __sage__bls_sig_common import g1gen, g2gen


if testvec == 1:
    from __sage__pixel_util import hash_1, hash_2



# the seed to instantiate G_0 and G_1 for parameters
param_seed = bytes("this is the seed for parameters"    )
# the seed to instantiate G_0 and G_1 for randomness
seed = bytes("this is the seed for randomness")
# parameter randomness increment from 1000
param_rand = 1000
# keygen/keyupdate/signature randomness increment from 0
rand = 2
# output to the file
file = open("test_vector1.txt", "w")

# testvec = 0: random r
# testvec = 1: r from hash function
# testvec = 2: r increases from a fixed value
def Zrrand():
    if testvec == 1:
        global seed
        r = hash_1(seed)
        seed = hash_2(seed)
    else:
        if testvec == 2:
            global rand
            r = rand
            rand += 1
        else:
            r = ZZ.random_element(1,q-1)
    return r

# output a *random* G1 element
def G1rand():
    if testvec == 1:
        global param_seed
        r = hash_1(param_seed)
        param_seed = hash_2(param_seed)
    else:
        if testvec == 2:
            global param_rand
            r = param_rand
            param_rand += 1
        else:
            r = ZZ.random_element(1,q-1)
    return r*g1gen

# output a *random* G2 element
def G2rand():
    if testvec == 1:
        global param_seed
        r = hash_1(param_seed)
        param_seed = hash_2(param_seed)
    else:
        if testvec == 2:
            global param_rand
            r = param_rand
            param_rand += 1
        else:
            r = ZZ.random_element(1,q-1)
    return r*g2gen


## parameter generation functions
## to decide: if we want to use constant group generators
def param_gen():
    g1 = G1rand()
    g2 = G2rand()
    h  = G1rand()
    hv = [G1rand() for _ in range(D+1)]
    return (g1, g2, h, hv)


## key generation function
## input public parameter pp
## output key pair (pk, sk)
def keygen(pp):
    g1, g2, h, hv = pp
    msk = Zrrand()
    pk  = msk * g2
    r   = Zrrand()
    print "randomness in key gen:", hex(r)
    time    = 1
    time_vec= time2vec(time, D)
    ssk0    = [0*g2, msk*h] + [0*g1 for _ in range (D)]

    print time_vec
    print hex(r)
    print hex(msk)
    ssk0    = randomization(ssk0, pp, time_vec, r)
    sk      = (time_vec, [ssk0])
    return (pk, sk)


## this function will (re-)randomize a sub secret key using a random field element
def randomization(sub_secret_key, pp, time_vec, randomness=None):

    # extract public parameters
    g1, g2, h, hv = pp
    # generate new randomness
    if randomness == None:
        randomness = Zrrand()

    # tmp = hv[0] * prod_i h[i]^time_vec[i]
    tmp = hv[0]
    for i in range(len(time_vec)):
        tmp += hv[i+1] * time_vec[i]

    # ssk[0] += r * g2
    sub_secret_key[0] += randomness*g2
    # ssk[1] += r * tmp
    sub_secret_key[1] += randomness*tmp

    # ssk[2... len(time_vec)] unchanged

    # ssk[len(time_vec)+2, D+2] += r * h[i]
    for i in range(0, len(sub_secret_key)-2):
        sub_secret_key[i+2] += randomness*hv[len(time_vec)+i+1]

    return sub_secret_key

## this function will delegate the sub secret key into the next time slot
def delegate(sub_secret_key, pp, time_vec, new_time_slot):

    tmp = sub_secret_key[2]*new_time_slot[0]
    sub_secret_key[1] += tmp
    del sub_secret_key[2]

    return sub_secret_key


## this function updates the *secret key at time t* to time t+1
def key_update(sk, pp):
    time_vec = copy(sk[0])
    ssk_vec = copy(sk[1])
    new_t = vec2time(copy(time_vec), D) + 1

    ## we can determine if a node is a leaf node or not by
    ## checking the time vector
    if (len(time_vec)<D-1):
        ## not a leaf node
        ## so we delegate into two leaf nodes

        ## for the left leaf node we will always re-use the randomness
        ssk_left = delegate(copy(ssk_vec[0]), pp, copy(time_vec), [1])

        ## for the right lead node we will need new randomness
        r = Zrrand()
        tmp = delegate(copy(ssk_vec[0]), pp, copy(time_vec), [2])
        ssk_right = randomization(tmp, pp, copy(time_vec) + [2], r)

        ## form the new secret key
        ## the sub_secret_keys are ALWAYS sorted in chronological order
        ## and there is NO empty sub_secret_keys
        ## this is different from pixel-python
        ## note that this does not change the actual secret key
        ssk_vec[0] = ssk_left
        ssk_vec.insert(1,ssk_right)
    else:
        ## a leaf node
        ## delegation is simply removing this sub secret key
        del ssk_vec[0]

    ## advance the time to the next slot
    new_t_vec = time2vec(new_t, D)

    return (new_t_vec, ssk_vec)

## running test with testvec = flag
def test(flag):
    global testvec
    testvec = flag
    pp = param_gen()
    print_param(pp)
    pk, sk = keygen(pp)
    for i in range(2^D-2):
        print ""
        print ""
        print "the %d-th update"%(i+1)
        sk = key_update(sk, pp)
        print_sk(sk)
    print "finished"

if __name__ == "__main__":
    def main():
        test(0)
        orig_stdout = sys.stdout
        sys.stdout = file
        test(1)
        sys.stdout = orig_stdout
        test(2)

    main()
