from __sage__pixel_util import  bls_curve_path, time2vec, vec2time,\
                                print_ssk, print_sk, D

import sys
sys.path.insert(0, bls_curve_path)

from __sage__g1_common import print_g1_hex
from __sage__g2_common import print_g2_hex
from __sage__bls_sig_common import g1gen, g2gen

testvec = 1
## testvec = 0: none test vectors, normal run
## testvec = 1: uses deterministic randomness from hash_1 and hash_2, and print out test vectors
## testvec = 2: uses simple deterministic randomness 1,2,3,4...

# if testvec != 0:
#     from __sage__bls_sig_common import g1gen, g2gen


if (testvec == 1):
    from __sage__pixel_util import hash_1, hash_2
    # the seed to instantiate G_0 and G_1 for parameters
    param_seed = bytes("this is the seed for parameters"    )
    # the seed to instantiate G_0 and G_1 for randomness
    seed = bytes("this is the seed for randomness")
    # output to the file
    file = open("test_vector1.txt", "w")
if (testvec == 2):
    file = open("test_vector2.txt", "w")
    # parameter randomness increment from 1000
    param_rand = 1000
    # keygen/keyupdate/signature randomness increment from 0
    rand = 2


# testvec = 0: random r
# testvec = 1: r from hash function
# testvec = 2: r increases from a fixed value
def Zrrand():
    if testvec ==1:
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

def G1rand():
    if testvec ==1:
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

def G2rand():
    if testvec ==1:
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

def param_gen():
    g1 = G1rand()
    g2 = G2rand()
    h  = G1rand()
    hv = [G1rand() for _ in range(D+1)]
    return (g1, g2, h, hv)

def print_param(pp):
    print "g1"
    print_g1_hex(pp[0])
    print "g2"
    print_g2_hex(pp[1])
    print "h"
    print_g1_hex(pp[2])
    for i in range(len(pp[3])):
        print "h%d"%i
        print_g1_hex(pp[3][i])

def keygen(pp):
    g1, g2, h, hv = pp
    msk = Zrrand()
    pk  = msk * g2
    r   = Zrrand()

    time    = 1
    time_vec= time2vec(time, D)
    ssk0    = [0*g2, msk*h] + [0*g1 for _ in range (D)]

    print time_vec
    print hex(r)
    print hex(msk)
    ssk0    = randomization(ssk0, pp, time_vec, r)
    sk      = (time_vec, [ssk0])
    return (pk, sk)


## this function will (re-)randomize a sub secret key
def randomization(sub_secret_key, pp, time_vec, randomness=None):

    # extract public parameters
    g1, g2, h, hv = pp
    # generate new randomness
    if randomness == None:
        randomness = Zrrand()

    # tmp = hv[0] * prod_i h[i]^time_vec[i]
    tmp = hv[0]
    for i in range(len(time_vec)):
        tmp += hv[i] * time_vec[i]

    # ssk[0] += r * g2
    sub_secret_key[0] += randomness*g2
    # ssk[1] += r * tmp
    sub_secret_key[1] += randomness*tmp

    # ssk[2... len(time_vec)] unchanged

    # ssk[len(time_vec)+2, D+2] += r * h[i]
    for i in range(len(time_vec), D):
        sub_secret_key[i+2] += randomness*hv[i+1]

    return sub_secret_key

## this function will delegate the sub secret key into the next time slot
def delegate(sub_secret_key, pp, time_vec, new_time_slot):

    # extract public parameters
    g1, g2, h, hv = pp

    new_time_vec = time_vec + [new_time_slot]

    # tmp = hv[0] * prod_i h[i]^time_vec[i]
    tmp = sub_secret_key[1]

    return sub_secret_key

def key_update(sk, pp):
    time_vec = sk[0]
    ssk_vec = sk[1]
    time = vec2time(time_vec, D)
    print time, "time vec", time_vec
#    print sk
    if (len(time_vec)<D-1):
        ## not a leaf node
        ## so we delegate into two leaf nodes

        ## for the left leaf node we will re-use the randomness
        ssk_left = delegate(ssk_vec[0], pp, time_vec, [1])
        print "ssk left"
        print_ssk(ssk_left)
        ## for the right lead node we will need new randomness
        r = Zrrand()
        ssk_right = delegate(ssk_vec[0], pp, time_vec, [2])
        ssk_right = randomization(ssk_right, pp, time_vec + [2], r)
        print "ssk right"
        print_ssk(ssk_right)
        ## form the new secret key
        ssk_vec[0] = ssk_left
        ssk_vec.append(ssk_right)
    else:
        ## a leaf node
        if time_vec[len(time_vec)-1] == 1:
            ## this is a left leaf node
            ## replace the first ssk (left leaf) with the last ssk (right leaf)
            ## and remove the last ssk
            ssk_vec[0] = ssk_vec[len(ssk_vec)-1]
            del ssk_vec[len(ssk_vec)-1]
        else:
            ## this is a right leaf node
            ## remove the first ssk (right leaf)
            del ssk_vec[0]

    ## advance the time to the next slot
    time_vec = time2vec(time+1, D)
    print "time vec", time_vec, time+1
    return (time_vec, ssk_vec)

pp = param_gen()
print_param(pp)
pk, sk = keygen(pp)
print_sk(sk)
sk2 = key_update(sk,pp)
print_sk(sk2)
sk3 = key_update(sk,pp)
print_sk(sk3)

print "finished"
