from keygen import key_gen, serialize_sk, print_sk
from prng import prng_sample_then_update, prng_rerandomize
from param import d, default_param

import sys
import filecmp
import copy
from curve_ops import point_mul, point_add
from util import print_g1_hex, print_g2_hex
from hash_to_field import I2OSP



# see the rust code for the detailed logic and examples
def sk_update(sk, pp, tar_time, seed):

    # re-randomize the prng
    info = b"Pixel secret key rerandomize expand" + I2OSP(sk[1][0][0],4)
    new_seed = prng_rerandomize(sk[0], seed, info)

    # find the ancestor node of the tar-time
    # if the ancestor happens to be the same as tar-time
    # then we have finished
    delegator =  find_ancestor(sk, tar_time)
    sk_vec = copy.copy(sk[1])
    # for e in sk_vec:
    #     if e[0] < delegator[0]:
    #         e = []
    sk_vec = [x for x in sk_vec if x[0] >= delegator[0]]
    if sk_vec[0][0] == tar_time:
        return (new_seed, sk_vec)

    # when ancestor is not for the tar-time,
    # we will use this ancestor (delegator) to delegate

    tvec = time_to_vec(tar_time, d)
    gammalist = gammat(tvec, d)

    # new_ssk contains ssk-s that are delegated
    new_ssk = []
    for e in gammalist:
        to_be_include = True
        time = vec_to_time(e,d)
        for ssk in sk_vec:
            # ssk already in the vector
            if ssk[0] == time:
                to_be_include = False

        # ssk is not in the list
        if to_be_include == True:
            ssk = delegate(copy.deepcopy(delegator), time)
            new_ssk.append(ssk)

    # now rerandomize all new_ssk except for the first one
    # randomize the ssks
    info = b"Pixel secret key update"
    for i in range(1,len(new_ssk)):
        r, new_seed = prng_sample_then_update(new_seed, info)
        new_ssk[i] = randomization(new_ssk[i], pp, r)


    # remove the delegator from sk_vec
    # insert the new_ssk instead
    del sk_vec[0]
    sk_vec = new_ssk + sk_vec

    return (new_seed, sk_vec)



# This function iterates through the existing sub secret keys, find the one for which
# 1. the time stamp is the greatest within existing sub_secret_keys
# 2. the time stamp is no greater than tar_time
# It returns this subsecretkey's time stamp; or an error if ...
# * there is no ssk in the secret key
# * the target time stamp is invalid for the curret time stamp
# e.g.:
#     sk {time: 2, ssks: {omited}}
#     sk.find_ancestor(12) = 9
# This is an ancestor node for the target time.
# Running example from key update:
# example 1: ancestor of time stamp 12, a.k.a. [2,1,2]
#  within the sk = {3, [ssk_for_t_3, ssk_for_t_6, ssk_for_t_9]} // [1,1], [1,2], [2]
#  is 9, corresponding to time vector [2], i.e., a pre-fix of [2,1,2]
# example 2: ancestor of time stamp 4, a.k.a. [1,1,1]
#  within the sk = {2, [ssk_for_t_2, ssk_for_t_9]}              // [1], [2]
#  is 2, corresponding to time vector [1], i.e., a pre-fix of [1,1,1]
def find_ancestor(sk, tar_time):
    (prng, ssk_vec) = sk
    ssk = ssk_vec[0]
    for e in ssk_vec :
        if e[0] <= tar_time:
            ssk = e
    return ssk

# Given a subsecrerkey `sk = [g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r]`,
# re-randomize it with `r`, and outputs
# `g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r`.
def randomization(ssk, pp, r):
    (pixelg2gen, h, hlist) = default_param
    (time,  g2r, hpoly, hvector) = copy.deepcopy(ssk)
    # randomize g2r: g2r += g2^r
    tmp = point_mul(r, pixelg2gen)
    g2r = point_add(g2r, tmp)

    # compute tmp = hv[0] * prod_i h[i]^time_vec[i]
    tmp = hlist[0]
    time_vec = time_to_vec(time, d)
    for i in range(len(time_vec)):
        tmp2 = point_mul(time_vec[i], hlist[i + 1])
        tmp = point_add(tmp, tmp2)

    # radomize tmp and set hpoly *= tmp^r
    tmp = point_mul(r, tmp)
    hpoly_new = point_add(hpoly, tmp)

    # randmoize hvector:
    # hvector_new[i] =  hvector[i] * hlist[i+|t|+1]^r
    hvector_new = []
    for i in range(len(hvector)):
        tmp = point_mul(r, hlist[i+1+len(time_vec)])
        hvector_new.append( point_add(tmp, hvector[i]))

    return (time, g2r, hpoly_new, hvector_new)


# Delegate the key into TimeStamp time.
# This function does NOT handle re-randomizations.
# Input `sk = [g, hpoly, h_{|t|+1}, ..., h_D]`,
# and a new time `tn`,
# output `sk = [g, hpoly*\prod_{i=|t|}^|tn| hi^tn[i], h_{|tn|+1}, ..., h_D]`.
def delegate(ssk, tar_time):
    (cur_time,  g2r, hpoly, hvector) = copy.deepcopy(ssk)

    cur_time_vec = time_to_vec(cur_time, d)
    tar_time_vec = time_to_vec(tar_time, d)

    # hpoly *= h_i ^ t_i
    for i in range(len(tar_time_vec)-len(cur_time_vec)):
        tmp = point_mul(tar_time_vec[i+len(cur_time_vec)], hvector[i])
        hpoly = point_add(hpoly, tmp)

    # remove the first `tar_vec_length - cur_vec_length` elements in h-vector
    for _ in range(len(tar_time_vec)-len(cur_time_vec)):
        del hvector[0]

    # return the new ssk
    return (tar_time, g2r, hpoly, hvector)



def vec_to_time(tvec, depth):
    if tvec == []:
        return 1
    else:
        ti = tvec.pop(0)
        return 1 + (ti-1) * (pow(2,depth-1)-1) + vec_to_time(tvec,depth-1)

def time_to_vec(time, depth):
    if time == 1:
        return []
    if depth > 0 and time > pow(2, depth - 1):
        return [2] + time_to_vec(time - pow(2,depth - 1), depth - 1)
    else:
        return [1] + time_to_vec(time - 1,depth - 1)


def gammat(tvec, depth):
#    ans = [vec_to_time(tvec, depth)]
    ans = [tvec]
    for i in range(len(tvec)):
        if tvec[i] == 1:
#            ans.append(vec_to_time((tvec[:i] + [2]),depth))
            ans.insert(1, tvec[:i] + [2])
    return ans


# generate test vectors for public/secret keys that match rust code
def key_update_test_vector_gen():
    seed = b"this is a very long seed for pixel tests"
    _, sk = key_gen(seed)
    for i in range(2,64):
        print(i)

        # update the secret key sequentially, and make sure the
        # updated key matched rust's outputs.
        sk2 = sk_update(copy.deepcopy(sk), default_param, i, "")
        sk_buf = serialize_sk(sk2)

        fname = "test_vector/sk_plain_%02d.txt"%i
        t = sys.stdout
        sys.stdout = open(fname, 'w')
        print_sk(sk2)
        sys.stdout = t

        # output to a binary file
        fname = "test_vector/sk_bin_%02d.txt"%i
        f = open(fname, "wb")
        f.write(sk_buf)
        f.close()

        # compare with rust's output
        fname2 = "../test_vector/test_vector/sk_bin_%02d.txt"%i
        assert filecmp.cmp(fname, fname2)
        sk = copy.deepcopy(sk2)



if __name__ == "__main__":
    def main():
        key_update_test_vector_gen()
    main()
