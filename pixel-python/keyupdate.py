from param import d, default_param
from curve_ops import point_mul, point_add


# Given a subsecrerkey `sk = [g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r]`,
# re-randomize it with `r`, and outputs
# `g^r, (h_0 prod hj^tj)^r, h_{|t|+1}^r, ..., h_D^r`.
def randomization(ssk, pp, r):
    (pixelg2gen, h, hlist) = default_param
    (time,  g2r, hpoly, hvector) = ssk

    # randomize g2r: g2r += g2^r
    tmp = point_mul(r, pixelg2gen)
    g2r = point_add(g2r, tmp)

    # compute tmp = hv[0] * prod_i h[i]^time_vec[i]
    tmp = hlist[0]
    time_vec = time_to_vec(time, d)
    for i in 0..len(time_vec):
        tmp2 = point_mul(time_vec[i], hlist[i + 1])
        tmp = point_add(tmp, tmp2)

    # radomize tmp and set hpoly *= tmp^r
    tmp = point_mul(r, tmp)
    hploy = point_add(hpoly, tmp)

    # randmoize hlist
    for i in range(len(hvector)):
        hvector[i] = point_mul(r, hvector[i])

    return (time, g2r, hpoly, hvector)


# Delegate the key into TimeStamp time.
# This function does NOT handle re-randomizations.
# Input `sk = [g, hpoly, h_{|t|+1}, ..., h_D]`,
# and a new time `tn`,
# output `sk = [g, hpoly*\prod_{i=|t|}^|tn| hi^tn[i], h_{|tn|+1}, ..., h_D]`.
def delegate(ssk, tar_time):
    (cur_time,  g2r, hpoly, hvector) = ssk

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





def time_to_vec(time, depth):
    if time == 1:
        return []
    if depth > 0 and time > pow(2, depth - 1):
        return [2] + time2vec(time - pow(2,depth - 1), depth - 1)
    else:
        return [1] + time2vec(time - 1,depth - 1)


def gammat(tvec):
    ans = [tvec]
    for i in range(len(tvec)):
        if tvec[i] == 1:
            ans.append(tvec[:i] + [2])
    return ans
