## change the following path to your bls_sig_ref's sage code
bls_curve_path = r'/Users/zhenfei/Documents/GitHub/consensus_sig_v2/bls_sigs_ref/sage-impl'

import sys
sys.path.insert(0, bls_curve_path)


from hash_to_field import hash_to_field
from hashlib import sha256
from __sage__g1_common import print_g1_hex, q
from __sage__g2_common import print_g2_hex


### public constants
D = 4   # depth

def print_sk(sk):
    print "==========================="
    print "secret key"
    t_vec = copy(sk[0])
    time = vec2time(t_vec, D)
    print "time:", time, ",   time vector", sk[0]
    for i in range(len(sk[1])):
        print "%d-th sub secret key" % i
        print_ssk(sk[1][i])
    print "==========================="

def print_ssk(ssk):
    print "g2 element"
    print_g2_hex(ssk[0])
    for i in range (1,len(ssk)):
        print "g1 elements"
        print_g1_hex(ssk[i])

def print_param(pp):
    print "==========================="
    print "parameters"
    print "g1"
    print_g1_hex(pp[0])
    print "g2"
    print_g2_hex(pp[1])
    print "h"
    print_g1_hex(pp[2])
    for i in range(len(pp[3])):
        print "h%d"%i
        print_g1_hex(pp[3][i])
    print "==========================="

## an instantiation of the G_0 function
## output = hash_to_field("G0_hash"| input, 0, q, Sha256, 1)
def hash_1(seed):
    s = b"G0_hash" + seed
    if not isinstance(s, bytes):
        raise ValueError("hash_1 can't hash anything but bytes")
    return hash_to_field(s, 0, q, 1)[0]

## an instantiation of the G_1 function
## output = sha256("G1_hash"| input)
def hash_2(seed):
    s = b"G1_hash" + seed
    if not isinstance(s, bytes):
        raise ValueError("hash_2 can't hash anything but bytes")
    t = sha256(s).digest()
    return t

## helper functions for handling time
## adopted from pixel.py

def time2vec(t,D):
   ## converts number to vector representation
   ## requires D >=1 and t in {1,2,...,2^D-1}
   if t==1:
     return []
   if D>0 and t > pow(2,D-1):
      return [2] + time2vec(t-pow(2,D-1),D-1)
   else:
      return [1] + time2vec(t-1,D-1)

def vec2time(tv,D):
   ## converts vector representation to number
   if tv == []:
      return 1
   else:
      ti = tv.pop(0)
      return 1 + (ti-1) * (pow(2,D-1)-1) + vec2time(tv,D-1)
