#!/usr/bin/python
#
# Pixel scheme with BLS12-381
#
# (C) 2019 Hoeteck Wee <hoeteck@alum.mit.edu>


## Overview of Pixel -- https://eprint.iacr.org/2019/514

## public parameters
## g1, g2, h
## hv: vector of D+1 group elements in G1

## treat time in {1,2,...,2^D-1} as vectors over {1,2}^{<= D-1}.
## see time2vec, vec2time
## note: D is ell in the paper.

## given time t in {1,2}^{<= D},
## secret keys sk_t = (t, skv_t)
## * where t is the current time vector
## * skv_t is a list of subkeys tsk_* defined below
## * we maintain the invariant len(skv_t) = len(t) + 1
## * and the first entry of skv_t is tsk_t

## Example for D=4
##   sk_empty = (tsk_[])
##   sk_1 = (tsk_1, tsk_2)
##   sk_11 = (tsk_11, tsk_2, tsk_12)
##   sk_111 = (tsk_111, tsk_2, tsk_12, tsk_112)
##   sk_112 = (tsk_112, tsk_2, tsk_12, [])
##   sk_12 = (tsk_12, tsk_2, [])
##   sk_121 = (tsk_121, tsk_2, [], tsk_122)
##   sk_122 = (tsk_122, tsk_2, [], [])
##   sk_2 = (tsk_2, [])
##   sk_21, sk_211, sk_212, sk_22, sk_221, sk_222

## we define tkey_rand, tkey_del to manipulate the tsk's.
## given a vector w of length <= D,
## * hw(w) := h_0 prod hj^wj  // convenient short-hand
## * tsk_w : (g2^r, h^x hw(w)^r, h_{|w|+1}^r, ..., h_{D+1}^r)
## * convenient to think of tsk_w as randomizing (1, h^x, 1, ..., 1),
##   i.e., point-wise multiply by (g2^r, hw(w)^r, h_{|w|+1}^r, ..., h_{D+1}^r)

## signing a message M given sk_t for time t
## signature is of the form:
##    (g2^r, h^x hw(t)^r h_D^{M r} )
## note: hw(t) h_D^M = hw(t||0^{D-|t|-1}||M)
## i.e., delegate tsk_t to t||0^{D-|t|-1}||M and randomize

## verifying a signature sig on M w.r.t time t
## * sig[0] = g2^r
## * sig[1] = h^x hw(t)^r h_D^{M r}
## * pk = g2^x
## * check e(sig[1], g2) = e(h, pk) * e(hw(t) h_D^M, sig[0])

curve = 1
## curve = 0: insecure! demonstrates arithmetic "in the exponent"
## curve = 1: uses BLS12-381

from random import seed
from random import randint
if (curve == 1):
  # requires Python 3 for the underlying BLS12-381 arithmetic
  from consts import g1suite, q
  from curve_ops import g1gen, g2gen, point_mul, point_neg, point_add, point_eq
  from pairing import multi_pairing
  from util import get_cmdline_options, prepare_msg, print_g1_hex, print_g2_hex, print_tv_sig

### public constants
D = 4   # depth

### export the determinstic randomness for testing and cross comparison
### with other implementation

seed(42)
file = open("randomness.txt", "w")



### helper functions to interface with curve operations

if (curve == 1):
  def G1add(a,b):
    return point_add(a,b)

  def G2add(a,b):
    return point_add(a,b)

  def G1mul(a,b):
    ## a group element, b scalar
    return point_mul(b,a)

  def G2mul(a,b):
    return point_mul(b,a)

  def G2neg(a):
    return point_neg(a)

  def G1rand():
    r = randint(1, q-1)
    file.write(str(r))
    file.write("\n")
    return G1mul(g1gen,r)

  def G2rand():
    r = randint(1, q-1)
    file.write(str(r))
    file.write("\n")
    return G2mul(g2gen,r)

  def GTtestpp(va,vb):
  ## checks whether <va, vb> == 0
    return (multi_pairing(va,vb) == 1)

else:
  q = 17

  def point_eq(a,b):
    return a == b

  def G1add(a,b):
    return (a+b) % q

  def G2add(a,b):
    return (a+b) % q

  def G1mul(a,b):
    return (a*b) % q

  def G2mul(a,b):
    return (a*b) % q

  def G2neg(a):
    return -a

  def G1rand():
    return randint(0,q-1)

  def G2rand():
    return randint(0,q-1)

  def GTtestpp(va,vb):
  ## checks whether <va, vb> == 0
    return (vip(va,vb) == 0)


### helper functions layered on top of curve operations

def vadd(va, vb):
## input: vectors va, vb
## return coordinate-wise addition of va, vb
## in group setting: first entry over G2, remaining entries over G1
  assert (len(va) > 0)
  ans = [ G2add(va[0],vb[0]) ]
  for i in range(1,len(va)):
      ans.append( G1add(va[i],vb[i]) )
  return ans

def vmul(va, b):
## multiply each entry of vector va by scalar b
## in group setting: first entry over G2, remaining entries over G1
  assert (len(va) > 0)
  ans = [ G2mul(va[0],b) ]
  for i in range(1,len(va)):
      ans.append( G1mul(va[i],b) )
  return ans

def vip(va, vb):
## return inner product of va, vb
## in group setting: this is over G1
  ans = G1mul(va[0],vb[0])
  for i in range(1,len(va)):
      ans = G1add(ans, G1mul(va[i],vb[i]))
  return ans

def tmv(tv, M):
## returns the vector associated with time tv and message M
  return tv + [0] * (D-len(tv)-1) + [M]

## helper functions for handling time

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

### public parameters
g1 = G1rand()
g2 = G2rand()
h = G1rand()
hv = [0] * (D+1) ## vector of D+1 group elements in G1

def hw(wv):
  ## h_0 prod hj^wj
  ## wv is a vector
#   ans = hv[0]
#   for i in range(1,len(wv)+1):
#     if wv[i-1] != 0:
#       ans = G1add(ans, G1mul(hv[i],wv[i-1]))
#   return ans
  return vip(hv[:len(wv)+1], [1]+wv)

## === formatting issues
## sk_tv is a pair tv, skv_tv
##   skv is a vector starting with tsk_tv, followed by remaining subkeys
##   assert len(skv) == len(tv)+1
## tsk_w doesn't contain w
##   assert len(tsk) == D-len(w)+2
## signature on a message doesn't contain time period

def setup():
  for i in range(0,D+1):
      hv[i] = G1rand()

def tkey_rand(tsk,w,r=None):
  ## randomizes tsk_w -- doesn't mutate
  ## that is, multiplies tsk_w by
  ## g2^r, (h_0 prod hj^wj)^r, h_{|w|+1}^r, ..., h_D^r
  ## i.e., r times [g2] + [hw(w)] + hv[len(w)+1:]
  ## TODO: erase r after? in RO, can avoid separately erasing stuff.
  if r is None:
    r = randint(1, q-1)
    file.write(str(r))
    file.write("\n")
  ha = hw(w)  ## h_0 prod hj^wj
  hvb = hv[len(w)+1:] ## h_{|w|+1}, ..., h_D
  #print r, [g2] + [ha] + hvb, vmul([g2] + [ha] + hvb, r)
  return vadd(tsk, vmul([g2] + [ha] + hvb, r))

def tkey_delegate(tsk,w,wplus):
  ## delegates tsk_w to tsk_{w || wplus} -- doesn't mutate
  ## doesn't randomize
  assert len(tsk) == D-len(w)+2
  wnew = w + wplus
  ans = tsk[0:1] # g2^r
  ans.append(vip(tsk[1:len(wplus)+2], [1]+wplus)) ## computes (h_0 prod hj^wj)^r for wnew
  ans.extend(tsk[len(wplus)+2:]) ## h_{|wnew|+1}^r, ..., h_D^r
  return ans

def keygen(x=None):
  ## if x is not specified, pick a random x
  if x is None:
    x = randint(1, q-1)
    file.write(str(x))
    file.write("\n")
  # print "x ",x
  pk = G2mul(g2,x)   ## g2^x over G2
  ## tsk_empty = randomize(1, h^x, 1, ..., 1)
  # print "hx ", h, x, h*x
  #tsk0 = [0] + [h * x] + D*[0]
  tsk0 =  tkey_rand([G1mul(h,0)] + [G1mul(h,x)] + D*[G1mul(h,0)], []) ## G2 x G1^{D+1}
  sk = ([], [tsk0])
  return (pk, sk)

def keyupdate(sk):
  ## updates t to t+1, mutates sk
  ## requires t+1 <= 2^{D}-1
  ## MUST implement secure erasures!
  ## TODO: implement taking an optimal parameter for fast updates
  (tv, skv) = sk
  ## TODO: erase/garbage-collect old tskv[0]
  if (len(tv) < D-1):
    ## NOT leaf node: always append 1 to tv
    ## tv: append 1
    ## skv: delagate tv to tv||1, tv||2, randomize tv||2, remove tv
    ## example:
    ##   sk_12 = (tsk_12, tsk_2, [])
    ##   sk_121 = (tsk_121, tsk_2, [], tsk_122)
      tskv1 = tkey_delegate(skv[0],tv,[1]) ## tv||1
      tskv2 = tkey_rand(tkey_delegate(skv[0],tv,[2]),tv + [2]) ## tv||2
      skv[0] = tskv1
      skv.append(tskv2)
      tv.append(1) ## tv = tv+[1] doesn't mutate
  else:
    ## IS leaf node (i.e len(tv) == D-1): convert last1 to a 2 in tv
    ## example, D=4:
    ##   sk_122 = (tsk_122, tsk_2, [], [])
    ##   sk_2 = (tsk_2, [])
      last1=0
      for j in range(len(tv)):
        if tv[j] == 1:
          last1 = j
          ## e.g. for 122, last1=0
      ## tv: change the last 1 to a 2, remove all remaining entries
      ## skv: move 2 to the first position, also remove corresponding entries
      skv[0] = skv[last1+1]
      skv[last1+1] = []
      del skv[last1+2:]
      tv[last1] = 2
      del tv[last1+1:]
  assert len(skv) == len(tv)+1

def sign(sk, M, r=None):
  ## signs message M in Z_q under the time period associated with sk
  ## switch order of sig1, sig2 in paper
  ## delegate tsk_tv to tv||0^{D-|tv|-1}||M and randomize
  (tv, tskv) = sk
  wplus = [0] * (D-len(tv)-1) + [M]  # 0^{D-|tv|-1}||M
  siga = tkey_delegate(tskv[0],tv,wplus)
  sig = tkey_rand(siga, tmv(tv, M),r)
  return sig

def verify(pk, tv, M, sig):
  ## check e(sig[1], g2) = e(h, pk) * e(hw(tv) h_D^M, sig[0])
  return GTtestpp( [sig[1],    h,  hw(tmv(tv,M))],
                   [G2neg(g2), pk, sig[0] ] )

def test():
      x = randint(1, q-1)
      file.write(str(x))
      file.write("\n")

      setup()
      (pk, sk1) = keygen(x)

      print("q", q, "depth", D, "msk", x)
      print("g2, h, h1,...,hD, ", g2, h, hv)
      print("pk,sk1", pk, sk1)
      (vt, tskv) = sk1
      tsk0 = tskv[0]


      print("== testing hw")
      assert point_eq(hw([]),hv[0])
      assert point_eq(hw([1]),G1add(hv[0],hv[1]))

      print("== testing delegation")
      tsk1 = tkey_delegate(tsk0,[],[1])
      #print("tsk for [1] ", tsk1)
      tsk11 = tkey_delegate(tsk1,[1],[1])
      assert tkey_delegate(tsk0,[],[1,1]) == tsk11
      #print("tsk for [1,1] ",tsk11, tkey_delegate(tsk0,[],[1,1]))
      assert tkey_delegate(tsk0,[],[1,1,2]) == tkey_delegate(tsk11,[1,1],[2])

      #sig001 = tkey_delegate(tsk0,[],[0,0,1])
      #print("delegate to 0,0,1", sig001, tkey_rand(sig001,[0,0,1]))

      print("== testing randomization")
      print("tsk for []", tkey_rand(tsk0,[]), tkey_rand(tsk0,[]))
      #print("tsk for [1]", tkey_rand(tsk1,[1]),tkey_rand(tsk1,[1]))
      assert tkey_rand(tsk1,[1],0) == tsk1
      print("tsk for [1,1]", tkey_rand(tsk11,[1,1]),tkey_rand(tsk11,[1,1]))
      assert not point_eq(tsk0[0],tkey_rand(tsk0,[])[0]), "randomization not adding entropy"

      print("== testing sign")

      ## signing M, time=1, randomness=0  ==  delegate to [0,0,0,M]
      assert sign(sk1,2,0) == tkey_delegate(tsk0,[],(D-1)*[0]+[2])
      assert sign(sk1,2,3) == tkey_rand(tkey_delegate(tsk0,[],(D-1)*[0]+[2]),(D-1)*[0]+[2],3)

      sig1 = sign(sk1,1)
      sig2 = sign(([1,1],[tsk11]),3)
      ## t = [], sig looks like: (r, x+h_D * M * r)
      print("x, w_001, w_113", x, hw([0,0,1]), hw([1,1,3]))
      print(tkey_delegate(tsk0,[],[0,0,1]))
      #print("assuming g2=1"
      # assert (g2 == 1)
      print("sig on M=1,t=[]", sig1) #, sig1[0], (hw([0,0,1]) * sig1[0] + h*x) % q
      print("sig on M=3,t=[1,1]", sig2) #, sig2[0], (hw([1,1,3]) * sig2[0] + h*x) % q

      print("== testing verify")
      print("verifying tsk0 well-formed via pairing")
      assert GTtestpp( [hw([]),   tsk0[1],   h],
                       [tsk0[0],  G2neg(g2), pk] )
      print("verifying one-step delegation via pairing")
      assert GTtestpp( [hw([1]),  tkey_delegate(tsk0,[],[1])[1],   h],
                       [tsk0[0],  G2neg(g2), pk] )

      assert sign(sk1,1,0) == tkey_delegate(tsk0,[],(D-1)*[0]+[1])

      print("verifying sign M=1, t=[]")
      assert GTtestpp( [hw((D-1)*[0]+[1]),   sign(sk1,1,0)[1],   h],
                       [tsk0[0],  G2neg(g2),          pk] )
      assert verify(pk,[],1,sign(sk1,1,0))
      #return GTtestpp( [sig[1],    h,  hw(tmv(tv,M))],
      #                 [G2neg(g2), pk, sig[0] ] )
      assert verify(pk,[1,1],3,sig2)
      assert not verify(pk,[1,1],3,[sig2[0],G1rand()]), "random signature should not verify"

      print("== testing update")

      for i in range(2**D-1):
        print("sk_", i) #, ": ", sk1
        print("  time ", sk1[0])
        print("  key  ", sk1[1])
        sig = sign(sk1,3) # time [2,2]
        time = sk1[0]
        print("  signature on M=3 ", sig, verify(pk,time,3,sig))
        keyupdate(sk1)


if __name__ == "__main__":
  def main():
    #if sys.version_info[0] < 3:
    #  sys.exit("This script requires Python3 or PyPy3 for the underlying BLS12-381 operations.")
    test()
    file.close()
  main()
