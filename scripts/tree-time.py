
def time2vec(t,D):
   # requires D >=1 and t in {1,2,...,2^D-1}
   if t==1:
     return []
   if D>0 and t > pow(2,D-1):
      return [2] + time2vec(t-pow(2,D-1),D-1)
   else:
      return [1] + time2vec(t-1,D-1)

def vec2time(tvec,D):
   if tvec == []:
      return 1
   else:
      ti = tvec.pop(0)
      return 1 + (ti-1) * (pow(2,D-1)-1) + vec2time(tvec,D-1)

def gammat(tvec):
   ans = [tvec]
   for i in range(len(tvec)):
      if tvec[i] == 1:
         print tvec[:i]
         ans.append(tvec[:i] + [2])
   return ans

print gammat([1,2,1])

D = 3
for i in range(1,pow(2,D)):
   tvec = time2vec(i,D)
   print i, " : ", tvec, " : ", vec2time(tvec,D)
