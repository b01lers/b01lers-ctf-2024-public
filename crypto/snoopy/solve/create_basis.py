import sys
import os
import numpy as np
from Crypto.Random.random import randrange
from numba import jit


def msg2bits(msg):
  Nbits = len(msg) << 3
  return [ (msg[k >> 3] >> (k & 7)) & 1   for k in range(Nbits) ]

HI = 3.3

@jit(nopython = True)   # serious python computations need something like this..
def sweep(m, turbo = 0.):
  res = m.copy()
  nx,ny = res.shape
  eps = float(0.)
  for i in range(1, nx - 1):
    for j in range(1, ny - 1):
      d = float(0.25) * (m[i, j+1] + m[i, j-1] + m[i+1, j] + m[i-1, j]) - m[i,j]
      res[i,j] += d * (1. - turbo)
      eps = max(eps, abs(d)) 
  return res, eps

def magic(m):
    for _ in range(200000):
      #m, eps = sweep(m, 0.)
      m, eps = sweep(m, 0.01)   # save some on datacenter costs (US Patent No. 20240412)
      if eps < 1e-14:  return m
    return None

def snoop(m, p1, p2):
    (i1,j1) = p1
    (i2,j2) = p2
    # cheapo gear constraints (this is a shoestring op :/)
    if min(i2 - i1, j2 - j1) < 10: 
      print("** Short circuit in detector **", flush = True)
      exit(0)      
    if (i2 - i1) + (j2 - j1) > 40:
      print("** Tampering detected **\nShutting down", flush = True)
      exit(0)      
    data =  [ m[i1, j]  for j in range(j1, j2) ]
    data += [ m[i, j2]  for i in range(i1, i2) ]
    data += [ m[i2, j]  for j in range(j2, j1, -1) ]
    data += [ m[i, j1]  for i in range(i2, i1, -1) ]
    return data

def mapPin(k, N):
    if k < N:      return 0,        k
    elif k < 2*N:  return k % N,    N
    elif k < 3*N:  return N,        (-k) % N
    else:          return (-k) % N, 0


def setup(msg, N):
  m = np.zeros((N + 1, N + 1), dtype = float)
  for i in range(1, N):
      for j in range(1, N):
        m[i, j] = HI * randrange(0, 2**64) / 2**64
  for k,b in enumerate(msg2bits(msg)):
    i,j = mapPin(k, N)
    m[i,j] = b * HI
  return m

def writeBasis(basisFn, Nbits, p1, p2):
  f = open(basisFn, "w")
  for i in range(Nbits):
    msg = int(2**i).to_bytes(Nbits >> 3, "little")
    m = setup(msg, Nbits >> 2)
    m = magic(m)
    h = snoop(m, p1, p2)
    f.write( f"{i} " + " ".join( [str(v)  for v in h ] )  + "\n")
    print(".", end = "", flush = True)

###
# create basis
##

basisFn = sys.argv[1]
Nbits = int(sys.argv[2])

p1 = (22,22)
p2 = (42,42)

print(f"creating basis... Nbits={Nbits} fn={basisFn}")
if not os.path.isfile(basisFn):   writeBasis(basisFn, Nbits, p1, p2)

