from pwn import *
from Crypto.Cipher import AES


def readBasis(fname):
  lines = open(fname, "r").read().strip().split("\n")
  N = len(lines)
  Nsnoop = len(lines[0].split()) - 1
  basis = [None]*N
  for l in lines:
    flds = l.split()
    idx = int(flds[0])
    vec = [ float(v)  for v in flds[1:] ]
    basis[idx] = vec
  return basis

def msg2bits(msg):
  Nbits = len(msg) << 3
  return [ (msg[k >> 3] >> (k & 7)) & 1   for k in range(Nbits) ]

def snoopValues(msg, basis):
  bits = msg2bits(msg)
  Nbits = len(bits)
  assert Nbits == len(basis)
  Nsnoop = len(basis[0])
  values = [0]*Nsnoop
  for k in range(Nbits):
    if bits[k] != 0:  
      for j in range(Nsnoop):  values[j] += basis[k][j]
  return values



##
# connect to challenge
##

#r = process(["python3", "snoopy.py"])
r = remote("localhost", 9104)

r.recvuntil(b">")

# place loop
r.send(b"1\n22 22\n42 42\n")
r.recvuntil(b">")

# boot
r.send(b"2\n")
r.recvuntil(b">")

# encrypt
r.send(b"4\n")
r.recvuntil(b">")

# snoop
r.send(b"5\n")
in1 = r.recvuntil(b">").strip().split(b"\n")
data = [float(v)  for v in in1[1].split(b"[")[1].replace(b",", b"")[:-1].split() ]
print(len(data), data)


##
# SOLVE
##

# write basis

# read basis
basis = readBasis("basis32.dat")

Nsnoop = len(data)
N = len(basis)
print(f"# N={N} Nsnoop={Nsnoop}")


# subtract off known initial state
Nkey = 8
knownState = (b"SnOoPy@BCtf204#"*2)[:16 - Nkey + 1] + b"\x00"*(Nkey-2) + b"\x01"
knownStateFull = b"".join( [ b"\x00" + knownState[i:i+1]   for i in range(16) ] )

print(f"known state: {knownStateFull}")

knownSnoop = snoopValues(knownStateFull, basis)
data = [ v - u   for v,u in zip(data, knownSnoop) ]


# quantize
FAC = 10**9
cdata = [int(v * FAC + 0.5)  for v in data] 

cbasis = [None]*N
for i in range(len(basis)):
  cbasis[i] = [int(v * FAC + 0.5)  for v in basis[i]]

print(f"cdata: {cdata}")

for i in range(5):
  print(i, cbasis[i])


###
# prepare for LLL
###

# skip basis vectors
def cutBasis(basis):
  res = []
  N = len(basis)
  # basis vectors for aes result -> all even registers but skip 4 corners of die
  for k in range(N):
    if (4 * k) % N == 0: continue        # skip corners
    if (k >> 3) & 1 != 0:  continue      # skip odd
    res.append(basis[k])
  # parts of encryption key -> contiguous range of odd registers
  # two key bytes are lost:
  # - 1st byte was in register  0 => overwritten during encryption
  # - 2nd byte was in register -1 => replaced with counter after encryption
  #
  for k in range(N):
    idx = (k >> 3)
    if idx & 1 == 0:  continue
    if idx < (35 - 2*Nkey) or idx > 29: continue
    res.append(basis[k])
  return res

cbasis2 = cutBasis(cbasis)
basis2 = cutBasis(basis)

N = len(basis2)
print(f"Ncut: {N}")

M = matrix(ZZ, N + 1, N + Nsnoop)

SCL = 1
SCL2 = 100
print(f"SCL={SCL} SCL2={SCL2}")

for i in range(N):
  for k in range(Nsnoop): M[i, N + k] = SCL * 2 * cbasis2[i][k]
  M[i, i] = 2 * SCL2
for k in range(Nsnoop):   M[N, N + k] = SCL * 2 * cdata[k]
for k in range(N):       M[N, k] = SCL2

Mred = M.LLL()
for idx,v in enumerate(Mred):
  if (v[0] // SCL2) & 1 == 0: continue
  coeffs = [ x // SCL2 for x in v[:N] ]
  if not all( [ abs(v) == 1  for v in coeffs ] ): continue
  print(f"IDX={idx}, norm={sum([x**2  for x in v])}")
  print(coeffs)
  print( [ x // SCL for x in v[N:] ] )
  break
else:
  print("NO SOLUTION - try again")
  exit(0)


ctxtReco = [ (1 - v) >> 1  for v in coeffs[:124] ]
# fill corner bits with 0-0-0-0
ctxtReco = [0] + ctxtReco[:31] + [0] + ctxtReco[31:62] + [0] + ctxtReco[62:93] + [0] + ctxtReco[93:]
ctxtReco = [ sum( [ 2**k * ctxtReco[pos + k]   for k in range(8) ] )   for pos in range(0, len(ctxtReco), 8) ]
print(f"ctxt RECO: {ctxtReco}")


keyReco = [ (1 - v) >> 1  for v in coeffs[124:] ]
keyReco = [0, 0] + [ sum( [ 2**k * keyReco[pos + k]   for k in range(8) ] )   for pos in range(0, len(keyReco), 8) ][::-1]
print(f"key RECO: {keyReco}")


# decrypt
for b in range(0x10000):
  keyCand = [int(b & 0xff), int(b >> 8)] + keyReco[2:]
  aes = AES.new(bytes(keyCand)*4, AES.MODE_ECB)
  for i in range(16):
    ctxtCand = bytearray(ctxtReco)
    for k in range(4):  ctxtCand[k * 4] ^^= (i >> k) & 1
    flagCand = aes.decrypt(bytes(ctxtCand))
    if any( [ v >= 0x80 or v <= 0x20    for v in flagCand] ):  continue
    print(b, i, flagCand)
