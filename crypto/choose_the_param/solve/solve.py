from Crypto.Util.number import long_to_bytes
from sage.all import Integer, CRT
from pwn import *

#p = process("./chal.py")
p = remote("127.0.0.1", 5001)

ms = []
ns = []
bits = 500*8
prime_len = 48
print(bits//prime_len)
for i in range(bits//prime_len):
    p.recvuntil("primes> ")
    p.sendline(str(prime_len))

    n = int(p.recvline().split(b" = ")[-1], 16)
    e = int(p.recvline().split(b" = ")[-1], 16)
    c = int(p.recvline().split(b" = ")[-1], 16)
    print(n, e, c)

    (P, _), (Q, _) = Integer(n).factor()
    d = pow(e, -1, (P-1)*(Q-1))
    m = pow(c, int(d), n)
    ms.append(m)
    ns.append(n)

flag = long_to_bytes(CRT(ms, ns))
print(flag[200:-200])

