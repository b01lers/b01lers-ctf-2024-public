---
header-includes:
   - \usepackage{amsmath}
output:
  pdf_document:
    keep_tex: true
---
# Writeup for shamir-for-dummies by FlaggnGoose

## Add your writeup here!

Following the notations in https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing, let $n$ be the number of parties and $k$ be the reconstruction threshold. 

Based on <code>server.py</code>, our 'friend' is running the reconstruction algorithm for additive secret sharing scheme (modulo some 'weight' that he has to divide in the end) with the shares generated using Shamir secret sharing scheme. Both Shamir and additive SS are linear secret sharing schemes based on linear codes; that is, the secret $s$ can be written as a linear combination of $k$ shares among $n$ shares $s_1, \dots, s_n$, making Shamir SS basically Additive SS with some 'weights' when $n = k$. However, in this problem, the choice of 'weight' is limited; we need to generate shares $s_1, \dots, s_n$ and find the weight $\lambda$ such that $\lambda^{-1} s_1 + \cdots + \lambda^{-1} s_n = s$, or $s_1 + \cdots + s_n = \lambda s$ equivalently. 

Let $\omega$ be a non-trivial $n$-th root of unity modulo $p$; that is, $\omega^n = 1 \mod p$ where $\omega \neq 1 \mod p$. Moreover, the following equality holds
$$
1 + \omega + \cdots + \omega^{n-1} = 0 \mod p
$$
If in particular we choose $\omega$ to be a primitive $n$-th root of unity modulo $p$, then $\omega, \omega^2, \cdots, \omega^{n-1}, \omega^n = 1$ are all distinct and are solutions to the equation $x^n - 1 = 0 \mod p$. 
The existence of such $\omega$ is guaranteed when we have $p$ a prime and $p = 1 \mod n$ which <code>server.py</code> does. Also, by choosing $n$ to be prime, any non-trivial $n$-th root of unity would also be primitive. 

Denote $P(X) = s + c_1 X + c_2 X^2 + \cdots + c_{n-1} X^{n-1}$ (note that since $k = n$, it should be a degree $n-1$ polynomial). Then
\begin{align*}
\sum_{i=1}^n P(\omega^i)
& = sn + c_1 \sum_{i=1}^n \omega^i + \cdots + c_{n-1} \sum_{i=1}^n (\omega^i)^{n-1} \\
& = sn + c_1 \sum_{i=1}^n \omega^i + \cdots + c_{n-1} \sum_{i=1}^n (\omega^{n-1})^{i} \\
& = sn + c_1 \sum_{i=1}^n \omega^i + \cdots + c_{n-1} \sum_{i=1}^n \omega^{i} \\
& = sn + c_1 (0) + \cdots + c_{n-1} 0 \mod p \\
& = sn \mod p
\end{align*}

Finding the $n$-th root of unity $\omega$ can be seen as finding the (cyclic) subgroup of size $n$ in $F_p$, and this can be done via exhaustive search: find $g$ such that $g^{\frac{p-1}{n}} \neq 1 \mod p$ (see https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Finding_primitive_roots).

All in one:
```python
import os
import sys
import time
import math
import random
from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes
import pwn

def nth_root_of_unity(n, p):
  gen_ind = 1
  gen_E = 1 # generator of E
  while gen_E == 1:
    gen_ind += 1
    gen_E = pow(gen_ind, (p-1) // n, p)
  assert pow(gen_E, n, p) == 1
  sum_omega_i = 0
  for i in range(0, n):
    sum_omega_i += pow(gen_E, i, p)
  assert (sum_omega_i % p) == 0
  return gen_E

nc_ed = pwn.remote('localhost', '5040')

nc_ed.recvuntil("n = ")
n = int(nc_ed.recvline())
nc_ed.recvuntil("p = ")
p = int(nc_ed.recvline())

for i in range(1, n+1):
  nc_ed.recvuntil("> ")
  nc_ed.sendline(str(pow(nth_root_of_unity(n, p), i, p)))

nc_ed.recvuntil("> ")
nc_ed.sendline(str(n))
# nc_ed.interactive()
nc_ed.recvuntil("The shares P(X_i)'s were':\n")
shares = nc_ed.recvline()
shares = str(shares, encoding='utf-8')
shares = (shares[1:])[:-2] # removing brackets and "\n"
# print("sol.py got shares as =", shares)
share_list = shares.split(", ")
# print(share_list)
sum_shares = 0
for s_i in share_list:
  sum_shares += int(s_i)
sum_shares %= p
sum_shares = (sum_shares * pow(n, -1, p)) % p
print(long_to_bytes(sum_shares)) # b'bctf{P0LYN0m14l_1N_M0d_P_12_73H_P0W3Rh0u23_0F_73H_5h4M1r}'
``` 

This is a simplified version of the attack on Shamir secret sharing scheme, where attackers can choose evaluation places adversarially, by Maji et al. EuroCrypt 2021 (https://eprint.iacr.org/2021/186) and Maji et al. ITC 2022 (https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITC.2022.16).
