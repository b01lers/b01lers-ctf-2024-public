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

nc_ed = pwn.remote('gold.b01le.rs', '5006')

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
