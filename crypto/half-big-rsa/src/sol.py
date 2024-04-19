import math
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import os

with open("output.txt","rb") as f:
    file = f.readlines()
    e = int((file[0])[4:])
    n = int((file[1])[4:])
    c = int((file[2])[4:])

# e = 8190 = 2 · 3^2 · 5 · 7 · 13
# factorbd says # n-1 = 2^4 · 3^3 · 202021 · 7625664192...09
g = math.gcd(e, n-1) # 18 = 2 * 3^2
# e/g = 5 * 7 * 13 and this is coprime with n-1
d_prime = pow(e // g, -1, (n-1) // g) # (e/g) d' = ((n-1)/g) k + 1
c_prime = pow(c, d_prime, n) # m' = c^d' = (m^e)^d' = m^g mod n (b/c n is prime)
assert pow(c_prime, e // g, n) == c # c_prime = m^18 mod n
c_prime_2 = pow(c_prime, 8 * 3, n) # (m')^24 = (m^18)^24 = m^432
e_prime_2 = g * (8 * 3) # 432

# Find a subgroup E with order 432 in F_n^*
# E is cyclic since F_n is a finite field because n is prime.
gen_ind = 1
gen_E = 1 # generator of E

# 432 = 2^4 * 3^3
# Exclude the elements whose 2^4, 3^3, 2^3 * 3^3, or 2^4 * 3^2 power is 1
# Their factors form the factors of 432. 
while gen_E == 1 or pow(gen_E, 16, n) == 1 or pow(gen_E, 27, n) == 1 or pow(gen_E, 144, n) == 1 or pow(gen_E, 216, n) == 1:
	gen_ind += 1
	gen_E = pow(gen_ind, (n-1) // e_prime_2, n)

# Testing to make sure g_E is order 432
for i in range(e_prime_2 + 1):
	if i != 0 and i != e_prime_2:
		assert pow(gen_E, i, n) != 1

d_prime_2 = pow(e_prime_2, -1, (n-1)//e_prime_2)
m_candidate = pow(c_prime_2, d_prime_2, n)
assert pow(m_candidate, e_prime_2, n) == c_prime_2

for i in range(0, e_prime_2):
	m = (m_candidate * pow(gen_E, i, n)) % n
	if pow(m, e, n) == c and b'bctf{' in long_to_bytes(m):
		print(long_to_bytes(m))
		# b'bctf{Pr1M3_NUM83r5_4r3_C001_bu7_7H3Y_4r3_57r0N6_0N1Y_WH3N_7H3Y_4r3_MU171P113D_3V3N_1F_7H3Y_4r3_b1g}'

