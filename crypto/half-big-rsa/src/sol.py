import math
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import os

with open("output.txt","rb") as f:
    file = f.readlines()
    e = int((file[0])[4:])
    n = int((file[1])[4:])
    c = int((file[2])[4:])

g = math.gcd(e, n-1)
# math.gcd(e//g, n-1)
d1 = pow(e//g, -1, n-1)
m1 = pow(c, d1, n)

assert pow(m1, e//g, n) == c # True
assert math.gcd(24 * g, (n-1)//(24 * g)) == 1 # True
m2 = pow(m1, 24, n)
d2 = pow(24 * g, -1, (n-1)//(24 * g))
m_candidate = pow(m2, d2, n)
assert pow(m_candidate, 24 * g, n) == m2 # True

# Find a subgroup E with order 432 in F_n^*
gen_ind = 1
gen_E = 1 # generator of E

# 432 = 2^4 * 3^3
# Exclude the elements whose 2^4, 3^3, 2^3 * 3^3, or 2^4 * 3^2 power is 1
# Their factors form the factors of 432. 
while gen_E == 1 or pow(gen_E, 16, n) == 1 or pow(gen_E, 27, n) == 1 \
	or pow(gen_E, 144, n) == 1 or pow(gen_E, 216, n) == 1:
	gen_ind += 1
	gen_E = pow(gen_ind, (n-1) // (24 * g), n)

# Testing to make sure g_E is order 432
for i in range(24 * g + 1):
	if i != 0 and i != 24 * g:
		assert pow(gen_E, i, n) != 1

for i in range(0, 24 * g):
	m = (m_candidate * pow(gen_E, i, n)) % n
	if pow(m, e, n) == c and b'bctf{' in long_to_bytes(m):
		print(long_to_bytes(m))
		## b'bctf{Pr1M3_NUM83r5_4r3_C001_bu7_7H3Y_4r3_57r0N6_0N1Y_WH3N_
        ##        7H3Y_4r3_MU171P113D_3V3N_1F_7H3Y_4r3_b1g}'