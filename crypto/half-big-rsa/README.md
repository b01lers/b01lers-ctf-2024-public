
---
header-includes:
   - \usepackage{amsmath}
output:
  pdf_document:
    keep_tex: true
---

# Writeup for half-big-rsa by FlaggnGoose

## Add your writeup here!

We are given the equation $c = m^e \mod n$ where $n$ is a 4096-bit prime number. 

Normally, we can find $d = e^{-1} \mod n-1$ then take $c^{d} \mod n$ but since $g := \gcd(e, n-1) = 18 \neq 1$ so such $d$ does not exist. 

We can instead find $d'$ such that $(e/g)d' = 1 \mod (n-1)/g$. This is equivalent to $ed' = g \mod n-1$ and hence
$$
c' := c^{d'} = (m^e)^{d'} = m^{ed'} = m^g \mod n
$$
 
Let $e' = g$ and so $c' = m^{e'} \mod n$ as above. Since $n$ is a 4096-bit prime number, it'd take forever to solve using the nth_root function in Sage. 

One way to solve this equation would be to take cubic residue twice and take quadratic residue (note that $e' = 18 = 2 \times 3^2$. However, since $n = 1 \mod 3$, such an approach is likely inefficient and/or unnecessarily complicated. 

Now we take $e'$-th root of $c'$. We can start by finding $e'^{-1} \mod (n-1)/e'$ but such inverse does not exist because $\gcd(e', (n-1)/e') = 6 != 1$.

Factorbd says $n-1 = 2^4 \times 3^3 \times 202021 \times 7625664192\dots09$. Since $e' = 18 = 2 \times 3^2$, we would have $\gcd(e' \cdot 2^3\cdot 3, (n-1)/e') = 1$ for sure. 

Let $c'' := (c')^{2^3 \times 3} = m^{e' \times 24} \mod n$. Let $e'':= 24e' = 432$ so $c'' = m^{e''} \mod n$. Then we can find $d''$ such that $d'' = (e'')^{-1} \mod (n-1)/e'$. We can then find a candidate $m$ which is $m_{\mathrm{candidate}} = (c'')^{d''} \mod n$.

However, note that $\mathbb{F}_n^*$ is a field --- there can be up to $432$ many $432$-th root. Let $g_{432}$ be the generator of a subgroup $\mathbb{F}_n^*$ of size $432$ (since $\mathbb{F}_n^*$ is a finite field, every subgroup is cyclic). Such a $g_{432}$, fortunately, can be found brute forcefully by taking $(n-1)/432$-th power of every element (notice that the $432$-th power of this element is guaranteed to be $1$) but excluding those whose order is not $432$ but a factor of $432$.

Once we find $g_{432}$, we can examine the set 
$$
M := \{ m_{\mathrm{candidate}} \cdot g_{432}^k \mid k = 0,1,\cdots,432\}
$$
and find all the elements $m \in M$ that give $m^e = c \mod n$. 


For completeness, we provide the full solution script for this challenge below:
```python
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
```

This challenge and solution was motivated and created based on https://eprint.iacr.org/2020/1059.pdf [Shumow, Daniel. "Incorrectly generated rsa keys: How to recover lost plaintexts." The Conference for Failed Approaches and Insightful Losses in Cryptology (CFail), 2020].