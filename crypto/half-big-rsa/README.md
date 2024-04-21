
---
header-includes:
   - \usepackage{amsmath}
output:
  pdf_document:
    keep_tex: true
---

<script type="text/javascript" async src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.3/MathJax.js?config=TeX-MML-AM_CHTML">
    MathJax.Hub.Config({
        tex2jax: {
            inlineMath: [["$", "$"], ["\\(", "\\)"]],
            processEscapes: true
        }
    });
</script>

# Writeup for half-big-rsa by FlaggnGoose

## Add your writeup here!

To begin with, we are given the equation $c = m^e \mod n$ where $n$ is a 4096-bit prime number. Normally, we'd be able to compute $d := e^{-1} \mod n-1$ and find $m$ by computing $c^d \mod n$, but unfortunately $e^{-1} \mod n-1$ does not exist as $g := \gcd(e, n-1) = 18 \neq 1$.

Fortunately, we have $\gcd(e/g, n-1) = 1$, so $d_1 := (e/g)^{-1} \mod n-1$ exists. That is, there exists $k \in \mathbb{Z}$ such that

$$
\frac{e}{g} d_1 = (n-1) k + 1 \implies e d_1 = (n-1)gk + g
$$

and hence, $c^{d_1} = m^{e d_1} = m^g = m^{18} \mod n$. Denote $m_1 := m^{g} \mod n$. It is clear that $m_1^{e/g} = c \mod n$.

```python
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
```

We are left with taking 18-th roots of $m_1$ in $\mathbb{F}_n$. We could use <code>nth_root</code> function in sagemath, but given that $n$ is a 4096-bit prime, it'd take forever. Let's use some trick. Factordb says:

$$
n-1 = 2^4 \times 3^3 \times 202021 \times 7625664192\dots 09
$$

Since $g = 18 = 2 \times 3^2$, we have $\gcd(g, (n-1)/g) = 6$, but

$$
\gcd\left(24 g, \frac{n-1}{24 g} \right) = 1
$$

because $24g = 2^4 \times 3^3$. So, we can raise $m_1$ to the power of $24$,

$$
m_2 := (m_1)^{24} = m^{24g} \mod n
$$

and compute the inverse of $24g$ -- there exists $k' \in \mathbb{Z}$ such that

$$
\begin{align*}
d_2 := (24g)^{-1} \mod \frac{n-1}{24 g} 
& \implies 24 g d_2 = 1 + \frac{n-1}{24 g} k' \\
& \implies 24 g \cdot (24 g\; d_2) = 24g + (n-1)k'
\end{align*}
$$

Hence,

$$
\begin{align*}
(m_2)^{24g d_2} = m^{24g \cdot (24g d_2)} = m^{24g} \mod n
\end{align*}
$$

```python
assert math.gcd(24 * g, (n-1)//(24 * g)) == 1 # True
m2 = pow(m1, 24, n)
d2 = pow(24 * g, -1, (n-1)//(24 * g))
m_candidate = pow(m2, d2, n)
assert pow(m_candidate, 24 * g, n) == m2 # True
```

and therefore, $m$ would be one of the $24g$-th roots of $(m_2)^{24g d_2}$ in $\mathbb{F}_n$. That is, let $\rho$ be a $24g$-th root of unity in $\mathbb{F}_n$, then $m = (m_2)^{d_2} \rho^i \text{ mod } n$ for some integer $i$.

This can be done by finding a generator of a subgroup $E$ of order $24g = 432$ in $\mathbb{F}_n^\times$. Note that $E$ is cyclic since $n$ is prime. This can be done brute forcefully but in most cases (and apparently and fortunately, for this case as well) it should finish very quickly.

```python
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
```

We are then left with computing the said $(m_2)^{d_2} \rho^i \mod n$ for $i = 0,1,\dots, 24g-1$.

```python
for i in range(0, 24 * g):
    m = (m_candidate * pow(gen_E, i, n)) % n
    if pow(m, e, n) == c and b'bctf{' in long_to_bytes(m):
        print(long_to_bytes(m))
        ## b'bctf{Pr1M3_NUM83r5_4r3_C001_bu7_7H3Y_4r3_57r0N6_0N1Y_WH3N_
        ##        7H3Y_4r3_MU171P113D_3V3N_1F_7H3Y_4r3_b1g}'
{% endhighlight %}
```
<b>Flag: <code>bctf{Pr1M3_NUM83r5_4r3_C001_bu7_7H3Y_4r3_57r0N6_0N1Y_WH3N_7H3Y_4r3_MU171P113D_3V3N_1F_7H3Y_4r3_b1g}</code></b>
