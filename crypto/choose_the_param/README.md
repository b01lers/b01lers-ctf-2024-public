# Writeup for choose_the_param by bronson113

[Blog Post](https://blog.bronson113.org/2024/04/15/b01lersctf-2024-author-writeup.html#choose-the-param)


```plaintext
I wounder why we need to specify parameter length in the spec...


`nc gold.b01le.rs 5001`
Solves: 46 solves / 432 points
```


```python
#!/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from secret import flag
import os




def Encrypt(key, message, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=long_to_bytes(nonce))
    return cipher.encrypt(message).hex()




def chal():
    key = os.urandom(16)
    print("Treat or Trick, count my thing. ")
    nonce_counter = 1
    print(Encrypt(key, flag, nonce_counter))
    while True:
        nonce_counter += 1
        to_enc = input("Give me something to encrypt: ")
        print(Encrypt(key, bytes.fromhex(to_enc), nonce_counter))




if __name__ == "__main__":
    chal()
```


This challenge is quite straight forward. We are given a service that will encrypt the flag using a primes of the length of our choice. It's clear that with a small prime, we can easily factor N, and recover m. However, since the flag is padded on both end, we won't gain any useful information if our prime is too small, or do we.


If we check what we actually retrieved from the RSA decryption, we get $ m = c^{d} \mod{n} $. This means like we get $m \mod{n}$ for each query. If we have multiple pairs of these m, we can recover the full m using Chinese Remainder Theorem.


`bctf{dont_let_the_user_choose_the_prime_length_>w<}`


```python
from Crypto.Util.number import long_to_bytes
from sage.all import Integer, CRT
from pwn import *


p = remote("gold.b01le.rs", 5001)


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
```



