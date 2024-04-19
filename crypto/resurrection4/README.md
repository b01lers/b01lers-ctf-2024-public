# Writeup for R(esurre)C(tion)4 by FlaggnGoose

## Add your writeup here!

This is a well-known bad implementation of RC4. Notice that the server is exchanging two values of <code>S</code>, namely <code>S[i]</code> and <code>S[j]</code>, via XOR operations:

```python
## swap values of S[i] and S[j]
S[i] ^= S[j] 
S[j] ^= S[i]
S[i] ^= S[j]
```
While this method may look 'cool' to you, this could induce errors after a large number of iterations/repetitions. To be specific, when <code>i=j</code> (or <code>i != j</code> but <code>S[i]=S[j]</code>), we would have <code>S[i] = S[j]</code>, hence making both <code>S[i] = S[j] = 0</code> as XOR of two same numbers is always 0. This eventually accumulates and transforms <code>S</code> into a sequence of zeroes after a certain number of steps, and hence the ciphertext will reveal information about the plaintext. In particular, some last bytes of the ciphertext will be (almost) identical to the some last bytes of the plaintext after a certain point, and if the plaintext is long enough, then the last few bytes of the ciphertext will simply be (almost) identical to the plaintext.

```python
import pwn
import binascii

nc_ed = pwn.remote('localhost', '5041')

nc_ed.recvuntil("(Just hit enter if you do not want to add any padding(s).)")
padding = ' ' * 1000000
nc_ed.sendline(padding)
nc_ed.recvline() ## Empty line
ciphertext = nc_ed.recvline() ## b'...\n'
ciphertext = str(ciphertext)[2:-3] ## Remove " b' " and " \n' "
unhexed_ct = binascii.unhexlify(ciphertext)
# print(unhexed_ct) ## This is also correct but it's too long
## Since flag won't be that long anyway, let's just print the last 50 chars.
print(unhexed_ct[len(unhexed_ct) - 50:len(unhexed_ct)])
## bctf{1f_gOOgL3_541D_1T_15_b4D_Th3n_1T_15_b4D}
```