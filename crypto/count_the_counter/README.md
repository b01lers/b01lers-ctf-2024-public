# Writeup for count_the_counter by bronson113

[Blog Post](https://blog.bronson113.org/2024/04/15/b01lersctf-2024-author-writeup.html#count-the-counter)

```plaintext
000 001 010 011 100...


`nc gold.b01le.rs 5002`
Solves: 26 solves / 466 points
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


In this challenge, our flag is encrypted using a nonce. We can then supply our own message to be encrypted, but each time the nonce are incremented. Normally this wouldn't pose an issue, as you would assume that with different nonce, CTR mode will produce different results. To verify this, we'll need to looking into how the nonce are used to create our counter.


In [pycryptodome](https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/_mode_ctr.py#L349), the full counter is created as nonce concatted with a counter.
Namely, the counter is in the form `|<nonce>|<counter>|`.
However, the length of each section isn't defined. Instead, the nonce is first taken, then the length of the counter is set to make the whole counter length to be 16 bytes.


Now notice that if the nonce ends in a null byte, it'll act the same if we truncated out the null byte from the end. Therefore, if we wait until the challenge give us 256 as the nonce, the nonce will be represented and '\x01\x00', which will be the same as the initial '\x01' nonce.


The rest is trivial if you know how CTR mode works. Since the key stream of the two cipher are the smae. We can xor the results from two encryption to remove the stream key and get back our result.


`bctf{there_is_a_reason_for_random_nonce_and_with_fixed_length_8c6bf5a1398d1f1d95f1}`


```python
from pwn import remote, xor


p = remote("gold.b01le.rs", 5002)
# trick or treat
p.recvline()


# Initial Cipher
enc = p.recvline().strip()
enc_bytes = bytes.fromhex(enc.decode())
print(f"Encrypted: {enc_bytes}")


# Wait until nonce wrap around
skip = 254
for i in range(skip):
    p.sendline(b"00")
for i in range(skip+1):
    p.recvuntil(b"Give me")


# Send message will all null bytes
p.sendline(b"0"*len(enc))
null_encrypt = p.recvline().split(b": ")[-1]
null_encrypt_bytes = bytes.fromhex(null_encrypt.decode())
print(f"Encrypt Null: {null_encrypt_bytes}")


# xor out the ctr cipher stream
print("Flag: ", xor(enc_bytes, null_encrypt_bytes))
```



