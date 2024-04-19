# Writeup for Counter Block Chaining by bronson113

[Blog Post](https://blog.bronson113.org/2024/04/15/b01lersctf-2024-author-writeup.html#propagating-counter-block-chaining)


```plaintext
Another counter mode challenge


`nc gold.b01le.rs 5003`
Solves: 11 solves / 487 points
```




```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from functools import reduce
from secret import flag
import os
import json


BLOCK_SIZE = 16
key_ctr1 = os.urandom(BLOCK_SIZE)
key_ctr2 = os.urandom(BLOCK_SIZE)
key_cbc = os.urandom(BLOCK_SIZE)
nonce1 = os.urandom(8)
nonce2 = os.urandom(8)


def AES_ECB_enc(key, message):
    enc = AES.new(key, AES.MODE_ECB)
    return enc.encrypt(message)


def AES_ECB_dec(key, message):
    enc = AES.new(key, AES.MODE_ECB)
    return enc.decrypt(message)


# Returning a block each time
def get_blocks(message):
    for i in range(0, len(message), BLOCK_SIZE):
        yield message[i:i+BLOCK_SIZE]
    return


# Takes any number of arguements, and return the xor result.
# Similar to pwntools' xor, but trucated to minimum length
def xor(*args):
    _xor = lambda x1, x2: x1^x2
    return bytes(map(lambda x: reduce(_xor, x, 0), zip(*args)))




def counter(nonce):
    count = 0
    while count < 2**(16 - len(nonce)):
        yield nonce + str(count).encode().rjust(16-len(nonce), b"\x00")
        count+=1
    return




def encrypt(message):
    cipher = b""
    iv = os.urandom(BLOCK_SIZE)
    prev_block = iv
    counter1 = counter(nonce1)
    counter2 = counter(nonce2)
    for block in get_blocks(pad(message, BLOCK_SIZE)):
        enc1 = AES_ECB_enc(key_ctr1, next(counter1))
        enc2 = AES_ECB_enc(key_cbc, xor(block, prev_block, enc1))
        enc3 = AES_ECB_enc(key_ctr2, next(counter2))
        enc4 = xor(enc3, enc2)
        prev_block = xor(block, enc4)
        cipher += enc4


    return iv + cipher


def decrypt(cipher):
    message = b""
    iv = cipher[:16]
    cipher_text = cipher[16:]


    prev_block = iv
    counter1 = counter(nonce1)
    counter2 = counter(nonce2)
    for block in get_blocks(cipher_text):
        dec1 = AES_ECB_enc(key_ctr2, next(counter2))
        dec2 = AES_ECB_dec(key_cbc, xor(block, dec1))
        dec3 = AES_ECB_enc(key_ctr1, next(counter1))
        message += xor(prev_block, dec2, dec3)
        prev_block = xor(prev_block, dec2, block, dec3)


    return unpad(message, BLOCK_SIZE)


def main():
    certificate = os.urandom(8) + flag + os.urandom(8)
    print(f"""
*********************************************************


Certificate as a Service


*********************************************************


Here is a valid certificate: {encrypt(certificate).hex()}


*********************************************************""")
    while True:
        try:
            cert = bytes.fromhex(input("Give me a certificate >> "))
            if len(cert) < 32:
                print("Your certificate is not long enough")


            message = decrypt(cert)
            if flag in message:
                print("This certificate is valid")
            else:
                print("This certificate is not valid")
        except Exception:
            print("Something went wrong")


if __name__ == "__main__":
    main()
```



We can first inspect the encrypt function. We see that two different sets of counter are used, and some sort of block chaining are used. The output of the counter are used to xor both the input and the output of the block cipher. Additionally, the results from the previous block are xored into the input of the next block. In essence, it's a chaining CTR-PCBC-CTR mode.


Other than the encrypt function, this challenge is quite a barebone example of padding oracle. and So the main difficulty will be in figuring out how to apply the attack on the new CTR-PCBC-CTR mode.


Let's first ignore the CTR modes as we should be able to adjust for them later. How do PCBC mode padding oracle works? If we look at the figure, you'll notice that controlling IV allows us to control the output of each block, since the result will snake through each plaintext and influence the next block accordingly. This can be used to directly influence the padding, and proceed with the normal padding oracle attack.


![](https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PCBC_encryption.svg/1920px-PCBC_encryption.svg.png)
![](https://upload.wikimedia.org/wikipedia/commons/thumb/5/5b/PCBC_decryption.svg/1920px-PCBC_decryption.svg.png)
(Image quoted from [wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)))


Now we need to worry about the counters. We can recall that CTR acted like a stream cipher, meaning that characters at the correct place will be decrypted correctly. Naturally, if we keep the ciphertext where they should be at, the decryption process will help us decoding the correct plaintext, and we don't need to worry about them. Since controlling the IV allows us to control every block of the output, we can choose which block we want the padding to be at, and resolve this issue. See the solve script for more detail.


`bctf{adding_ctr_mode_doesn't_provide_any_security_to_padding_oracle..._c850d60d210169}`


```python
# ctr - pcbc - ctr
# but the chaining is done from ctr output
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import *
import os




BLOCK_SIZE = 16


def oracle(p, ct):
    p.sendline(ct.hex())


def oracle_res(p, count):
    result = []
    for i in range(count):
        p.recvuntil(b">> ")
        res = p.recvline()
        if b"Something went wrong" in res:
            result.append(False)
        else:
            result.append(True)
    return result


def oracle_block(p, iv, ct):
    guess = []
    for l in range(1, 17):
        for c in range(256):
#            print(bytes(guess+[c])[::-1])
            new_iv = xor(bytes([c]+guess[::-1]).rjust(16,b"\x00"), bytes([l]*16), iv)
            oracle(p, new_iv+ct)


        res = oracle_res(p, 256)


        for c in range(256):
            if res[c]:
                guess.append(c)
                break
        print(bytes(guess[::-1]))
    return bytes(guess[::-1])


def main():
#    p = remote("127.0.0.1", "5003")
    p = remote("gold.b01le.rs", "5003")
#    p = process(["python3", "./src/chal.py"])
    p.recvuntil(b"valid certificate: ")
    cipher_text = bytes.fromhex(p.recvline().decode())
    iv, ct = cipher_text[:16], cipher_text[16:]
    flag = b"".join((oracle_block(p, iv, ct[:i*16]) for i in range(1, len(ct)//16+1)))
    print(flag)




if __name__ == "__main__":
    main()
```



