# ctr - cbc - ctr
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
    p = remote("127.0.0.1", "5003")
#    p = process(["python3", "./src/chal.py"])
    p.recvuntil(b"valid certificate: ")
    cipher_text = bytes.fromhex(p.recvline().decode())
    iv, ct = cipher_text[:16], cipher_text[16:]
    flag = b"".join((oracle_block(p, iv, ct[:i*16]) for i in range(1, len(ct)//16+1)))
    print(flag)


if __name__ == "__main__":
    main()





