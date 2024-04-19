from pwn import remote, xor

p = remote("127.0.0.1", 5002)
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
