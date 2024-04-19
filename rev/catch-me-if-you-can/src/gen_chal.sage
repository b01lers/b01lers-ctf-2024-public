#!/usr/bin/sage
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

flag = b"bctf{we1rd_pyth0nc0d3_so1v3_w1th_f4s7_M47r1x_Mu1t}"

mod = 10**9 + 7
F = GF(mod)

transitionA = matrix(F, [
        [0, 1, 0],
        [0, 0, 1],
        [1, 1, 1]
        ]).T
transitionB = matrix(F,[
        [0, 1, 0],
        [0, 0, 1],
        [1, 1, 0]
        ]).T
transitionC = matrix(F,[
        [0, 1, 0],
        [0, 0, 1],
        [1, 0, 1]
        ]).T
transitionD = matrix(F,[
        [0, 1, 0],
        [0, 0, 1],
        [1, 0, 0]
        ]).T
def gen_remain(x):
    total_transition = matrix.identity(F, 3)
    for i in range(x):
        if i%5 == 0 and i%3 == 0:
                total_transition = total_transition * transitionD
        elif i%3 == 0:
            total_transition = total_transition * transitionA
        elif i%3 == 1:
            total_transition = total_transition * transitionB
        else:
            total_transition = total_transition * transitionC
    return total_transition



T = gen_remain(15)
initial = vector(F, [1, 2, 3])
order = T.multiplicative_order()
F2 = Zmod(order*15)

def slow(count):
    a, b, c = initial
    for i in range(count):
        if i%5 == 0 and i%3 == 0:
            a, b, c = b, c, (a)%mod
        elif i%3 == 0:
            a, b, c = b, c, (a+b+c)%mod
        elif i%3 == 1:
            a, b, c = b, c, (a+b)%mod
        elif i%3 == 2:
            a, b, c = b, c, (a+c)%mod
    return a

def fast(count):
    return (initial * (T**(int(count)//15)) * gen_remain(int(count)%15))[0]


def testing():
    for i in range(1, 5000, 20):
        print(i)
        assert(slow(i) == fast(i))

    for i in range(1, 5000, 20):
        print(i)
        assert(fast(2**i) == fast(F2(2)**i))

def match_output():
    print(list(map(fast, range(100))))

#testing()
match_output()
print(len(flag))
base = 3

result = []
for i in range(0, len(flag)//2):
    iter_count = F2(base ** (i))
    print(i, iter_count)
    key = int(fast(iter_count))

    encoded = (flag[i]) ^^ (key & 0xff)
    result.append(encoded)

print(iter_count)
for i in range(len(flag)//2, len(flag)):
    iter_count = iter_count ** base
    print(i)
    key = int(fast(iter_count))

    encoded = (flag[i]) ^^ (key & 0xff)
    result.append(encoded)

print(result)

    
# generate append statements
count = 0
c0 = 0
c1 = 16
c2 = 32
output = ""
while count < 50:
    r = random.randint(0, 2)
    if r == 0:
        if c0 < 16:
            output += f"AAAt0.append({result[c0]})\n"
            c0 += 1
            count += 1
    if r == 1:
        if c1 < 32:
            output += f"AAAt1.append({result[c1]})\n"
            c1 += 1
            count += 1
    if r == 2:
        if c2 < 50:
            output += f"AAAt2.append({result[c2]})\n"
            c2 += 1
            count += 1
    
print(output)
    




