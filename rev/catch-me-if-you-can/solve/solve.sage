import sys
import random

target = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]

mod = 1000000007
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

def not_fibonacci(count):
    return int((initial * (T**(int(count)//15)) * gen_remain(int(count)%15))[0])

base = 3

result = []
for i in range(0, 50):
    try:
        for j in range(25, 50):
            random.seed(j / (j-i))
        iter_count = base ** (i)
    except ZeroDivisionError:
        iter_count = F2(iter_count ** base)
    finally:
        key = not_fibonacci(iter_count)

        flag = (target[i]) ^^ (key & 0xff)
        print(chr(flag), end="")
        sys.stdout.flush()

