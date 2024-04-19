import sys

target = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]

def not_fibonacci(n):
    a, b, c = 1, 2, 3
    mod = 1000000007
    for i in range(n):
        match (i%3, i%5):
            case (0, 0):
                a, b, c = b, c, (a)%mod
            case (0, _):
                a, b, c = b, c, (a+b+c)%mod
            case (1, _):
                a, b, c = b, c, (a+b)%mod
            case (2, _):
                a, b, c = b, c, (a+c)%mod
    return a

print(list(map(not_fibonacci, range(100))))
base = 3

result = []
for i in range(0, 25):
    iter_count = base ** (i)
    key = not_fibonacci(iter_count)

    flag = (target[i]) ^ (key & 0xff)
    print(chr(flag), end="")
    sys.stdout.flush()

iter_count = base ** 24
for i in range(25, 50):
    iter_count = iter_count ** base
    key = not_fibonacci(iter_count)

    flag = (target[i]) ^ (key & 0xff)
    print(chr(flag), end="")
    sys.stdout.flush()


