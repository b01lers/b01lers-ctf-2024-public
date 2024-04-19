mods = [35831, 143, 1061, 877, 29463179, 229, 112, 337, 1061, 47, 29599, 145, 127, 271639, 127, 353, 193, 191, 337, 1061, 193, 353, 269, 487, 245]

def fib(n, computed = {0: 0, 1: 1}):
     if n not in computed:
         computed[n] = fib(n-1, computed) + fib(n-2, computed)
     return computed[n]

base = fib(90)
rebuilt = ""

for i in mods:
    rebuilt += chr(base % i)

print(rebuilt)
