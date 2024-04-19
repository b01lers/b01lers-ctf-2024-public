import random
names = ('seed', 'iter_count', 'result', 't0', 't1', 't2', 
        'target', 'i', 'base', 'j', 'a', 'b', 'c', 'mod', 
        'flag')

eye = "OoUu0Qq"
mouth = "wvu3UVW"
face = [i+j+i for i in eye for j in mouth]
exists = set()
def gen_random_var_name():
    x = "OwO_" + "_".join(random.choices(face, k=9))
    while x in exists:
        x = "OwO_" + "_".join(random.choices(face, k=9))
    exists.add(x)
    return x

src = open("chal.py", "r").read()
for name in names:
    src = src.replace(f"AAA{name}", gen_random_var_name())

print(src)

open("chal_obfuscated.py", "w").write(src)
