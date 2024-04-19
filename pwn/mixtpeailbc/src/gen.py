import random

def subi(f, rhs):
    return f - 29

def xori(f, rhs):
    return f ^ 29

def muli(f, rhs):
    return f * 2


def add(f, rhs):
    return f + rhs

def sub(f, rhs):
    return f - rhs

def xor(f, rhs):
    return f ^ rhs

def mul(f, rhs):
    return f * rhs

def shl(f, rhs):
    return f << rhs

flag = 'bctf{gl4d_u_g0t_th3s3_0ps_4ll_s0rt3d_0ut_db7db686d63697ca79faf6}'

# round1: add, subi 29, mul, xor, shl, xor, sub, muli 2
# round2: xor, xori 29, shl, sub, mul, sub, add, muli 2
# round3: sub, subi 29, mul, add, shl, add, xor, muli 2
# round4: add, xori 29, shl, xor, mul, xor, sub, muli 2

ops = [
    add, subi, mul, xor, shl, xor, sub, muli,
    xor, xori, shl, sub, mul, sub, add, muli,
    sub, subi, mul, add, shl, add, xor, muli,
    add, xori, shl, xor, mul, xor, sub, muli,
]

rhs_data = [
    31, 12, 2, 123, 1, 90, 49, 88,
    238, 42, 0, 11, 2, 47, 101, 9,
    36, 0, 1, 48, 2, 158, 152, 88,
    9, 0, 1, 202, 2, 26, 110, 83,
]

print('[', end='')

for i in range(32):
    op = ops[i]
    f = ord(flag[i])
    rhs = rhs_data[i]

    # print()
    # print(i)
    # print(op)
    # print(f)
    # print(rhs)

    result = op(f, rhs)
    assert result >= 0
    assert result < 256

    print(f'{result} ', end='')

print(']')
