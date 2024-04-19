from pwn import *
import time

flag = 'bctf{gl4d_u_g0t_th3s3_0ps_4ll_s0rt3d_0ut_db7db686d63697ca79faf6}'

def guess(index):
    test = ''
    for i in range(len(flag)):
        if i == index:
            test += 'z'
        else:
            test += flag[i]

    r = process(["./mixtape", "flag_checker.bytecode"])
    r.send(test)
    print(r.recvline())

    time.sleep(0.1)
    r.close()

for i in range(len(flag)):
    guess(i)
