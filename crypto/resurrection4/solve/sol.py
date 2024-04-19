import pwn
import binascii

nc_ed = pwn.remote('gold.b01le.rs', '5004')

nc_ed.recvuntil("(Just hit enter if you do not want to add any padding(s).)")
padding = ' ' * 1000000
nc_ed.sendline(padding)
nc_ed.recvline() ## Empty line
ciphertext = nc_ed.recvline() ## b'...\n'
ciphertext = str(ciphertext)[2:-3] ## Remove " b' " and " \n' "
unhexed_ct = binascii.unhexlify(ciphertext)
# print(unhexed_ct) ## This is also correct but it's too long
## Since flag won't be that long anyway, let's just print the last 50 chars.
print(unhexed_ct[len(unhexed_ct) - 50:len(unhexed_ct)])
## bctf{1f_gOOgL3_541D_1T_15_b4D_Th3n_1T_15_b4D}