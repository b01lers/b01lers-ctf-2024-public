# Writeup for seeing-red by CaptainNapkins

Buffer overflow, return to use_ticket to read flag into global buffer
That buffer is still on the stack, so continue flow back to main and 
then there is a printf vuln. Use the printf vuln to leak the contents of the 
flag buffer that were previously stored on the stack

Full Writeup: https://gabri3l.net/b01lers-ctf-2024/#seeing-red--pwn
