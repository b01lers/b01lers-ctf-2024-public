# Writeup for mixtpeailbc by Athryx

The bytecode vm has permute regs out of bounds read to read libc return address off of stack.
The permute ops instruction can have an out of bounds access where a pointer is fetched from a register,
this means you can leak libc address, and put system as an op pointer, and return to system.
