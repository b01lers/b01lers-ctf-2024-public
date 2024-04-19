; li r1 0x1000 ; address of op permute data

; li r2 0

; .perm_setup:

; add r3 r1 r2 ; address to write to
; st8 r2 r3 0 ; *r3 = r2

; addi r2 r2 1
; cmpi r3 r2 37
; jlt r3 .perm_setup

li r1 abs:pops_data

li r2 abs:enter_flag_str
print 28 r2 0

li r2 0x2000 ; address of input data
scan 64 r2 0 ; scan from stdin into address of r2

; we check the flag in sections of 8
; flag is 64 bytes
; first for sections are comparing arithmatic and bitwise operations
; with a result, but permuting operation each time

; important regs:
; r1: permute data
; r2: user input


; only for first part

; r5: round number for first part check
; r6: pointer to current input char
; r20: data pointer for check data
; r21: data pointer for rhs data

li r20 abs:check_data
li r21 abs:rhs_data

li r5 0 ; counter for first part loop, will incrament to 4 for each section
addi r6 r2 0 ; pointer to current input char

.first_part_loop:

; checks

ld8 r7 r6 0 ; input char
ld8 r8 r21 0 ; rhs char
ld8 r9 r20 0 ; check char

add r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect


ld8 r7 r6 1 ; input char
ld8 r9 r20 1 ; check char

subi r10 r7 29
cmp r10 r10 r9
jne r10 .incorrect


ld8 r7 r6 2 ; input char
ld8 r8 r21 2 ; rhs char
ld8 r9 r20 2 ; check char

mul r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect

ld8 r7 r6 3 ; input char
ld8 r8 r21 3 ; rhs char
ld8 r9 r20 3 ; check char

xor r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect


ld8 r7 r6 4 ; input char
ld8 r8 r21 4 ; rhs char
ld8 r9 r20 4 ; check char

shl r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect


ld8 r7 r6 5 ; input char
ld8 r8 r21 5 ; rhs char
ld8 r9 r20 5 ; check char

xor r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect

ld8 r7 r6 6 ; input char
ld8 r8 r21 6 ; rhs char
ld8 r9 r20 6 ; check char

sub r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect

ld8 r7 r6 7 ; input char
ld8 r9 r20 7 ; check char

muli r10 r7 2
cmp r10 r10 r9
jne r10 .incorrect


; update pointers for char we are scanning
addi r6 r6 8
addi r20 r20 8
addi r21 r21 8

; permute ops
pops 0 r1 0

addi r5 r5 1
cmpi r10 r5 4
jlt r10 .first_part_loop


; second check for blocks 4 - 8
; uses pregs instrustion to shuffle bytes of flag

; registers
; r3: pointer to current round permute data
; r4: pointer to current round check data
; r5: current round counter
; r6: pointer to current char

li r3 abs:reg_permute_data1
li r4 abs:pregs_check_data1
li r5 0

.second_part_loop:

; load flag data
ld8 r20 r6 0
ld8 r21 r6 1
ld8 r22 r6 2
ld8 r23 r6 3
ld8 r24 r6 4
ld8 r25 r6 5
ld8 r26 r6 6
ld8 r27 r6 7

; permute flag data
pregs 28 r3 0

; load check data
ld8 r10 r4 0
ld8 r11 r4 1
ld8 r12 r4 2
ld8 r13 r4 3
ld8 r14 r4 4
ld8 r15 r4 5
ld8 r16 r4 6
ld8 r17 r4 7

; check if flag bytes match check data
cmp r9 r10 r20
jne r9 .incorrect
cmp r9 r11 r21
jne r9 .incorrect
cmp r9 r12 r22
jne r9 .incorrect
cmp r9 r13 r23
jne r9 .incorrect
cmp r9 r14 r24
jne r9 .incorrect
cmp r9 r15 r25
jne r9 .incorrect
cmp r9 r16 r26
jne r9 .incorrect
cmp r9 r17 r27
jne r9 .incorrect


; update pointers for char we are scanning
addi r6 r6 8
addi r3 r3 28 ; permute data is 28 bytes big
addi r4 r4 8


addi r5 r5 1
cmpi r10 r5 4
jlt r10 .second_part_loop


; print out correct
li r1 abs:correct_str
print 8 r1 0
exit

.incorrect:

li r1 abs:incorrect_str
print 10 r1 0
exit

; ops:
; round1: add, subi 29, mul, xor, shl, xor, sub, muli 2
; round2: xor, xori 29, shl, sub, mul, sub, add, muli 2
; round3: sub, subi 29, mul, add, shl, add, xor, muli 2
; round4: add, xori 29, shl, xor, mul, xor, sub, muli 2
check_data:
.bytes [129 70 232 29 246 61 59 104 138 66 117 84 206 1 217 190 80 75 51 163 204 253 168 224 124 66 104 166 216 69 5 96]
rhs_data:
.bytes [31 12 2 123 1 90 49 88]
.bytes [238 42 0 11 2 47 101 9]
.bytes [36 0 1 48 2 158 152 88]
.bytes [9 0 1 202 2 26 110 83]
pops_data:
; loops:
; subi -> xori
; add -> xor -> sub
; mul -> shl
; muli
.bytes [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 31 20 19 32 37 24 25 26 27 28 29 30 21 22 33 34 35 36 23 38]

reg_permute_data1:
.bytes [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 25 21 27 26 24 20 22 23]
reg_permute_data2:
.bytes [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 24 21 22 25 20 23 27 26]
reg_permute_data3:
.bytes [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 23 25 22 24 20 27 21 26]
reg_permute_data4:
.bytes [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 25 21 24 20 26 27 22 23]

pregs_check_data1:
.string "0ttu_r3d"
pregs_check_data2:
.string "ddbb_786"
pregs_check_data3:
.string "39666cd7"
pregs_check_data4:
.string "f7aa6}9f"

correct_str:
.string "Correct\n"

incorrect_str:
.string "Incorrect\n"

enter_flag_str:
.string "Enter flag (64 characters): "
