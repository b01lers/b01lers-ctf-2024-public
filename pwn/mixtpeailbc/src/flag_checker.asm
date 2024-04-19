; unscramble the check data
li r1 abs:scramble_key
li r2 0
li r3 abs:scramble_pops

.unscramble_loop:

ld8 r4 r1 0
ld8 r5 r1 1
ld8 r6 r1 2
ld8 r7 r1 3


add r4 r4 r5
xor r7 r7 r6

pops 0 r3 0

xor r6 r6 r5
add r5 r5 r6

pops 0 r3 0

add r4 r7 r4
xor r7 r4 r4

pops 0 r3 0


st8 r4 r1 0
st8 r5 r1 1
st8 r6 r1 2
st8 r7 r1 3


addi r1 r1 4
addi r2 r2 4
cmpi r128 r2 64
jlt r128 .unscramble_loop

li r1 abs:scramble_key
li r2 abs:scrambled_data
li r3 0

; use the unscrambled key to decrypt 1 time padded data
.xor_unscramble:

ld8 r4 r1 0
ld8 r5 r2 0
xor r4 r4 r5
st8 r4 r2 0

addi r1 r1 1
addi r2 r2 1
addi r3 r3 1
cmpi r128 r3 64
jlt r128 .xor_unscramble



; li r1 0x1000 ; address of op permute data

; li r2 0

; .perm_setup:

; add r3 r1 r2 ; address to write to
; st8 r2 r3 0 ; *r3 = r2

; addi r2 r2 1
; cmpi r3 r2 37
; jlt r3 .perm_setup

; this register indicates if the flag is correct
; 1 if correct 0 if not
; will be anded with 0 after incorrect step 1 after correct
; this is for constant time checks so pintools can't solve
li r255 1

; this register is 0, just for oncunditional jumps
li r254 1

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
jne r10 .incorrect_c1
andi r255 r255 1
jeq r254 .end_c1
.incorrect_c1:
andi r255 r255 0
jeq r254 .end_c1
.end_c1:

ld8 r7 r6 1 ; input char
ld8 r9 r20 1 ; check char

subi r10 r7 29
cmp r10 r10 r9
jne r10 .incorrect_c2
andi r255 r255 1
jeq r254 .end_c2
.incorrect_c2:
andi r255 r255 0
jeq r254 .end_c2
.end_c2:


ld8 r7 r6 2 ; input char
ld8 r8 r21 2 ; rhs char
ld8 r9 r20 2 ; check char

mul r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect_c3
andi r255 r255 1
jeq r254 .end_c3
.incorrect_c3:
andi r255 r255 0
jeq r254 .end_c3
.end_c3:

ld8 r7 r6 3 ; input char
ld8 r8 r21 3 ; rhs char
ld8 r9 r20 3 ; check char

xor r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect_c4
andi r255 r255 1
jeq r254 .end_c4
.incorrect_c4:
andi r255 r255 0
jeq r254 .end_c4
.end_c4:


ld8 r7 r6 4 ; input char
ld8 r8 r21 4 ; rhs char
ld8 r9 r20 4 ; check char

shl r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect_c5
andi r255 r255 1
jeq r254 .end_c5
.incorrect_c5:
andi r255 r255 0
jeq r254 .end_c5
.end_c5:


ld8 r7 r6 5 ; input char
ld8 r8 r21 5 ; rhs char
ld8 r9 r20 5 ; check char

xor r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect_c6
andi r255 r255 1
jeq r254 .end_c6
.incorrect_c6:
andi r255 r255 0
jeq r254 .end_c6
.end_c6:

ld8 r7 r6 6 ; input char
ld8 r8 r21 6 ; rhs char
ld8 r9 r20 6 ; check char

sub r10 r7 r8
cmp r10 r10 r9
jne r10 .incorrect_c7
andi r255 r255 1
jeq r254 .end_c7
.incorrect_c7:
andi r255 r255 0
jeq r254 .end_c7
.end_c7:

ld8 r7 r6 7 ; input char
ld8 r9 r20 7 ; check char

muli r10 r7 2
cmp r10 r10 r9
jne r10 .incorrect_c8
andi r255 r255 1
jeq r254 .end_c8
.incorrect_c8:
andi r255 r255 0
jeq r254 .end_c8
.end_c8:


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
jne r9 .incorrect_c9
andi r255 r255 1
jeq r254 .end_c9
.incorrect_c9:
andi r255 r255 0
jeq r254 .end_c9
.end_c9:

cmp r9 r11 r21
jne r9 .incorrect_c10
andi r255 r255 1
jeq r254 .end_c10
.incorrect_c10:
andi r255 r255 0
jeq r254 .end_c10
.end_c10:

cmp r9 r12 r22
jne r9 .incorrect_c11
andi r255 r255 1
jeq r254 .end_c11
.incorrect_c11:
andi r255 r255 0
jeq r254 .end_c11
.end_c11:

cmp r9 r13 r23
jne r9 .incorrect_c12
andi r255 r255 1
jeq r254 .end_c12
.incorrect_c12:
andi r255 r255 0
jeq r254 .end_c12
.end_c12:

cmp r9 r14 r24
jne r9 .incorrect_c13
andi r255 r255 1
jeq r254 .end_c13
.incorrect_c13:
andi r255 r255 0
jeq r254 .end_c13
.end_c13:

cmp r9 r15 r25
jne r9 .incorrect_c14
andi r255 r255 1
jeq r254 .end_c14
.incorrect_c14:
andi r255 r255 0
jeq r254 .end_c14
.end_c14:

cmp r9 r16 r26
jne r9 .incorrect_c15
andi r255 r255 1
jeq r254 .end_c15
.incorrect_c15:
andi r255 r255 0
jeq r254 .end_c15
.end_c15:

cmp r9 r17 r27
jne r9 .incorrect_c16
andi r255 r255 1
jeq r254 .end_c16
.incorrect_c16:
andi r255 r255 0
jeq r254 .end_c16
.end_c16:


; update pointers for char we are scanning
addi r6 r6 8
addi r3 r3 28 ; permute data is 28 bytes big
addi r4 r4 8


addi r5 r5 1
cmpi r10 r5 4
jlt r10 .second_part_loop

; check if r255 is 1, which means flag is correct
cmpi r1 r255 1
jne r1 .incorrect

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
scrambled_data:
check_data:
; .bytes [129 70 232 29 246 61 59 104 138 66 117 84 206 1 217 190 80 75 51 163 204 253 168 224 124 66 104 166 216 69 5 96]
.bytes [171 42 41 73 103 134 217 74 109 187 167 154 49 158 210 64 0 20 112 3 234 2 172 172 163 246 31 24 221 215 212 106]
pregs_check_data1:
; .string "0ttu_r3d"
.bytes [68 35 40 157 133 10 135 208]
pregs_check_data2:
; .string "ddbb_786"
.bytes [212 46 241 2 33 125 32 202]
pregs_check_data3:
; .string "39666cd7"
.bytes [79 66 188 206 128 27 14 91]
pregs_check_data4:
; .string "f7aa6}9f"
.bytes [54 133 156 193 151 133 3 36]

; rhs arguments for the operations in the first 4 blocks of checking
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

scramble_key:
.bytes [137 173 110 14 42 89 59 47 244 43 253 251 166 148 159 166 231 28 95 12 12 251 255 210 220 195 58 68 20 67 20 72 231 11 103 1 166 204 128 204 220 217 108 9 73 82 106 115 21 241 123 249 33 18 124 149 68 79 76 175 148 194 252 11]
; turns into this key: b'*l\xc1T\x91\xbb\xe2"\xe7\xf9\xd2\xce\xff\x9f\x0b\xfeP_C\xa0&\xff\x04L\xdf\xb4w\xbe\x05\x92\xd1\ntW\\\xe8\xdax\xb4\xb4\xb0J\x93`~J\x18\xfc|{\x8a\xf8\xb6xjlP\xb2\xfd\xa0\xa1\xf8:B'

scramble_pops:
.bytes [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 31 20 19 22 23 24 25 26 27 28 29 30 21 32 33 34 35 36 37 38]

correct_str:
.string "Correct\n"

incorrect_str:
.string "Incorrect\n"

enter_flag_str:
.string "Enter flag (64 characters): "
