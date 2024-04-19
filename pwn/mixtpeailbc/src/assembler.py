import sys

op_map = {
    'nop': 0,
    'ld': 1,
    'st': 2,
    'pops': 3,
    'pregs': 4,
    'exit': 5,
    'li': 6,
    'li16': 7,
    'li32': 8,
    'li48': 9,
    'cmp': 10,
    'cmpi': 11,
    'jmp': 12,
    'jeq': 13,
    'jne': 14,
    'jgt': 15,
    'jlt': 16,
    'jge': 17,
    'jle': 18,
    'add': 19,
    'addi': 20,
    'sub': 21,
    'subi': 22,
    'mul': 23,
    'muli': 24,
    'div': 25,
    'divi': 26,
    'or': 27,
    'ori': 28,
    'and': 29,
    'andi': 30,
    'xor': 31,
    'xori': 32,
    'print': 33,
    'scan': 34,
    'ld8': 35,
    'st8': 36,
    'shl': 37,
    'shli': 38,
}

class Constant:
    def __init__(self, input, bits16 = False):
        self.bits16 = bits16
        self.is_label = False
        if len(input) >= 2 and input[0] == 'r' and input[1].isdigit():
            # this is a register
            self.value = int(input[1:])
        elif input.startswith('0x'):
            self.value = int(input[2:], 16)
        elif input[0].isdigit():
            self.value = int(input)
        else:
            self.is_label = True
            if input.startswith('abs:'):
                self.value = input[4:]
                self.abs_label = True
            else:
                self.value = input
                self.abs_label = False

    def label(self):
        if self.is_label:
            return self.value
        else:
            return None

    def mask(self):
        if self.bits16:
            return 0xffff
        else:
            return 0xff

    def num(self):
        if self.is_label:
            return None
        else:
            return self.value & self.mask()

    def resolved(self, labels, rel_addr):
        if self.is_label:
            num = labels[self.value]

            if not self.abs_label:
                num = num - rel_addr

            return num & self.mask()
        else:
            return self.num()

class Instr:
    @staticmethod
    def raw_data(data):
        out = Instr(None, None, None, None)
        out.raw_data = True
        out.data = data
        return out

    def __init__(self, opcode, a1, a2, a3):
        self.raw_data = False
        self.opcode = opcode
        self.a1 = a1
        self.a2 = a2
        self.a3 = a3

    def size(self):
        if self.raw_data:
            return len(self.data)
        else:
            return 4

    def append_to(self, out, labels, rel_addr):
        if self.raw_data:
            out.extend(self.data)
        else:
            out.append(self.opcode)
            out.append(self.a1.resolved(labels, rel_addr))

            if self.a2.bits16:
                n = self.a2.resolved(labels, rel_addr)
                out.append(n & 0xff)
                out.append((n >> 8) & 0xff)
            else:
                out.append(self.a2.resolved(labels, rel_addr))
                out.append(self.a3.resolved(labels, rel_addr))


def assemble(input):
    instrs = []
    label_offsets = {}
    offset = 0

    for line in input.split('\n'):
        line = line.split(';')[0]
        line = line.strip()
        if line == '':
            continue

        instr_parts = []
        for piece in line.split(' '):
            piece = piece.strip()
            if piece == '':
                continue
            instr_parts.append(piece)

        if len(instr_parts) == 1 and instr_parts[0][-1] == ':':
            label = instr_parts[0][:-1]
            label_offsets[label] = offset
        elif instr_parts[0][0] == '.':
            # assembler directive
            op = instr_parts[0]

            # this allows directive argument to have spaces
            space_index = line.find(' ')
            data = line[space_index:].strip()

            if op == '.string':
                assert data[0] == '"'
                assert data[-1] == '"'

                str_data = data[1:-1].replace('\\n', '\n').encode('utf-8')
                instrs.append(Instr.raw_data(str_data))
                offset += len(str_data)
            elif op == '.bytes':
                assert data[0] == '['
                assert data[-1] == ']'

                byte_data = bytearray()

                for number in data[1:-1].split(' '):
                    number = number.strip()
                    if number == '':
                        continue

                    if number.startswith('0x'):
                        byte_data.append(int(number[2:], 16))
                    else:
                        byte_data.append(int(number))

                instrs.append(Instr.raw_data(bytes(byte_data)))
                offset += len(byte_data)

        elif len(instr_parts) == 4:
            op = instr_parts[0]
            opcode = op_map[op]
            instrs.append(Instr(opcode, Constant(instr_parts[1]), Constant(instr_parts[2]), Constant(instr_parts[3])))
            offset += 4
        elif len(instr_parts) == 3:
            op = instr_parts[0]
            opcode = op_map[op]
            instrs.append(Instr(opcode, Constant(instr_parts[1]), Constant(instr_parts[2], True), None))
            offset += 4
        elif len(instr_parts) == 1:
            op = instr_parts[0]
            opcode = op_map[op]
            instrs.append(Instr(opcode, Constant('0'), Constant('0'), Constant('0')))
            offset += 4
        else:
            print(instr_parts)
            print('error: invalid item')
            return

    out = bytearray()
    offset = 0
    for instr in instrs:
        instr.append_to(out, label_offsets, offset)
        offset += instr.size()

    return bytes(out)

def main():
    input_file = sys.argv[2]
    output_file = sys.argv[1]

    with open(input_file, 'r') as f:
        input_data = f.read()

    output_data = assemble(input_data)

    with open(output_file, 'wb') as f:
        f.write(output_data)

if __name__ == '__main__':
    main()
