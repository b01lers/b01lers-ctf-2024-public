#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdnoreturn.h>

#define DEBUG

#define NUM_OPS 39
#define NUM_REGISTERS 256
#define MEMORY_SIZE 0x8000

typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef size_t usize;


#define OPCODE_MASK 0x000000ff
#define OPERAND1_MASK 0x0000ff00
#define OPERAND2_MASK 0x00ff0000
#define OPERAND3_MASK 0xff000000

typedef u32 Instruction;

u8 instr_get_opcode(Instruction instr) {
  return (u8)(instr & OPCODE_MASK);
}

u8 instr_get_operand1(Instruction instr) {
  return (u8)((instr & OPERAND1_MASK) >> 8);
}

u8 instr_get_operand2(Instruction instr) {
  return (u8)((instr & OPERAND2_MASK) >> 16);
}

u8 instr_get_operand3(Instruction instr) {
  return (u8)((instr & OPERAND3_MASK) >> 24);
}

u16 instr_get_operand16(Instruction instr) {
  return (u16)((instr & 0xffff0000) >> 16);
}


struct Vm;
typedef void (*Op)(struct Vm *, Instruction);

typedef struct Vm {
  Op ops[NUM_OPS];
  usize registers[NUM_REGISTERS];
  u8 memory[MEMORY_SIZE];
} Vm;

void vm_next_instruction(Vm *vm) {
  vm->registers[0] += sizeof(Instruction);
}

noreturn void vm_oob_access(Vm *vm) {
  puts("error: out of bounds access detected");
  exit(1);
}

u8 vm_get_u8(Vm *vm, usize address) {
  if (address >= MEMORY_SIZE) {
    vm_oob_access(vm);
  } else {
    return vm->memory[address];
  }
}

void vm_set_u8(Vm *vm, usize address, u8 val) {
  if (address >= MEMORY_SIZE) {
    vm_oob_access(vm);
  } else {
    vm->memory[address] = val;
  }
}

Instruction vm_get_instruction(Vm *vm, usize address) {
  if (address + sizeof(Instruction) >= MEMORY_SIZE) {
    vm_oob_access(vm);
  } else {
    return (u32)vm->memory[address]
      | (u32)vm->memory[address + 1] << 8
      | (u32)vm->memory[address + 2] << 16
      | (u32)vm->memory[address + 3] << 24;
  }
}

usize vm_get_usize(Vm *vm, usize address) {
  if (address + sizeof(usize) >= MEMORY_SIZE) {
    vm_oob_access(vm);
  } else {
    return (usize)vm->memory[address]
      | (usize)vm->memory[address + 1] << 8
      | (usize)vm->memory[address + 2] << 16
      | (usize)vm->memory[address + 3] << 24
      | (usize)vm->memory[address + 4] << 32
      | (usize)vm->memory[address + 5] << 40
      | (usize)vm->memory[address + 6] << 48
      | (usize)vm->memory[address + 7] << 56;
  }
}

void vm_set_usize(Vm *vm, usize address, usize val) {
  if (address + sizeof(usize) >= MEMORY_SIZE) {
    vm_oob_access(vm);
  } else {
    for (int i = 0; i < sizeof(usize); i++) {
      vm->memory[address + i] = val & 0xff;
      val >>= 8;
    }
  }
}

#ifdef DEBUG
void vm_dump_state(Vm *vm) {
  usize last_reg_index = NUM_REGISTERS - 1;
  while (vm->registers[last_reg_index] == 0) {
    last_reg_index -= 1;
    if (last_reg_index == 0) {
      break;
    }
  }

  puts("Vm state:");
  puts("\nRegisters:");
  for (usize i = 0; i <= last_reg_index; i++) {
    printf("r%lu: %#lx\n", i, vm->registers[i]);
  }

  printf("Current instruction: %#x\n", vm_get_instruction(vm, vm->registers[0]));
  puts("");
}
#endif

usize vm_get_access_address(Vm *vm, Instruction instr) {
  u8 address_reg = instr_get_operand2(instr);
  i8 offset = (i8)instr_get_operand3(instr);

  return vm->registers[address_reg] + offset;
}


// instructions
void nop(Vm *vm, Instruction instr) {
  vm_next_instruction(vm);
}

void load(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  usize address = vm_get_access_address(vm, instr);

  vm->registers[dst_reg] = vm_get_usize(vm, address);

  vm_next_instruction(vm);
}

void store(Vm *vm, Instruction instr) {
  u8 src_reg = instr_get_operand1(instr);
  usize address = vm_get_access_address(vm, instr);

  vm_set_usize(vm, address, vm->registers[src_reg]);

  vm_next_instruction(vm);
}

void load8(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  usize address = vm_get_access_address(vm, instr);

  vm->registers[dst_reg] = vm_get_u8(vm, address);

  vm_next_instruction(vm);
}

void store8(Vm *vm, Instruction instr) {
  u8 src_reg = instr_get_operand1(instr);
  usize address = vm_get_access_address(vm, instr);

  vm_set_u8(vm, address, vm->registers[src_reg]);

  vm_next_instruction(vm);
}

void permute_ops(Vm *vm, Instruction instr) {
  u8 *permute_vals = &vm->memory[vm_get_access_address(vm, instr)];

  Op temp_ops[NUM_OPS];
  for (usize i = 0; i < NUM_OPS; i++) {
    temp_ops[i] = vm->ops[i];
  }

  for (usize i = 0; i < NUM_OPS; i++) {
    // intentional bug, out of bounds access
    vm->ops[i] = temp_ops[permute_vals[i]];
  }

  vm_next_instruction(vm);
}

void permute_regs(Vm *vm, Instruction instr) {
  u8 num_regs = instr_get_operand1(instr);
  u8 *permute_vals = &vm->memory[vm_get_access_address(vm, instr)];

  usize temp_regs[NUM_REGISTERS];
  for (usize i = 0; i < NUM_REGISTERS; i++) {
    temp_regs[i] = vm->registers[i];
  }

  for (usize i = 0; i < num_regs; i++) {
    // this is intentional bug for pwn
    // out of bounds access allows reading beyond memory for leak of values on stack
    vm->registers[i] = temp_regs[permute_vals[i]];
  }

  vm_next_instruction(vm);
}

void exit_op(Vm *vm, Instruction instr) {
  puts("exiting...");
  exit(0);
}

void load_immediate(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  u16 immediate = instr_get_operand16(instr);

  vm->registers[dst_reg] = immediate;

  vm_next_instruction(vm);
}

void load_mid_low_immediate(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  u16 immediate = instr_get_operand16(instr);

  vm->registers[dst_reg] |= ((usize)immediate << 16);

  vm_next_instruction(vm);
}

void load_mid_high_immediate(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  u16 immediate = instr_get_operand16(instr);

  vm->registers[dst_reg] |= ((usize)immediate << 32);

  vm_next_instruction(vm);
}

void load_upper_immediate(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  u16 immediate = instr_get_operand16(instr);

  vm->registers[dst_reg] |= ((usize)immediate << 48);

  vm_next_instruction(vm);
}

typedef enum {
  Greater,
  Equal,
  Less,
} CmpResult;

void cmp(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  usize lhs = vm->registers[instr_get_operand2(instr)];
  usize rhs = vm->registers[instr_get_operand3(instr)];
  
  CmpResult result = Equal;
  if (lhs > rhs) {
    result = Greater;
  } else if (lhs < rhs) {
    result = Less;
  }

  vm->registers[dst_reg] = result;

  vm_next_instruction(vm);
}

void cmp_immediate(Vm *vm, Instruction instr) {
  u8 dst_reg = instr_get_operand1(instr);
  usize lhs = vm->registers[instr_get_operand2(instr)];
  usize rhs = instr_get_operand3(instr);

  CmpResult result = Equal;
  if (lhs > rhs) {
    result = Greater;
  } else if (lhs < rhs) {
    result = Less;
  }

  vm->registers[dst_reg] = result;

  vm_next_instruction(vm);
}

// used for jump instructions
CmpResult vm_get_cmp_result(Vm *vm, Instruction instr) {
  usize val = vm->registers[instr_get_operand1(instr)];

  if (val == Greater) {
    return Greater;
  } else if (val == Less) {
    return Less;
  } else {
    return Equal;
  }
}

void jump_reg(Vm *vm, Instruction instr) {
  u8 reg = instr_get_operand1(instr);
  i16 offset = (i16)instr_get_operand16(instr);
  vm->registers[0] = vm->registers[reg] + offset;
}

void jump_inner(Vm *vm, Instruction instr) {
  i16 offset = (i16)instr_get_operand16(instr);
  vm->registers[0] += offset;
}

void jump_eq(Vm *vm, Instruction instr) {
  if (vm_get_cmp_result(vm, instr) == Equal) {
    jump_inner(vm, instr);
  } else {
    vm_next_instruction(vm);
  }
}

void jump_ne(Vm *vm, Instruction instr) {
  if (vm_get_cmp_result(vm, instr) != Equal) {
    jump_inner(vm, instr);
  } else {
    vm_next_instruction(vm);
  }
}

void jump_lt(Vm *vm, Instruction instr) {
  if (vm_get_cmp_result(vm, instr) == Less) {
    jump_inner(vm, instr);
  } else {
    vm_next_instruction(vm);
  }
}

void jump_gt(Vm *vm, Instruction instr) {
  if (vm_get_cmp_result(vm, instr) == Greater) {
    jump_inner(vm, instr);
  } else {
    vm_next_instruction(vm);
  }
}

void jump_le(Vm *vm, Instruction instr) {
  if (vm_get_cmp_result(vm, instr) != Greater) {
    jump_inner(vm, instr);
  } else {
    vm_next_instruction(vm);
  }
}

void jump_ge(Vm *vm, Instruction instr) {
  if (vm_get_cmp_result(vm, instr) != Less) {
    jump_inner(vm, instr);
  } else {
    vm_next_instruction(vm);
  }
}

#define OP_REG(op_name, op) \
void op_name(Vm *vm, Instruction instr) { \
  u8 dst_reg = instr_get_operand1(instr); \
  usize lhs = vm->registers[instr_get_operand2(instr)]; \
  usize rhs = vm->registers[instr_get_operand3(instr)]; \
  vm->registers[dst_reg] = lhs op rhs; \
  vm_next_instruction(vm); \
}

#define OP_IMM(op_name, op) \
void op_name(Vm *vm, Instruction instr) { \
  u8 dst_reg = instr_get_operand1(instr); \
  usize lhs = vm->registers[instr_get_operand2(instr)]; \
  usize rhs = instr_get_operand3(instr); \
  vm->registers[dst_reg] = lhs op rhs; \
  vm_next_instruction(vm); \
}

#define OP(op_name, op) \
OP_REG(op_name, op) \
OP_IMM(op_name ## _immediate, op)

OP(add, +)
OP(sub, -)
OP(mul, *)
OP(divide, /)
OP(or, |)
OP(and, &)
OP(xor, ^)
OP(shl, <<)

void print(Vm *vm, Instruction instr) {
  u8 len = instr_get_operand1(instr);
  usize address = vm_get_access_address(vm, instr);

  for (usize i = 0; i < len; i++) {
    u8 c = vm_get_u8(vm, address + i);
    printf("%c", c);
  }

  vm_next_instruction(vm);
}

void get_input(Vm *vm, Instruction instr) {
  u8 len = instr_get_operand1(instr);
  usize address = vm_get_access_address(vm, instr);

  for (usize i = 0; i < len; i++) {
    u8 c = (u8)getc(stdin);
    vm_set_u8(vm, address + i, c);
  }

  vm_next_instruction(vm);
}

Vm vm_new() {
  Vm vm;

  vm.ops[0] = nop;
  vm.ops[1] = load;
  vm.ops[2] = store;
  vm.ops[3] = permute_ops;
  vm.ops[4] = permute_regs;
  vm.ops[5] = exit_op;
  vm.ops[6] = load_immediate;
  vm.ops[7] = load_mid_low_immediate;
  vm.ops[8] = load_mid_high_immediate;
  vm.ops[9] = load_upper_immediate;
  vm.ops[10] = cmp;
  vm.ops[11] = cmp_immediate;
  vm.ops[12] = jump_reg;
  vm.ops[13] = jump_eq;
  vm.ops[14] = jump_ne;
  vm.ops[15] = jump_gt;
  vm.ops[16] = jump_lt;
  vm.ops[17] = jump_ge;
  vm.ops[18] = jump_le;
  vm.ops[19] = add;
  vm.ops[20] = add_immediate;
  vm.ops[21] = sub;
  vm.ops[22] = sub_immediate;
  vm.ops[23] = mul;
  vm.ops[24] = mul_immediate;
  vm.ops[25] = divide;
  vm.ops[26] = divide_immediate;
  vm.ops[27] = or;
  vm.ops[28] = or_immediate;
  vm.ops[29] = and;
  vm.ops[30] = and_immediate;
  vm.ops[31] = xor;
  vm.ops[32] = xor_immediate;
  vm.ops[33] = print;
  vm.ops[34] = get_input;
  vm.ops[35] = load8;
  vm.ops[36] = store8;
  vm.ops[37] = shl;
  vm.ops[38] = shl_immediate;

  for (int i = 0; i < NUM_REGISTERS; i++) {
    vm.registers[i] = 0;
  }

  memset(vm.memory, 0, MEMORY_SIZE);

  return vm;
}

void vm_run(Vm *vm) {
  for (;;) {
#ifdef DEBUG
    vm_dump_state(vm);
#endif

    Instruction instr = vm_get_instruction(vm, vm->registers[0]);

    u8 opcode = instr_get_opcode(instr);
    if (opcode >= NUM_OPS) {
      puts("error: invalid opcode");
      exit(1);
    }

    vm->ops[opcode](vm, instr);
  }
}

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

void usage() {
  puts("usage: mixtape <bytecode>");
}

int main(int argc, char **argv) {
  setup();

  if (argc != 2) {
    usage();
    return 1;
  }

  char *arg = argv[1];
  if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
    usage();
    return 0;
  }

  FILE *file = fopen(arg, "r");
  if (file == NULL) {
    printf("error: could not open bytecode file `%s`\n", arg);
    return 1;
  }

  Vm vm = vm_new();
  fread(vm.memory, sizeof(u8), MEMORY_SIZE, file);
  fclose(file);

  vm_run(&vm);
}
