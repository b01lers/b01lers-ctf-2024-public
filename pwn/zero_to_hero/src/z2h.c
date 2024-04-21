#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <stddef.h>

#define ADDR 0x10000
#define MAXLEN 512


char flag[100];

struct sock_filter filter[] = {
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr) ),  // examine
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3c, 0, 1), BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),  // allow exit
  BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)  // kill process
};

struct sock_fprog prog = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter, };

int nibble2int(const char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return (c - 'a') + 10;
  if (c >= 'A' && c <= 'F') return (c - 'A') + 10;
  return -1;
}

int hexbyte2int(const char* const p) {
  int hi = nibble2int(p[0]); 
  int lo = nibble2int(p[1]);
  if (lo < 0 || hi < 0) return -1;
  return lo + (hi << 4); 
}


int main() {

  FILE* f = fopen("./flag.txt", "r");
  if (f == 0) {
    fprintf(stdout, "no flag\n");
    fflush(stdout);
    return 1;
  }
  fread(flag, 1, 100, f);
  fclose(f);

  void* addr = mmap((void*) ADDR, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr != (void*) ADDR) {
    fprintf(stdout, "failure\n");
    fflush(stdout);
    return 1;
  }

  char buf[(MAXLEN << 1) + 2];
  fprintf(stdout, "input: ");
  fflush(stdout);
  fgets(buf, MAXLEN * 2, stdin);

  char* addr2 = addr;
  for (int i = 0; i < MAXLEN; ++i) {
    int v = hexbyte2int(buf + 2 * i);
    if (v < 0) {
      fprintf(stdout, "stored %d byte(s)\n", i);
      fflush(stdout);
      break;
    }
    addr2[i] = v;
  }


  fprintf(stdout, "wiping and executing...");
  fflush(stdout);

  if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ) return 1;

  if ( prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) ) return 1;

  asm volatile (
    "xor ebx, ebx\n"
    "xor ecx, ecx\n"
    "xor edx, edx\n"
    "xor edi, edi\n"
    "xor esi, esi\n"
    "xor ebp, ebp\n"
    "xor esp, esp\n"
    "xor r8d, r8d\n"
    "xor r9d, r9d\n"
    "xor r10d, r10d\n"
    "xor r11d, r11d\n"
    "xor r12d, r12d\n"
    "xor r13d, r13d\n"
    "xor r14d, r14d\n"
    "xor r15d, r15d\n"
    "mov eax, 0x10000\n"
    "jmp rax \n"
  );

  return 0;
}
