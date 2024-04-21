#include "rb_rng.h"
#include <stddef.h>
#include <stdio.h>

size_t count[256];

void test();

int main() {
  test();
  RbRng rng = rb_rng_from_os_random();

  // for (size_t i = 0; i < 1000000000; i++) {
  //   // count[rb_rng_next_byte(&rng)] += 1;
  // }

  // for (size_t i = 0; i < 123; i++) {
  //   printf("%u\n", rb_rng_next_byte(&rng));
  // }

  // for (size_t i = 0; i < 1000000000; i++) {
  //   count[rb_rng_next_byte(&rng)] += 1;
  // }

  // for (size_t i = 0; i < 256; i++) {
  //   printf("%lu, ", i);
  // }
  // puts("\n");
  // for (size_t i = 0; i < 256; i++) {
  //   printf("%lu, ", count[i]);
  // }


  // for (size_t i = 0; i < 256; i++) {
  //   printf("%lu: %lu\n", i, count[i]);
  // }
}
