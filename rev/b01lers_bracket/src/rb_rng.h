#ifndef RB_RNG
#define RB_RNG

#include <stdint.h>
#include <stddef.h>

typedef uint8_t u8;
typedef int8_t i8;
typedef uint32_t u32;
typedef int32_t i32;

#define ELEM_COUNT 16
#define STATE_SIZE (ELEM_COUNT * sizeof(u32))
#define SEED_SIZE STATE_SIZE

typedef struct {
  u32 state[ELEM_COUNT];
} State;

typedef struct {
  State state;
  u8 out_bytes[STATE_SIZE];
  size_t out_index;
} RbRng;

RbRng rb_rng_new(u8 *seed);
RbRng rb_rng_from_os_random();

u8 rb_rng_next_byte(RbRng *rng);
void rb_rng_random(RbRng *rng, u8 *buf, size_t n);

#endif
