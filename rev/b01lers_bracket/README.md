# Writeup for b01lers_bracket by Athryx

## Overview

The b01lers bracket consists of a custom prng based on a red black tree and a game where you must predict an imaginary
march madness bracket fully correctly. After reverse engineering the b01lers bracket, you can see that
it first gets output from the prng to get the teams records and points per game.

### Bracket

For each team, 1 byte is generated. The first 5 bits are the number of wins, and the last 3 bits
are used for determining points per game. The formula is `points per game = 39 + (3 * wins) / 2 + other_3_bits`.

The only exception is purdue is fixed with a record of 29-3 and 82 points per game.

This is generated for all 144 teams so you get 143 bytes of prng output (cause purdue doesn't give any output).
The top 64 teams are seeded into the bracket, and to predict each match, a random byte is generated.
It is then used in the following formula:
`difference = 4 * (team2_seed - team1_seed)`
If the 1 byte signed random number is greater than the difference, team 2 wins, otherwise team 1 wins.

The code for determining match winner is below
```c
Team *match_get_winner(Match *match, RbRng *rng) {
  // high seed on team2 gives weight to team 1
  i8 seed_diff = (i8) match->team2->seed - (i8) match->team1->seed;
  // 16 * 6 == 96 / 128 weight that is afffected by seed
  i8 threshhold = 4 * seed_diff;
  i8 random = (i8) rb_rng_next_byte(rng);

  // if random above threshhold, team2 won
  return random > threshhold ? match->team2 : match->team1;
}
```

### Rng

The rng has a 64 byte state divided into 16 4 byte numbers. The rng outputs 64 byte blocks, and random bytes are taken
from the block, until the block runs out, then another block is made. To generate a block, the rng inserts the 16 4 byte numbers
into a red black tree, then it performs an inorder traversal of the tree, and the corresponding output 4 byte number is based
on the index during traversal, the depth in the tree, the value of the number in the node, and the color of the node.
The relavent code is as follows:
```c
u32 rb_node_transform(u32 *index_constants, u32 *level_constants, u32 n, size_t traversal_index, size_t tree_level, bool red) {
  if (red) {
    n = rotate_left(n, 3);
  } else {
    n = rotate_left(n, 19);
  }

  n = n ^ index_constants[traversal_index];
  n = n + level_constants[tree_level];

  return n;
}
```

To get the next state, each 4 byte state number is added with each 4 byte number in the output block, and the result is the next state.

## Solve

So you must break the prng, given 143 bytes of output. This corresponds to 2 blocks of output given, plus a bit extra.
The solution I did only used the first 128 bytes, or first 2 blocks.

### Generating all Possible Red Black Trees

The approach I used for solving is generate
every possible red black tree with 16 nodes. This ends up being only around 20,00 trees. The way it was done is first
start with an empty tree, and keep track of all the places nodes can be inserted (for empty tree only the root can be inserted).
Then try all possible ways of inserting the red nodes in the tree, which means try all combinations of inserting red nodes
only below black nodes or at the root. If a read node was inserted below a red node, this would violate the red black tree
rules, so don't test these trees. Then for each tree, try inserting a black node at every leaf position. This is because
the number of black nodes from the root to every leaf must be the same for the whole tree, so we do this to maintain red black tree
rules. Once 16 nodes are reached, record the arrangement of the tree.

### Recovering possible state bytes

Then for each tree, the `rb_node_transform` function can be easily inverted, so you take the output state bytes to get the
possible input state bytes for both the first and second state block. The bytes will not be in order, but if you put them into
a set for the possible first and second state bytes, you can see it is only around 100 - 150 state numbers possible.

### Recovering original state

You know that some number from the first state was added with an output number to get a number of the corresponding second state.
The approach that I used is to iterate all 16 output words $o_i \in output_1$.
Then iterate all possible numbers $s_1 \in possiblestate_1$, and if $o_1 + s_1 \mod 2^{32} \in possiblestate_2$ then you have likely
found the correct state number $s_1$ for position i.

It turns out the chances of all 16 positions only having 1 possibility is high, which means you can recover entire original state.
Then you can easily predict all other matches, to get the flag.

flag: `bctf{sh01lDv3_us3d_a_r34l_RnG_57e22f5af0c0c908b67a}`

### Other Notes

The solver script I had seems to only work 90% of the time, which I kind of expected would be the case, cause there might be multiple possibilities
for the original state at a given position, but it usually fails for an opposite reason: because not all bytes could be determined (so it can't find a possibility for some positions).
Im not sure exactly why this happens, perhaps the method I used of finding all possible red black trees is not completely correct, maybe some are missed, or some other error,
but it is more the likely enough to solve the challenge. The RNG is also pretty weak, so there is probably multiple ways to do it.

### Solver Code

The solve script is found in `src/solve.py` which is in charge of connecting to output and parsing text, and `src/tree_generator/src/main.rs` is in charge of actualy breaking the rng.
The rust code also links into the original challenge code in order to get random numbers once the state is recovered.
