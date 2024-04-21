#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/random.h>

#include "rb_rng.h"

typedef u8 child;

#define min(a, b) ((a) < (b) ? (a) : (b))

typedef struct Node {
  struct Node *parent;
  union {
    struct Node *child[2];
    struct {
      struct Node *left;
      struct Node *right;
    };
  };
  bool red;
  u32 n;
} Node;

typedef enum {
  LEFT,
  RIGHT,
} Direction;

Node *node_new(u32 n) {
  Node *out = malloc(sizeof(Node));
  out->parent = NULL;
  out->left = NULL;
  out->right = NULL;
  out->red = true;
  out->n = n;
  return out;
}

Node *get_child(Node *node, Direction dir) {
  return node->child[dir];
}

void set_child(Node *parent, Node *child, Direction dir) {
  parent->child[dir] = child;
  if (child != NULL) {
    child->parent = parent;
  }
}

Direction get_child_direction(Node *child) {
  Node *parent = child->parent;
  if (parent == NULL) {
    assert(false);
  }

  if (parent->left == child) {
    return LEFT;
  } else if (parent->right == child) {
    return RIGHT;
  } else {
    assert(false);
  }
}

Direction get_opposite_direction(Direction dir) {
  return 1 - dir;
}

typedef struct {
  Node *root;
} RbTree;

RbTree *rb_tree_new() {
  RbTree *out = (RbTree *) malloc(sizeof(RbTree));
  out->root = NULL;
  return out;
}

void rb_node_delete(Node *node) {
  if (node == NULL) {
    return;
  }

  rb_node_delete(node->left);
  rb_node_delete(node->right);
  free(node);
}

void rb_tree_delete(RbTree *tree) {
  rb_node_delete(tree->root);
  free(tree);
}

Node *rb_tree_rotate(RbTree *tree, Node *node, Direction dir) {
  Node *parent = node->parent;
  Node *rotate_child = get_child(node, get_opposite_direction(dir));
  if (rotate_child == NULL) {
    assert(false);
  }

  Node *childs_child = get_child(rotate_child, dir);

  if (parent == NULL) {
    // node had no parent, rotate child should now be root
    tree->root = rotate_child;
    rotate_child->parent = NULL;
  } else {
    Direction parent_dir = get_child_direction(node);
    set_child(parent, rotate_child, parent_dir);
  }

  set_child(node, childs_child, get_opposite_direction(dir));
  set_child(rotate_child, node, dir);

  return rotate_child;
}

void rb_tree_insert_inner(RbTree *tree, Node *parent, Node *node, Direction dir) {
  node->parent = NULL;
  node->left = NULL;
  node->right = NULL;
  node->red = true;

  if (parent == NULL) {
    // insert node as root
    tree->root = node;
    return;
  }

  set_child(parent, node, dir);

  do {
    if (!parent->red) {
      // parent is black, invariants hold
      return;
    }

    Node *grandparent = parent->parent;
    if (grandparent == NULL) {
      // parent is root, just change its color to black
      parent->red = false;
      return;
    } else {
      Direction parent_dir = get_child_direction(parent);
      Node *uncle = get_child(grandparent, get_opposite_direction(parent_dir));

      if (uncle == NULL || !uncle->red) {
        // parent is red, uncle is black

        if (get_child(parent, get_opposite_direction(parent_dir))) {
          // if a formation like this occurs:
          //      G
          //    /   \
          //  P      U
          //   \
          //    N
          rb_tree_rotate(tree, parent, parent_dir);
          node = parent;
          parent = get_child(grandparent, parent_dir);
        }

        // now formation is like this:
        //      G
        //    /   \
        //  P      U
        // /
        //N

        rb_tree_rotate(tree, grandparent, get_opposite_direction(parent_dir));
        parent->red = false;
        grandparent->red = true;
        return;
      } else {
        // both parent and uncle are red, recolor nodes
        parent->red = false;
        uncle->red = false;
        grandparent->red = true;

        // reiterate loop, cause now grandparent could violate requirements
        node = grandparent;
        parent = grandparent->parent;
        if (parent == NULL) {
          // if root reached, grandparent does not violate coloring requirements
          return;
        }
      }
    }

  } while (true);
}

void rb_tree_insert(RbTree *tree, u32 n) {
  Node *node = node_new(n);
  Node *parent = tree->root;

  if (parent == NULL) {
    rb_tree_insert_inner(tree, parent, node, LEFT);
    return;
  }

  Direction dir = LEFT;
  for (;;) {
    if (node->n < parent->n) {
      if (parent->left == NULL) {
        dir = LEFT;
        break;
      } else {
        parent = parent->left;
      }
    } else {
      if (parent->right == NULL) {
        dir = RIGHT;
        break;
      } else {
        parent = parent->right;
      }
    }
  }

  rb_tree_insert_inner(tree, parent, node, dir);
}

u32 index_constants_inorder[ELEM_COUNT] = {1838976474, 374824258, 2015091835, 1499349161, 560112356, 3475770958, 3691556860, 1719217899, 1407712889, 2451628150, 1483082012, 2388279961, 846184684, 1052683959, 4086528325, 2714620518};
u32 level_constants_inorder[ELEM_COUNT] = {3146222752, 3518595899, 1187047309, 2423588276, 3146452533, 1998009090, 1037015550, 3015469299, 3111564502, 113553370, 908559975, 943130345, 65112547, 2578601813, 3968906670, 747778115};
u32 index_constants_preorder[ELEM_COUNT] = {1887769515, 3735348945, 944943912, 372723852, 4286040690, 3307288336, 991147818, 2425748506, 1830629178, 3775741956, 2607442498, 1881568352, 1235041540, 45668753, 4255054136, 2248747441};
u32 level_constants_preorder[ELEM_COUNT] = {3044999676, 1594039004, 3286380463, 3517179363, 2104772949, 2754456282, 629411303, 2646745403, 2872309558, 3786261448, 3312379268, 816912229, 3233978986, 2632854529, 4156002538, 2056267636};


void state_print(State *state) {
  // puts("state:");
  // for (size_t i = 0; i < ELEM_COUNT; i++) {
  //   printf("%lu: %u\n", i, state->state[i]);
  // }
  puts("state: ");
  printf("[");
  for (size_t i = 0; i < ELEM_COUNT; i++) {
    printf("%u, ", state->state[i]);
  }
  printf("]\n");
}

u32 rotate_left(u32 n, size_t amount) {
  return (n << amount) | (n >> (8 * sizeof(u32) - amount));
}

u32 rb_node_transform(u32 *index_constants, u32 *level_constants, u32 n, size_t traversal_index, size_t tree_level, bool red) {
  // printf("start n: %u\n", n);
  if (red) {
    n = rotate_left(n, 3);
  } else {
    n = rotate_left(n, 19);
  }

  // printf("rotate n: %u\n", n);

  n = n ^ index_constants[traversal_index];
  // printf("xor n: %u\n", n);
  n = n + level_constants[tree_level];
  // printf("finished n: %u\n", n);

  return n;
}

// output is array of ELEM_COUNT elements
void rb_inorder_round(Node *node, u32 *out, size_t *traversal_index, size_t tree_level) {
  if (node == NULL) {
    return;
  }

  rb_inorder_round(node->left, out, traversal_index, tree_level + 1);

  // puts("====== inorder round ======");
  // printf("%u\n", node->n);
  // puts(node->red ? "red" : "black");
  // printf("level %lu\n", tree_level);
  // printf("index: %lu\n", *traversal_index);
  // puts("\n");

  out[*traversal_index] = rb_node_transform(index_constants_inorder, level_constants_inorder, node->n, *traversal_index, tree_level, node->red);
  *traversal_index += 1;

  rb_inorder_round(node->right, out, traversal_index, tree_level + 1);
}

// output is array of ELEM_COUNT elements
void rb_preorder_round(Node *node, u32 *out, size_t *traversal_index, size_t tree_level) {
  if (node == NULL) {
    return;
  }

  rb_preorder_round(node->left, out, traversal_index, tree_level + 1);
  rb_preorder_round(node->right, out, traversal_index, tree_level + 1);

  out[*traversal_index] = rb_node_transform(index_constants_preorder, level_constants_preorder, node->n, *traversal_index, tree_level, node->red);
  *traversal_index += 1;
}

// output is array of ELEM_COUNT elements
void rb_round(State *state, u32 *out) {
  // state_print(state);
  RbTree *tree = rb_tree_new();

  // insert all numbers into rb tree
  for (size_t i = 0; i < ELEM_COUNT; i++) {
    rb_tree_insert(tree, state->state[i]);
  }

  size_t traversal_index = 0;
  u32 inorder_data[ELEM_COUNT];
  rb_inorder_round(tree->root, inorder_data, &traversal_index, 0);

  // traversal_index = 0;
  // u32 preorder_data[ELEM_COUNT];
  // rb_preorder_round(tree->root, preorder_data, &traversal_index, 0);

  for (size_t i = 0; i < ELEM_COUNT; i++) {
    // out[i] = inorder_data[i] ^ preorder_data[i];
    out[i] = inorder_data[i];
  }

  rb_tree_delete(tree);
}

u32 u32_from_parts(u8 *parts) {
  return (u32) parts[0] | ((u32) parts[1] << 8) | ((u32) parts[2] << 16) | ((u32) parts[3] << 24);
}

void rb_rng_next_state(RbRng *rng);

// seed should be 64 bytes long
RbRng rb_rng_new(u8 *seed) {
  RbRng out;

  // copy seed to state
  for (size_t i = 0; i < ELEM_COUNT; i++) {
    u8 *n = &seed[sizeof(u32) * i];
    out.state.state[i] = u32_from_parts(n);
  }

  rb_rng_next_state(&out);

  return out;
}

RbRng rb_rng_from_os_random() {
  u8 seed[SEED_SIZE];
  getrandom(seed, SEED_SIZE, 0);

  return rb_rng_new(seed);
}

void rb_rng_next_state(RbRng *rng) {
  u32 round_out[ELEM_COUNT];
  rb_round(&rng->state, round_out);

  // puts("out bytes");
  // state_print(&rng->state);

  memcpy(&rng->out_bytes, round_out, STATE_SIZE);
  // for (size_t i = 0; i < 64; i++) {
  //   printf("%u, ", rng->out_bytes[i]);
  // }
  rng->out_index = 0;

  for (size_t i = 0; i < ELEM_COUNT; i++) {
    rng->state.state[i] += round_out[i];
  }

  // puts("next state");
  // state_print(&rng->state);
}

u8 rb_rng_next_byte(RbRng *rng) {
  if (rng->out_index == STATE_SIZE) {
    rb_rng_next_state(rng);
  }

  u8 out = rng->out_bytes[rng->out_index];
  rng->out_index += 1;
  return out;
}

void rb_rng_random(RbRng *rng, u8 *buf, size_t n) {
  for (size_t i = 0; i < n; i++) {
    buf[i] = rb_rng_next_byte(rng);
  }
}



///////////////////////////////////////////
// SOLVING                               //
///////////////////////////////////////////

// called by the rust solving code
#ifdef SOLVE

void perform_round(u32 *start_state, u32 *end_state, u8 *out_bytes) {
  State state;
  memcpy(&state.state, start_state, STATE_SIZE);

  u32 out[ELEM_COUNT];
  rb_round(&state, out);

  for (size_t i = 0; i < ELEM_COUNT; i++) {
    state.state[i] += out[i];
  }

  memcpy(end_state, &state.state, STATE_SIZE);
  memcpy(out_bytes, out, STATE_SIZE);
}

#endif
