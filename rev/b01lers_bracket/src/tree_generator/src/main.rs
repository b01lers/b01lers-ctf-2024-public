use std::{cmp::min, collections::HashSet};

const STATE_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Node {
    Red,
    Black,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Leaf {
    parent: Node,
    index: usize,
}

#[derive(Debug, Clone)]
struct Tree {
    node_count: usize,
    tree: Vec<Option<Node>>,
    // these are indexes pointing to places that would be a child of a leaf
    leafs: HashSet<usize>,
    data: [u32; STATE_SIZE],
    correct: [u32; STATE_SIZE],
    initial_states_permuted: Vec<[u32; STATE_SIZE]>,
    first_state_possible_elems: HashSet<u32>,
    next_state_possible_elems: HashSet<u32>,
}

impl Tree {
    fn new(data: [u32; STATE_SIZE], correct: [u32; STATE_SIZE]) -> Tree {
        let mut out = Tree {
            node_count: 0,
            tree: Vec::new(),
            leafs: HashSet::new(),
            data,
            correct,
            initial_states_permuted: Vec::new(),
            first_state_possible_elems: HashSet::new(),
            next_state_possible_elems: HashSet::new(),
        };

        // consider root black leaf so it is used by red and black nodes
        out.leafs.insert(0);

        out
    }

    fn parent(index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            Some((index - 1) / 2)
        }
    }

    fn left_child(index: usize) -> usize {
        2 * (index + 1) - 1
    }

    fn right_child(index: usize) -> usize {
        2 * (index + 1)
    }

    fn get_node(&self, index: usize) -> Option<Node> {
        self.tree.get(index).copied().flatten()
    }

    fn set_index(&mut self, index: usize, node: Node) {
        while index >= self.tree.len() {
            self.tree.push(None);
        }

        if self.tree[index].is_none() {
            self.node_count += 1;
        }

        self.tree[index] = Some(node);

        self.leafs.remove(&index);

        if self.tree.get(Self::left_child(index)).cloned().flatten().is_none() {
            self.leafs.insert(Self::left_child(index));
        }

        if self.tree.get(Self::right_child(index)).cloned().flatten().is_none() {
            self.leafs.insert(Self::right_child(index));
        }
    }

    fn remove_index_leaf(&mut self, index: usize) {
        assert!(index < self.tree.len());

        match self.tree[index] {
            Some(_) => {
                self.leafs.remove(&Self::left_child(index));
                self.leafs.remove(&Self::right_child(index));
                self.node_count -= 1;
            },
            None => panic!("expected leaf"),
        }

        self.tree[index] = None;

        if let Some(parent) = Self::parent(index) {
            match self.tree[parent] {
                Some(_) => self.leafs.insert(index),
                None => panic!("parent is none"),
            };
        }
    }

    fn black_round(&mut self, max_size: usize) {
        if self.node_count + self.leafs.len() > max_size {
            // doing a black round would take too many nodes
        } else {
            let leafs = self.leafs.clone();
            for leaf in leafs.iter() {
                self.set_index(*leaf, Node::Black);
            }

            if self.node_count == max_size {
                self.compute();
            } else {
                self.red_round(max_size);
            }

            for leaf in leafs.iter() {
                self.remove_index_leaf(*leaf);
            }
        }
    }

    fn red_round_inner(&mut self, max_size: usize, level: usize, insert_pos: &[usize], start_index: usize) {
        if level == 0 {
            if self.node_count == max_size {
                self.compute();
            } else {
                self.black_round(max_size);
            }
            return;
        }

        for i in start_index..insert_pos.len() {
            self.set_index(insert_pos[i], Node::Red);
            self.red_round_inner(max_size, level - 1, insert_pos, i + 1);
            self.remove_index_leaf(insert_pos[i]);
        }
    }

    fn red_round(&mut self, max_size: usize) {
        assert!(self.node_count <= max_size);

        // maximum amount of red nodes that could be added
        let max_add_amount = max_size - self.node_count;

        let red_insert_pos = self.leafs.iter()
            .cloned()
            .filter(|index| {
                let parent_index = Self::parent(*index);
                if let Some(parent_index) = parent_index {
                    match self.tree[parent_index] {
                        Some(Node::Black) => true,
                        Some(Node::Red) => false,
                        None => panic!("node has no parent"),
                    }
                } else {
                    true
                }
            }).collect::<Vec<_>>();
        // number of possible places red leafs can be inserted
        let red_pos_count = red_insert_pos.len();

        if red_pos_count == 0 {
            return;
        }

        let add_amount = min(max_add_amount, red_pos_count);

        for i in 0..=add_amount {
            self.red_round_inner(max_size, i, &red_insert_pos[..], 0);
        }
    }

    fn in_order_round(&self, node_index: usize, input: &[u32; STATE_SIZE], out: &mut [u32; STATE_SIZE], index: &mut usize, tree_level: usize) {
        if let Some(node) = self.get_node(node_index) {
            self.in_order_round(Self::left_child(node_index), input, out, index, tree_level + 1);

            out[*index] = rb_node_transform_inv(&IN_ORDER_INDEX, &IN_ORDER_LEVEL, *index, tree_level, node, input[*index]);
            *index += 1;

            self.in_order_round(Self::right_child(node_index), input, out, index, tree_level + 1);
        }
    }

    fn compute(&mut self) {
        let mut initial_state = [0; STATE_SIZE];
        self.in_order_round(0, &self.data, &mut initial_state, &mut 0, 0);
        self.initial_states_permuted.push(initial_state);
        for n in initial_state {
            self.first_state_possible_elems.insert(n);
        }

        let mut next_state_inverted = [0; STATE_SIZE];
        self.in_order_round(0, &self.correct, &mut next_state_inverted, &mut 0, 0);
        for n in next_state_inverted {
            self.next_state_possible_elems.insert(n);
        }

        /*let mut next_state = [0; STATE_SIZE];
        for i in 0..STATE_SIZE {
            next_state[i] = initial_state[i].wrapping_add(self.data[i]);
        }

        println!("initial state: {initial_state:?}");
        println!("next state: {next_state:?}");*/
    }
}

static IN_ORDER_INDEX: [u32; 16] = [1838976474, 374824258, 2015091835, 1499349161, 560112356, 3475770958, 3691556860, 1719217899, 1407712889, 2451628150, 1483082012, 2388279961, 846184684, 1052683959, 4086528325, 2714620518];
static IN_ORDER_LEVEL: [u32; 16] = [3146222752, 3518595899, 1187047309, 2423588276, 3146452533, 1998009090, 1037015550, 3015469299, 3111564502, 113553370, 908559975, 943130345, 65112547, 2578601813, 3968906670, 747778115];

fn rb_node_transform_inv(index_consts: &[u32; 16], level_consts: &[u32; 16], index: usize, level: usize, node: Node, mut n: u32) -> u32 {
    n = n.wrapping_sub(level_consts[level]);
    n = n ^ index_consts[index];

    if node == Node::Red {
        n.rotate_right(3)
    } else {
        n.rotate_right(19)
    }
}

fn main() {
    //let data = [105, 100, 46, 252, 180, 141, 13, 166, 201, 231, 124, 194, 52, 42, 131, 172, 248, 70, 102, 216, 51, 88, 87, 184, 134, 211, 42, 36, 80, 217, 36, 122, 71, 93, 60, 156, 112, 7, 87, 118, 85, 119, 156, 5, 107, 212, 98, 205, 225, 1, 113, 178, 212, 56, 45, 4, 143, 211, 14, 104, 164, 194, 97, 65, 143, 36, 81, 9, 129, 93, 32, 92, 50, 222, 249, 162, 107, 112, 106, 191, 129, 134, 38, 159, 139, 42, 98, 131, 218, 207, 60, 25, 204, 122, 218, 247, 178, 167, 138, 106, 97, 63, 36, 198, 109, 181, 97, 110, 242, 68, 203, 120, 8, 22, 152, 49, 237, 86, 154, 128, 105, 2, 191, 71, 161, 29, 199, 122, 72, 169, 216, 96, 95, 110, 251, 223, 226, 170, 157, 196, 70, 34, 155];
    //let data = [14, 162, 106, 97, 92, 57, 106, 126, 111, 101, 70, 232, 131, 0, 78, 223, 185, 71, 88, 228, 56, 110, 216, 153, 129, 140, 120, 71, 108, 4, 222, 43, 151, 217, 112, 189, 95, 180, 87, 124, 116, 58, 162, 36, 157, 89, 123, 73, 4, 63, 142, 250, 133, 249, 25, 184, 136, 154, 26, 189, 127, 154, 146, 162, 189, 58, 223, 193, 108, 209, 70, 196, 95, 115, 118, 203, 171, 71, 190, 105, 93, 187, 202, 234, 20, 171, 140, 116, 150, 24, 202, 254, 97, 159, 250, 65, 105, 16, 225, 189, 22, 177, 66, 34, 15, 209, 40, 28, 74, 1, 245, 198, 168, 144, 223, 169, 174, 37, 6, 78, 183, 98, 153, 38, 213, 149, 172, 42, 99, 135, 172, 82, 180, 97, 67, 243, 189, 87, 109, 186, 88, 18, 91];
    // fails
    //let data = [94, 151, 226, 178, 80, 85, 255, 224, 254, 123, 67, 102, 11, 181, 86, 144, 162, 92, 192, 9, 225, 237, 149, 190, 129, 217, 124, 10, 235, 193, 148, 205, 130, 188, 43, 223, 78, 57, 45, 248, 148, 175, 77, 126, 106, 254, 204, 69, 229, 160, 249, 47, 6, 62, 148, 229, 241, 195, 25, 151, 230, 78, 34, 225, 174, 107, 149, 142, 121, 232, 120, 242, 56, 248, 111, 97, 121, 201, 5, 144, 217, 246, 2, 157, 139, 51, 7, 145, 248, 163, 137, 249, 210, 145, 245, 124, 154, 95, 119, 146, 126, 19, 117, 113, 58, 202, 246, 65, 9, 252, 73, 140, 192, 192, 195, 169, 223, 131, 33, 196, 208, 61, 123, 18, 238, 189, 69, 54, 18, 144, 117, 197, 78, 226, 245, 228, 233, 68, 108, 227, 64, 108, 192];
    //let data = [98, 211, 209, 116, 199, 150, 89, 242, 87, 155, 22, 188, 109, 219, 225, 85, 160, 124, 99, 216, 153, 177, 90, 0, 138, 51, 108, 225, 191, 165, 19, 246, 82, 132, 140, 222, 131, 107, 241, 225, 205, 166, 13, 187, 9, 126, 206, 218, 222, 254, 103, 119, 225, 42, 2, 255, 63, 165, 254, 252, 189, 114, 234, 244, 15, 109, 170, 41, 24, 119, 124, 249, 64, 206, 105, 153, 126, 151, 2, 40, 218, 83, 12, 250, 22, 92, 146, 222, 133, 238, 10, 207, 182, 22, 237, 28, 211, 129, 170, 92, 114, 60, 55, 19, 66, 27, 135, 217, 178, 148, 235, 89, 205, 100, 88, 107, 134, 99, 8, 37, 159, 188, 12, 14, 231, 169, 31, 221, 215, 201, 8, 33, 176, 6, 188, 69, 159, 196, 241, 180, 218, 109, 212];
    //let data = [54, 77, 143, 13, 189, 193, 47, 166, 22, 203, 79, 39, 37, 41, 94, 39, 93, 219, 51, 237, 240, 178, 221, 165, 166, 50, 6, 39, 67, 232, 136, 223, 53, 151, 191, 51, 251, 133, 230, 192, 125, 165, 21, 42, 51, 90, 165, 120, 158, 25, 163, 121, 45, 213, 63, 213, 179, 73, 237, 154, 53, 65, 7, 235, 3, 228, 233, 225, 215, 157, 40, 148, 55, 120, 238, 52, 232, 87, 4, 41, 195, 84, 221, 115, 115, 50, 120, 3, 151, 125, 159, 57, 35, 147, 59, 146, 214, 175, 15, 45, 242, 66, 156, 109, 69, 128, 143, 32, 156, 196, 61, 222, 90, 219, 94, 150, 5, 82, 1, 161, 119, 187, 222, 86, 140, 190, 23, 74, 17, 96, 145, 25, 240, 110, 39, 75, 79, 34, 240, 124, 236, 101, 113];

    eprintln!("aaaaa");
    let stdin = std::io::stdin();
    let mut input = String::new();

    let mut data = Vec::new();
    // read in 2 blocks
    for _ in 0..(8 * STATE_SIZE) {
        //eprintln!("1");
        stdin.read_line(&mut input).unwrap();
        //eprintln!("2");
        //eprintln!("{input}");
        data.push(input.trim().parse::<u8>().unwrap());
        input.clear();
    }

    let mut data_vec = [0; STATE_SIZE];
    for i in 0..data_vec.len() {
        let data_range = data[(4 * i)..(4 * (i + 1))].try_into().unwrap();
        data_vec[i] = u32::from_le_bytes(data_range);
    }
    
    //println!("data: {data_vec:?}");

    let mut correct_vec = [0; STATE_SIZE];
    for i in 0..correct_vec.len() {
        let data_range = data[(4 * i + 64)..(4 * (i + 1) + 64)].try_into().unwrap();
        correct_vec[i] = u32::from_le_bytes(data_range);
    }

    //println!("correct: {correct_vec:?}");

    let mut tree = Tree::new(data_vec, correct_vec);
    tree.red_round(STATE_SIZE);
    //println!("states: {}", tree.initial_states_permuted.len());
    //println!("unique elems: {}", tree.next_state_possible_elems.len());

    let mut initial_state = [0; STATE_SIZE];
    let mut possible = 0;
    for elem in tree.first_state_possible_elems.iter() {
        for (i, first_round_out) in data_vec.iter().enumerate() {
            let next_round_elem = elem.wrapping_add(*first_round_out);
            if tree.next_state_possible_elems.contains(&next_round_elem) {
                initial_state[i] = next_round_elem;
                possible += 1;
            }
        }
    }

    assert_eq!(possible, STATE_SIZE);

    //println!("state: {initial_state:?}");

    let mut rng = RbRng::new(initial_state);
    // rng is now in the same state as after first round finished
    // get past inital teams
    rng.next_block();

    for _ in 0..=14 {
        rng.next_byte();
    }

    eprintln!("stage 2");

    // now predict matches based on python scripts input seeds
    loop {
        //eprintln!("begin");
        stdin.read_line(&mut input).unwrap();
        //eprintln!("got1 {input}");
        let seed1 = input.trim().parse::<i8>().unwrap();
        input.clear();

        stdin.read_line(&mut input).unwrap();
        //eprintln!("got2 {input}");
        let seed2 = input.trim().parse::<i8>().unwrap();
        input.clear();

        let threshhold = 4 * (seed2 - seed1);
        let next_byte = rng.next_byte() as i8;
        eprintln!("{next_byte:?}");
        if next_byte > threshhold {
            println!("2");
        } else {
            println!("1");
        }

        //eprintln!("end");
    }
}

extern "C" {
    fn perform_round(start_state: *const u32, end_state: *mut u32, out_bytes: *mut u8);
}

struct RbRng {
    state: [u32; STATE_SIZE],
    out_block: [u8; 4 * STATE_SIZE],
    out_index: usize,
}

impl RbRng {
    fn new(seed: [u32; STATE_SIZE]) -> RbRng {
        let mut out = RbRng {
            state: [0; STATE_SIZE],
            out_block: [0; 4 * STATE_SIZE],
            out_index: 0,
        };

        out.state = seed;
        out.next_block();
        out
    }

    fn next_block(&mut self) {
        let mut end_state = [0u32; STATE_SIZE];
        unsafe {
            perform_round(&self.state as *const u32, &mut end_state as *mut u32, &mut self.out_block as *mut u8);
        }

        self.state = end_state;
        self.out_index = 0;
    }

    fn next_byte(&mut self) -> u8 {
        if self.out_index >= self.out_block.len() {
            self.next_block();
        }

        let out = self.out_block[self.out_index];
        self.out_index += 1;
        out
    }
}