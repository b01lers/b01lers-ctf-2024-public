fn main() {
    cc::Build::new()
        .file("../rb_rng.c")
        .define("SOLVE", None)
        .compile("rb_rng");
}