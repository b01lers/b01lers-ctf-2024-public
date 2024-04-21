#!/bin/sh

gcc rb_rng.c -c
gcc bracket.c -c
# gcc rng_test.c -c
gcc rb_rng.o bracket.o -o b01lers_bracket
strip b01lers_bracket
# gcc rb_rng.o rng_test.o -o rng_test
