python generate_object_file.py
python generate_linker_script.py
gcc -m32 -T linker_script.ld key_object.o flag_object.o -o linked.elf
