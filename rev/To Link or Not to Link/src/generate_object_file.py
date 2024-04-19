from makeelf.elf import *

pairs = [("bctf{we're_out_of_milk}", "flag_object.o", "flag_base.o"), 
         ("super_duper_secret_key!", "key_object.o", "key_base.o")]

for input_str, filename, base in pairs:
    elf = ELF.from_file(base)[0]
    binary_str = ''.join(format(ord(i), '08b') for i in input_str)

    buffer_base = 0x10000
    current_offset = 0 

    for ind, i in enumerate(binary_str):
        section_name = "." + "0" * ind + "1" + "0" * (len(binary_str) - ind - 1)
        section_value = b"\x00" if i == "1" else b""
        elf.append_section(section_name, section_value, buffer_base + current_offset)
        current_offset += len(section_value)

    with open(filename, 'wb') as f:
        f.write(bytes(elf))
