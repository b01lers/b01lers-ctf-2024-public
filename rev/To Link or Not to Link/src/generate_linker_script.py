bit_string_len = 184

def write_section(section):
    global script
    script += section + "_calculate : {\n"
    script += "\tKEEP(flag_object.o(" + section + "))\n"
    script += "\tKEEP(key_object.o(" + section + "))\n"
    script += "}\n"
    script += section + " : {\n"
    script += "\t_res = SIZEOF(" + section + "_calculate) == 1 ? 1 : 0;\n"
    script += "\t. = . + _res;\n"
    script += "}\n\n" 

script = ""
with open("default_linker_script.ld") as f:
    script += f.read()

for i in range(bit_string_len):
    write_section("." + "0" * (i) + "1" + "0" * (bit_string_len - i - 1))

script += "}\n"

with open("linker_script.ld", "w") as f:
    f.write(script)
