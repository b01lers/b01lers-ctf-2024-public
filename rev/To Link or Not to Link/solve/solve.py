from elftools.elf.elffile import ELFFile


def section_sizes_to_bytestring(section_sizes):
    bitstring = ''.join(map(str, section_sizes))
    bytestring = b''.join(int(bitstring[i * 8: (i + 1) * 8], 2).to_bytes(1, byteorder='big') for i in range(len(bitstring) // 8))
    return bytestring

section_sizes = []

with open("key_object.o", 'rb') as elffile:
    for section in ELFFile(elffile).iter_sections():
        if "0" in section.name and "1" in section.name:
            section_sizes.append(section.data_size)

key_bytestring = section_sizes_to_bytestring(section_sizes)

section_sizes = []

with open("linked.elf", 'rb') as elffile:
    for section in ELFFile(elffile).iter_sections():
        if "0" in section.name and "1" in section.name and "calculate" not in section.name:
            section_sizes.append(section.data_size)

ct_bytestring = section_sizes_to_bytestring(section_sizes)

flag_bytestring = b""

for key, ct in zip(key_bytestring, ct_bytestring):
    flag_bytestring += (key ^ ct).to_bytes(1, byteorder='big')

print(flag_bytestring.decode())
