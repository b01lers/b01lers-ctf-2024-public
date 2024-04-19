from types import CodeType
def x():pass
x.__code__ = CodeType(0,0,0,0,0,0,bytes.fromhex(input(">>> ")[:176]),(),(),(),'Δ','♦','✉︎',0,bytes(),bytes(),(),())
x()