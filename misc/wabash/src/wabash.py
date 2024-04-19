#!/usr/local/bin/python3

import os
import time

def wabash(command:str):
    command = command.split()
    for i in range(len(command)):
        command[i] = "wa"+command[i]
        command[i] = command[i].replace(";", "")
        command[i] = command[i].replace("`", "")
    return " ".join(command)

def slowprint(s):
    for c in s + '\n':
        print(c, end='', flush=True)
        time.sleep(0.1)

print(r'''                  _                       _      
 __ __ __ __ _   | |__    __ _     ___   | |_    
 \ V  V // _` |  | '_ \  / _` |   (_-<   | ' \   
  \_/\_/ \__,_|  |_.__/  \__,_|   /__/_  |_||_|  
_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| 
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
''')
slowprint("$ `bash`;")
print("sh: 1: wabash: not found")
while True:
    os.system(wabash(input("$ ")))