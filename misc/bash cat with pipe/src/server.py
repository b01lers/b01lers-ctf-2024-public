#!/usr/local/bin/python3

import subprocess

prefix = 'cat with |'
ban_list = ['?', '||', '&&', 'flag', ';', '-', '[', ']', '*', '"', "'", '\\', '`', '$']


def run_input():
    inp = input(f'$ {prefix} ')

    for banned in ban_list:
        if banned in inp:
            print(f'disallowed: {banned}')
            return

    subprocess.call(f'{prefix} {inp}', shell=True, executable='/bin/bash')


while True:
    run_input()
