#!/bin/bash
python3.10 obfuscate.py
python3.10 -m py_compile chal_obfuscated.py
mv __pycache__/chal_obfuscated.cpython-310.pyc chal.pyc
