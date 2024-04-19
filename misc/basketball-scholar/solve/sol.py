import os
import numpy as np
from stegano import lsb
from PIL import Image
import random
import math
import base64 

"""
Code mostly taken from this StackOverflow answer: 
https://stackoverflow.com/a/39225039
"""

# -----------------------------------------------------------

def Decode(src):

	img = Image.open(src, 'r')
	width, height = img.size
	array = np.array(list(img.getdata()))
	total_pixels = array.size // len(img.mode)
	hidden_bits = ""

	index = 0
	p = 2
	while p < total_pixels:
		for q in range(0, 3):
			hidden_bits += (bin(array[p][q])[2:][-1])
		index += 3
		p = index * width + (index + 2)

	hidden_bits = [hidden_bits[i:i + 8] for i in range(0, len(hidden_bits), 8)]

	message = ""
	for i in range(len(hidden_bits)):
		message += chr(int(hidden_bits[i], 2))
	return message

# -------------------------------------------------------

if __name__ == "__main__":
    cwd = os.getcwd()
    path = cwd + '/' + 'pete.png'
    decoded = Decode(path)
    print(decoded)
