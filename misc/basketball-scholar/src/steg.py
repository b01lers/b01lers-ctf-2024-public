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
def Encode(src, message, dest):

	img = Image.open(src, 'r')
	width, height = img.size
	array = np.array(list(img.getdata()))
	total_pixels = array.size // len(img.mode)
	b_message = ''.join([format(ord(i), "08b") for i in message])
	req_pixels = len(b_message)

	if req_pixels > total_pixels or req_pixels > min(width, height):
		print("Need larger file size")

	else:
		index = 0
		p = 0
		j = 0
		while index < req_pixels:
			p = j * width + (j + 2)
			for q in range(0, 3):
				if index < req_pixels:
					array[p][q] = int(bin(array[p][q])[2:9] + b_message[index], 2)
					index += 1
			j += 3

	array = array.reshape(height, width, len(img.mode))
	enc_img = Image.fromarray(array.astype('uint8'), img.mode)
	enc_img.save(dest)

# -------------------------------------------------------

if __name__ == "__main__":
    cwd = os.getcwd()
    dest = cwd + '/pete-original.png'
    entry_name = "hw_answer.txt"
    with open(cwd + '/' + entry_name, 'rb') as f:
    	encode_string = f.read()
    new_path = cwd + '/' + 'pete.png'
    Encode(dest, str(encode_string), new_path)
