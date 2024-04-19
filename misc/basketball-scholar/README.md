# Writeup for basketball-scholar by FlaggnGoose

## Add your writeup here!

In <code>pete.png</code> file, there is a sequence of brighter pixels aligned along the diagonal starting from the 2nd pixel (counting from zero) of the file. So, you just need to scan those pixels. 

Using LSB detectors such as <a href="https://github.com/livz/cloacked-pixel">cloaked-pixel</a>, we can figure out that LSB steganography was likely used on this picture.

```python
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
    # b'VGhpcyBIVyB3YXMgdG9vIGVhc3kgYmN0ZntHb19iMDFsZXJDVEZtYWtlcnMhfQ==\n'èÿLÀBÙßõ?ä
```
And <code>VGhpcyBIVyB3YXMgdG9vIGVhc3kgYmN0ZntHb19iMDFsZXJDVEZtYWtlcnMhfQ== </code> is <code>This HW was too easy bctf{Go_b01lerCTFmakers!}</code> in base64.