import sys
import base64

file = sys.argv[1]

with open(file, 'rb') as f:
    data = f.read()
    b64data = base64.b64encode(data)

    with open(f'{file}.enc', 'wb') as out:
        out.write(b64data)

