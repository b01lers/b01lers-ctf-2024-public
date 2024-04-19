# Writeup for imagehost by hmmm

There's a path traversal in [`tokens.py`](./src/app/tokens.py), as `public_key.absolute().is_relative_to(Path.cwd())` doesn't account for `../`. Thus, we can control the location of the public key used to decode the JWT. The JWT is decoded using RS256, so we can't just point it to /dev/null like we could for HS256. Instead, we can attempt to upload a valid public key through the image uploading functionality.

However, we also need to bypass the `Image.open` check. We can concat a PNG file with a RSA public key—PNGs ignore anything after IEND, and [`PEM_read_bio_PrivateKey`](https://www.openssl.org/docs/manmaster/man3/PEM_read_bio_PrivateKey.html) ignores extra content.

Full solve script in [`solve/solve.py`](./solve/solve.py)

Image source: https://twitter.com/yo_draw/status/1335476129247813636
