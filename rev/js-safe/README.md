# Writeup for js-safe by bronson113

[blog post](https://blog.bronson113.org/2024/04/15/b01lersctf-2024-author-writeup.html#js-safe)

```plaintext
Crack the safe...


`http://gold.b01le.rs:4006`
Solves: 84 solves / 355 points
```


When you visit the website, you'll see a numpad. Now let's try to click some button. You'll notice that it checks if you're number is correct when you've enter 6 "digits". Notice that the check is done of the front end, hence we have access to the full logic. Now, the source is un-readable, and some anti-debugging seems to be in place. One way is to go backward. You can find some mention of CryptoJS in the source file. We can "guess" that that's where our flag is decrypted and displayed. Right before that, there are a sequence of `&=` with a variable. This checks if the results are all true to then call our decrypted function. This should be the key to our solution.


Now after reconstructing all the constants from the obfuscated code, we can get a picture of how the password is check.


```
let pass = true;
pass&=(pw[4] == (pw[1] - 4));
pass&=(pw[1] == (pw[0] ^ 68));
pass&=(pw[0] == (pw[2] - 7));
pass&=(pw[3] == (pw[2] ^ 37));
pass&=(pw[5] == (pw[0] ^ 20));
pass&=(pw[4] == (pw[1] - 4));
pass&=(pw[0] == (pw[3] ^ 34));
pass&=(pw[0] == (pw[2] - 7));
pass&=(pw[0] == (pw[5] + 12));
pass&=(pw[2] == (pw[4] + 71));
pass&=(pw[2] == (pw[5] ^ 19));
pass&=(pw[5] == (pw[3] ^ 54));
pass&=(82 == (pw[3]));
```


We then retrieve the password by solving those constrains. This can be done with any sat solver, or by hand, since there are only 6 digits. The twist here is that the password isn't actually just digits, but contains letters as well. If you now entering the password to the function itself through `addToPassword` function, the program will decrypt the flag for us!


`bctf{345y-p4s5w0rd->w<}`

