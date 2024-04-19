# Writeup for TeXnically... by FlaggnGoose

## Add your writeup here!

We start by typing some random LaTeX commands (e.g., `\texttt{b01ler up!}` as provided). The response suggests that we were supposed to get something, but apparently we are not getting anything. 

The response from the server was likely hidden during the compile. The challenge says "you can program with LaTeX" and "program that hides the flag" in its description. With that in mind, looking at the `server.py`, we see that our tex file contains the line `\newif\iflong` which defines a new Boolean variable `\long` in LaTeX.

Trying `\longtrue`, we get a bunch of Lorem Ipsum. But at the bottom, we see the sentence "Wait! I am not done yet! Keep scrolling please!" and somewhere after that sentence, we see the content of Lorem Ipsum mixed with the page numbering "Page 1." This implies that the output was so long but somehow instead of moving to the next page, it just overflew in the same page. So we can try moving the output above a little bit, say, by `\longtrue \vspace{-15cm}` command. Then there is the flag!