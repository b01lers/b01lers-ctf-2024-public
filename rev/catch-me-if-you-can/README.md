# Writeup for catch-me-if-you-can by bronson113

[Blog Post](https://blog.bronson113.org/2024/04/15/b01lersctf-2024-author-writeup.html#catch-me-if-you-can)



```plaintext
I give you this flag generator, but it's too slow. You need to speed up to catch me =D


Solves: 6 solves / 493 points
```


We are given a pyc file, but pycdc can't decompile it. It seems like this file uses some sort of match statements, so pycdc can't decompile it back into python source. The other things is that all the variable names seems to be obfuscated.


After some reversing, you'll notice that the file clearly splits into two part.
A array is first constructed, acting like a key of some sort.
Then, each value are xored with a value that's generated using a complicated algorithm. However, the later the character, the longer the algorithm seems to take to finish. So our goal is to speed up this algorithm.


Notice that there is a weird try-except-finally block in the script. In fact, the challenge is intentionally triggering a divide by zero exception, and used that to change the program flow. After some de-obfuscation, the control flow looks like (with i being the current loop id):


```python
try:
  for j in range(25, 50):
    if j/(j-i) == 1: random.seed(j)
  n = 3 ** i
except:
  n = n ** 3
finally:
  n = 3 ** i # *This line shouldn't be here
  some_alg(n) # apply that function n iterations to get our key
```


> \*: The given program file actually won't print out the full flag, which I only discover after the competition ends.
> Seems like 6 teams guessed my intention and still end up with a solution. This is an oversight on my part, as the encoded flag is generated in another script without that.


Now here is the pseudocode of the algorithm:


```python
def some_alg(n):
    a, b, c = 1, 2, 3
    mod = 1000000007
    for i in range(n):
        match (i%3, i%5):
            case (0, 0):
                a, b, c = b, c, (a)%mod
            case (0, _):
                a, b, c = b, c, (a+b+c)%mod
            case (1, _):
                a, b, c = b, c, (a+b)%mod
            case (2, _):
                a, b, c = b, c, (a+c)%mod
    return a
```


The algorithm is a similar to a fibonacci sequence (imo), but more complicated. Firstly, the state transition is not fixed, but in a fizzbuzz like manner. In addition, three previous states are used to derive the next state. Thankfully, all transition is modded, so the result won't grow extremely large.


Despite the difference to the normal fibonacci sequence, you can still model 15 iterations of this algorithm as a transition matrix, and use repeated squaring on that matrix to get results faster.
However, when the iteration count is too high (as it's expected to go to $3^{25^{3\times 25}}$), The power itself is hard to compute. The trick is to reduce this using the multiplicative order of the matrix, which turns out to be our mod squared, and get the result back really fast.
You still need to be ware of some minor details though, since the matrix represents 15 iterations, you'll need to be careful when working with the remainders. Personally I did the iteration count mod ${15\times mod^2}$ to avoid the issue, but there might be some other ways as well. I know that some teams used some very different modulo and still get the same result (like mod+1).


`bctf{we1rd_pyth0nc0d3_so1v3_w1th_f4s7_M47r1x_Mu1t}`


```python
import sys
import random


target = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]


mod = 1000000007
F = GF(mod)
transitionA = matrix(F, [
        [0, 1, 0],
        [0, 0, 1],
        [1, 1, 1]
        ]).T
transitionB = matrix(F,[
        [0, 1, 0],
        [0, 0, 1],
        [1, 1, 0]
        ]).T
transitionC = matrix(F,[
        [0, 1, 0],
        [0, 0, 1],
        [1, 0, 1]
        ]).T
transitionD = matrix(F,[
        [0, 1, 0],
        [0, 0, 1],
        [1, 0, 0]
        ]).T


def gen_remain(x):
    total_transition = matrix.identity(F, 3)
    for i in range(x):
        if i%5 == 0 and i%3 == 0:
                total_transition = total_transition * transitionD
        elif i%3 == 0:
            total_transition = total_transition * transitionA
        elif i%3 == 1:
            total_transition = total_transition * transitionB
        else:
            total_transition = total_transition * transitionC
    return total_transition






T = gen_remain(15)
initial = vector(F, [1, 2, 3])
order = T.multiplicative_order()
F2 = Zmod(order*15)


def not_fibonacci(count):
    return int((initial * (T**(int(count)//15)) * gen_remain(int(count)%15))[0])


base = 3


result = []
for i in range(0, 50):
    try:
        for j in range(25, 50):
            random.seed(j / (j-i))
        iter_count = base ** (i)
    except ZeroDivisionError:
        iter_count = F2(iter_count ** base)
    finally:
        key = not_fibonacci(iter_count)


        flag = (target[i]) ^^ (key & 0xff)
        print(chr(flag), end="")
        sys.stdout.flush()
```



