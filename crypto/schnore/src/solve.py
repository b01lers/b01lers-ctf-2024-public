#!/usr/bin/python3.8

import math
from pwn import *
import sys
from Crypto.Util import number
from Crypto.Random import random
from Crypto.Hash import SHA512

# FIPS 186-4 Appendix A.1/A.2 compliant prime order q group and prime order p field
p = 32148430219533869432664086521225476372736462680273996089092113172047080583085077464347995262368698415917196323365668601969574610671154445337781821758494432339987784268234681352859122106315479086318464461728521502980081310387167105996276982251134873196176224643518299733023536120537865020373805440309261518826398579473063255138837294134742678213639940734783340740545998610498824621665838546928319540277854869576454258917970187451361767420622980743233300167354760281479159013996441502511973279207690493293107263225937311062981573275941520199567953333720369198426993035900390396753409748657644625989750046213894003084507
q = 25652174680121164880516494520695513229510497175386947962678706338003
g = 23174059265967833044489655691705592548904322689090091191484900111607834369643418104621577292565175857016629416139331387500766371957528415587157736504641585483964952733970570756848175405454138833698893579333073195074203033602295121523371560057410727051683793079669493389242489538716350397240122001054430034016363486006696176634233182788395435344904669454373990351188986655669637138139377076507935928088813456234379677586947957539514196648605649464537827962024445144040395834058714447916981049408310960931998389623396383151616168556706468115596486100257332107454218361019929061651117632864546163172189693989892264385257

A = 30210424620845820052071225945109142323820182565373787589801116895962027171575049058295156742156305996469210267854774935518505743920438652976152675486476209694284460060753584821225066880682226097812673951158980930881565165151455761750621260912545169247447437218263919470449873682069698887953001819921915874928002568841432197395663420509941263729040966054080025218829347912646803956034554112984570671065110024224236097116296364722731368986065647624353094691096824850694884198942548289196057081572758803944199342980170036665636638983619866569688965508039554384758104832379412233201655767221921359451427988699779296943487

#  https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
def modp_qr(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned if no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m
def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls



# Or use b01lers CTF URL and port
nc = remote("127.0.0.1", 5093)

nc.recvuntil(b"a + cx = ")
# We don't know x, and we don't have to listen to the protocol :)
z = random.randrange(1,p)
nc.sendline(str(z).encode())

# Verifier sleepby and forgot to ask for X. We can work with this!
nc.recvuntil(b'X = ')

# Compute the same challenge the verifier will
h = SHA512.new(truncate="256")
h.update(number.long_to_bytes(g) + number.long_to_bytes(p) + number.long_to_bytes(A))
c = number.bytes_to_long(h.digest()) % p

# Adaptive attacker knows random (A,z) it chose & associated challenge c by now,
# so X is the only unknown. Rearrange verification equation to solve for public key X!
# g^z ?= A * X^c
# X := (A^{-1} * g^z)^(c^{-1} mod phi(p)) mod p
# or X = (g^z / A)^(1/c mod p-1) mod p
phip = p - 1
# Value of hash challenge c isn't guaranteed to be divisible modulo phi(p) = p-1 to compute X, however...
# We can observe that gcd(c, p-1) = 2 != 1 (i.e. shares common factor 2), so c isn't directly invertible in the exponent
# But we can at least compute c^{-1}' such that (c/2)c^{-1}' = 1 mod (p-1)/2
factors = math.gcd(c, phip)
print("gcd(c, p-1) = ", factors)
cinvp = pow(c // factors, -1, phip // factors)
# We get most of the way to computing X by appling this:
# X' := (A^{-1} * g^z)^(c^{-1}' mod p-1) mod p
# X' = (g^z / A)^(2/c mod p-1) mod p = X^2 mod p
Z = pow(g, z, p)
Ainv = pow(A, -1, p)
Xprime = pow(Ainv * Z, cinvp, p)

# See above -- we have X' = X^2, now we simply need "square root" (quadratic residue) of X^2.
# And so, if we find the quadratic residues of X', we have two candidates to try.
# Use Tonelli-Shanks to find the first...
Xqr1 = modp_qr(Xprime, p) % p
# ... and if we know one we know the other, since (p-X)^2 = p^2 - 2pX + X^2 = X^2 mod p
Xqr2 = (p-Xqr1) % p

#X = pow(Z * Ainv, cexpinv, p)
# But the first one works in this example.
nc.sendline(str(Xqr1).encode())

# Flag!
nc.recvuntil(b'> ')
print(nc.recv().decode().strip())
nc.interactive()
