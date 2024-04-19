#!/usr/bin/python3

from math import log, ceil
from Crypto.Util.number import *
 # FIPS 186-4 Appendix A.1/A.2 compliant prime order q group and prime order p field
from Crypto.PublicKey import DSA as FFC
(p,q,g) = FFC.generate(2048).domain()

print("p ({}-bit)\t= {}".format(ceil(log(p,2)),p))
print("q ({}-bit)\t= {}".format(ceil(log(q,2)),q))
print("g ({}-bit)\t= {}".format(ceil(log(g,2)),g))
