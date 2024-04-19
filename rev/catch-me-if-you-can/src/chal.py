import os
import sys
import random

match (os.urandom(8), 1):
    case (b"OwO_QuQ_", _): 
        print("Oops! something went wrong, run again")
    case (AAAseed, AAAiter_count): 
        print("You're Lucky")
        print("Here is your flag: ", end="")

AAAresult = []

AAAt0 = []
AAAt1 = []
AAAt2 = []

AAAt0.append(96)
AAAt0.append(98)
AAAt2.append(198)
AAAt2.append(31)
AAAt0.append(68)
AAAt0.append(160)
AAAt1.append(180)
AAAt1.append(165)
AAAt1.append(115)
AAAt1.append(203)
AAAt0.append(172)
AAAt1.append(177)
AAAt2.append(60)
AAAt0.append(115)
AAAt1.append(17)
AAAt1.append(166)
AAAt0.append(20)
AAAt0.append(108)
AAAt1.append(196)
AAAt0.append(25)
AAAt1.append(255)
AAAt2.append(167)
AAAt2.append(17)
AAAt2.append(1)
AAAt2.append(132)
AAAt0.append(122)
AAAt1.append(127)
AAAt2.append(106)
AAAt2.append(195)
AAAt0.append(208)
AAAt2.append(19)
AAAt1.append(70)
AAAt2.append(38)
AAAt2.append(151)
AAAt1.append(172)
AAAt1.append(55)
AAAt0.append(71)
AAAt1.append(11)
AAAt0.append(158)
AAAt0.append(63)
AAAt1.append(204)
AAAt1.append(20)
AAAt2.append(203)
AAAt2.append(163)
AAAt2.append(211)
AAAt2.append(27)
AAAt2.append(73)
AAAt0.append(233)
AAAt2.append(98)
AAAt0.append(59)

AAAtarget = AAAt0+AAAt1+AAAt2


for AAAi in range(0, 50):
    AAAbase = 3
    try:
        for AAAj in range(25, 50):
            random.seed(AAAj / (AAAj-AAAi))
        AAAiter_count = AAAbase ** (AAAi)
    except ZeroDivisionError:
        AAAiter_count = AAAiter_count ** AAAbase
    finally:
        AAAiter_count = AAAbase ** (AAAi)
        AAAa, AAAb, AAAc = 1, 2, 3
        AAAmod = 1000000007
        # the original not_fibonacci
        for AAAj in range(AAAiter_count):
            match (AAAj%3, AAAj%5):
                case (0, 0):
                    AAAa, AAAb, AAAc = AAAb, AAAc, (AAAa)%AAAmod
                case (0, _):
                    AAAa, AAAb, AAAc = AAAb, AAAc, (AAAa+AAAb+AAAc)%AAAmod
                case (1, _):
                    AAAa, AAAb, AAAc = AAAb, AAAc, (AAAa+AAAb)%AAAmod
                case (2, _):
                    AAAa, AAAb, AAAc = AAAb, AAAc, (AAAa+AAAc)%AAAmod

        AAAflag = (AAAtarget[AAAi]) ^ (AAAa & 0xff)
        print(chr(AAAflag), end="")
        sys.stdout.flush()
