import math
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import os

num_bits = 4096
e = (num_bits - 1) * 2
# n = getPrime(num_bits)
# while math.gcd(e, n-1) == 1: 
# 	n = getPrime(num_bits)
n = 665515140120452927777672138241759151799589898667434054796291409500701895847040006534274017960741836352283431369658890777476904763064058571375981053480910502427450807868148119447222740298374306206049235106218160749784482387828757815767617741823504974133549502118215185814010416478030136723860862951197024098473528800567738616891653602341160421661595097849964546693006026643728700179973443277934626276981932233698776098859924467510432829393769296526806379126056800758440081227444482951121929701346253100245589361047368821670154633942361108165230244033981429882740588739029933170447051711603248745453079617578876855903762290177883331643511001037754039634053638415842161488684352411211039226087704872112150157895613933727056811203840732191351328849682321511563621522716119495446110146905479764695844458698466998084615534512596477826922686638159998900511018901148179784868970554998882571043992165232556707995154316126421679595109794273650628957795546293370644405017478289280584942868678139801608538607476925924119532501884957937405840470383051787503858934204828174270819328204062103187487600845013162433295862838022726861622054871029319807982173856563380230936757321006235403066943155942418392650327854150659087958008526462507871976852849

# print("n = ", n)
# print(math.gcd(e, n-1))

with open("flag.txt","rb") as f:
    flag = f.read()

m = bytes_to_long(flag)
c = pow(m, e, n)
print(c)

with open("output.txt", "w") as f:
	f.write("e = {0}\n".format(e))
	f.write("n = {0}\n".format(n))
	f.write("c = {0}\n".format(c))
