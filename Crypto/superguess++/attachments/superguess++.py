from Crypto.Util.number import getPrime
from secrets import randbelow 
import signal

with open(flag.txt, rb) as f
    flag = f.read()

signal.alarm(300)

q = getPrime(182)
x = randbelow(q)
l = 2
T = []
U = []
for i in range(93)
    t = randbelow(q)
    u = (x  t - randbelow(q  l)) % q
    T.append(t)
    U.append(u)

print(fq = {q})
print(fT = {T})
print(fU = {U})

guess = int(input(x = ).strip()) 
if guess == x
    print(flag)
