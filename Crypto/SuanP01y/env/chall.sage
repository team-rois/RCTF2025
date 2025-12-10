from sage.all import GF, ZZ, sample, gcd, PolynomialRing
from Crypto.Cipher import AES
from hashlib import md5
import os

r, d = 16381, 41
R.<x> = PolynomialRing(GF(2))
S.<X> = R.quo(x^r - 1)

def suan_p01y(nt, db):
    return sum(x^i for i in set(sample(range(db+1), nt)))

while True:
    t = [suan_p01y(d, r//3) for _ in range(2)]
    if gcd(t[0], t[1]) != 1:
        continue
    h = [(ti * X^ZZ.random_element(r)) for ti in t]
    if h[0].is_unit():
        break

with open("output.txt", "w") as f:
    f.write(f"hint = {h[1] / h[0]}\n")
    f.write(
        AES.new(
            key=md5(str(h[0]).encode()).digest(),
            nonce=b"suanp01y",
            mode=AES.MODE_CTR
        ).encrypt(os.environ.get("FLAG", "RCTF{fake_flag}").encode()).hex()
    )
