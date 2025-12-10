import random
import hashlib
from z3 import *

FLAG_LEN = 17

flags = [BitVec(f"flag[{i}]", 8) for i in range(FLAG_LEN)]
s = Solver()

f = lambda i: flags[i]

# Helper: promote 8-bit to 32-bit for arithmetic/multiplication etc.
def Z32(x8):
    """Zero-extend an 8-bit BitVec to 32-bit."""
    return ZeroExt(24, x8)

def LShR32(x32, sh):
    return LShR(x32, sh)

# 16-bit hash2 implementation using a 32-bit mix then take low 16 bits.
# This mirrors the mix32/hash2_16 design: pack a<<8 | b, mix, return lower 16 bits.
def hash2_16(a8, b8):
    a32 = Z32(a8)
    b32 = Z32(b8)
    key = (a32 << 8) | b32           # 32-bit value with a in high 8 bits, b in low 8 bits

    # mix32 (splitmix-like) using 32-bit BitVec arithmetic (wraps naturally)
    # constants written as 32-bit BitVecVals
    k = key
    k = (k + BitVecVal(0x9E3779B9, 32)) & BitVecVal(0xFFFFFFFF, 32)
    k = (k ^ LShR(k, 16)) * BitVecVal(0x85EBCA6B, 32)
    k = k & BitVecVal(0xFFFFFFFF, 32)
    k = (k ^ LShR(k, 13)) * BitVecVal(0xC2B2AE35, 32)
    k = k & BitVecVal(0xFFFFFFFF, 32)
    k = k ^ LShR(k, 16)
    # return low 16 bits
    return Extract(15, 0, k)

def low8(expr32):
    return Extract(7, 0, expr32)


for fs in flags:
    s.add(UGE(fs,32))
    s.add(UGE(126,fs))

s.add(hash2_16(f(0), f(2)) == BitVecVal(50141, 16))
s.add(hash2_16(f(0), f(13)) == BitVecVal(58957, 16))
s.add(hash2_16(f(11), f(2)) == BitVecVal(55732, 16))
s.add(hash2_16(f(10), f(13)) == BitVecVal(5086, 16))
s.add(hash2_16(f(6), f(15)) == BitVecVal(34907, 16))

s.add(low8(((flags[0] << 1) + LShR(flags[4], 1) ^ flags[14]) ) == 208)
s.add(low8((flags[14] ^ flags[2]) ) == 84)
s.add(low8((flags[0]*(flags[7] + 3) ^ flags[16]*2) ) == 145)
s.add(low8((flags[1] ^ flags[2]) + flags[16]*2 ) == 13)
s.add(low8((flags[11]*3 ^ flags[1] + flags[16]) + 17 ) == 241)
s.add(low8((flags[10]*(flags[15] + 3) ^ flags[11]*2) ) == 100)
s.add(low8((flags[8] ^ flags[1]) ) == 3)
s.add(low8((flags[4]*(flags[7] + 3) ^ flags[16]*2) ) == 37)
s.add(low8((flags[4] ^ flags[10]) + flags[5]*2 ) == 247)
s.add(low8((flags[9]*3 ^ flags[6] + flags[2]) + 17 ) == 113)
s.add(low8((flags[3]*(flags[8] + 3) ^ flags[5]*2) ) == 180)
s.add(low8(((flags[12] << 1) + LShR(flags[9], 1) ^ flags[6]) ) == 217)
s.add(low8((flags[0] ^ flags[7]) ) == 115)
s.add(low8((flags[2]*3 ^ flags[7] + flags[10]) + 17 ) == 72)
res = s.check()
print("Solver result:", res)
if res == sat:
    m = s.model()
    out = [m.evaluate(f(i)).as_long() for i in range(17)]
    print("flag bytes (decimal):", out)
    # print as hex and ascii (if printable)
    print("flag bytes (hex):", [hex(x) for x in out])
    try:
        print("flag as ascii (non-printable shown as \\x..):",
              "".join(chr(x) if 32 <= x < 127 else ("\\x%02x" % x) for x in out))
    except Exception as e:
        print("Could not render ascii:", e)
else:
    print("Unsat or unknown; no model printed.")