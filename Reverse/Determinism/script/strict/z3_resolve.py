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
# s.add(hash2_16(flags(0), flags(17)) == BitVecVal(31698, 16))
# s.add(low8(flags(17) ^ flags(18) == 9))
# s.add(low8(((flags[5] << 1) + LShR(flags[2], 1) ^ flags[15]) ) == 170)
# s.add(low8((flags[14]*(flags[7] + 3) ^ flags[5]*2) ) == 211)
# s.add(low8((flags[2]*(flags[4] + 3) ^ flags[11]*2) ) == 18)
# s.add(low8((flags[15] ^ flags[3]) + flags[4]*2 ) == 224)
# s.add(low8(((flags[14] << 1) + LShR(flags[4], 1) ^ flags[0]) ) == 186)
s.add(low8((flags[0] ^ flags[7]) ) == 115)
# s.add(low8((flags[16] ^ flags[7]) + flags[2]*2 ) == 182)
# s.add(low8((flags[11]*(flags[14] + 3) ^ flags[12]*2) ) == 38)
# s.add(low8(((flags[12] << 1) + LShR(flags[16], 1) ^ flags[7]) ) == 168)

# s.add(flags[0] == 67)
# s.add(flags[2] == 49)
# s.add(flags[11] == 104)
# s.add(flags[13] == 95)
# s.add(flags[0] == 67)
# s.add(flags[1] == 116)
# s.add(flags[2] == 49)
# s.add(flags[3] == 108)
# s.add(flags[4] == 95)
# s.add(flags[5] == 102)
# s.add(flags[6] == 76)
# s.add(flags[7] == 48)
# s.add(flags[8] == 119)
# s.add(flags[9] == 95)
# s.add(flags[10] == 116)
# s.add(flags[11] == 104)
# s.add(flags[12] == 51)
# s.add(flags[13] == 95)
# s.add(flags[14] == 101)
# s.add(flags[15] == 78)
# s.add(flags[16] == 100)
# s.add(low8(((flags[0] << 1) + LShR(flags[4], 1) ^ flags[14]) ) == 208)
# s.add(low8((flags[14] ^ flags[2]) ) == 84)
# s.add(low8((flags[0]*(flags[7] + 3) ^ flags[16]*2) ) == 145)
# s.add(low8((flags[1] ^ flags[2]) + flags[16]*2 ) == 13)
# s.add(low8((flags[11]*3 ^ flags[1] + flags[16]) + 17 ) == 241)
# s.add(low8((flags[10]*(flags[15] + 3) ^ flags[11]*2) ) == 100)
# s.add(low8((flags[8] ^ flags[1]) ) == 3)
# # # s.add(low8(hash2(flags[0],flags[13])  ==  58957)
# # # s.add(low8(hash2(flags[11],flags[2]) = 55732)
# s.add(low8((flags[4]*(flags[7] + 3) ^ flags[16]*2) ) == 37)
# s.add(low8((flags[4] ^ flags[10]) + flags[5]*2 ) == 247)
# s.add(low8((flags[9]*3 ^ flags[6] + flags[2]) + 17 ) == 113)
# s.add(low8((flags[3]*(flags[8] + 3) ^ flags[5]*2) ) == 180)
# s.add(low8(((flags[12] << 1) + LShR(flags[9], 1) ^ flags[6]) ) == 217)
# s.add(low8(((flags[5] << 1) + LShR(flags[2], 1) ^ flags[15]) ) == 170)
# s.add(low8((flags[14]*(flags[7] + 3) ^ flags[5]*2) ) == 211)
# s.add(low8((flags[2]*(flags[4] + 3) ^ flags[11]*2) ) == 18)
# s.add(low8((flags[15] ^ flags[3]) + flags[4]*2 ) == 224)
# s.add(low8(((flags[14] << 1) + LShR(flags[4], 1) ^ flags[0]) ) == 186)
# s.add(low8((flags[0] ^ flags[7]) ) == 115)
# s.add(low8((flags[16] ^ flags[7]) + flags[2]*2 ) == 182)
# s.add(low8((flags[11]*(flags[14] + 3) ^ flags[12]*2) ) == 38)
# s.add(low8(((flags[12] << 1) + LShR(flags[16], 1) ^ flags[7]) ) == 168)
# # s.add(low8(hash2(flags[10],flags[13])  == 5086)
# # s.add(low8((flags[2]*(flags[3] + 3) ^ flags[14]*2) ) == 245)
# # s.add(low8((flags[16] ^ flags[14]) ) == 1)
# # s.add(low8((flags[4] ^ flags[11]) + flags[2]*2 ) == 153)
# # s.add(low8((flags[13] ^ flags[9]) + flags[10]*2 ) == 232)
# # s.add(low8((flags[1]*(flags[7] + 3) ^ flags[14]*2) ) == 214)
# # s.add(low8(((flags[13] << 1) + LShR(flags[5], 1) ^ flags[7]) ) == 193)
# # s.add(low8((flags[1] ^ flags[11]) ) == 28)
# # s.add(low8(((flags[1] << 1) + LShR(flags[4], 1) ^ flags[11]) ) == 127)
# # s.add(low8((flags[8]*(flags[12] + 3) ^ flags[7]*2) ) == 122)
# # s.add(low8(((flags[9] << 1) + LShR(flags[15], 1) ^ flags[7]) ) == 213)
# # s.add(low8((flags[6] + flags[11] + flags[15] ^ flags[11]*3) ) == 58)
# # s.add(low8((flags[10]*3 ^ flags[0] + flags[12]) + 17 ) == 59)
# # s.add(low8(hash2(flags[6],flags[15])  ==  34907)
# # s.add(low8((flags[8] ^ flags[11]) ) == 31)
# # s.add(low8(((flags[5] << 1) + LShR(flags[13], 1) ^ flags[15]) ) == 181)
# # s.add(low8((flags[6] + flags[7] + flags[11] ^ flags[7]*3) ) == 116)
# # s.add(low8(((flags[0] << 1) + LShR(flags[3], 1) ^ flags[10]) ) == 200)
# # s.add(low8(hash2(flags[0],flags[11])  ==  18064)
# # s.add(low8(((flags[3] << 1) + LShR(flags[0], 1) ^ flags[15]) ) == 183)
# # s.add(low8((flags[3]*3 ^ flags[15] + flags[13]) + 17 ) == 250)
# # s.add(low8(((flags[10] << 1) + LShR(flags[11], 1) ^ flags[5]) ) == 122)
s.add(low8((flags[2]*3 ^ flags[7] + flags[10]) + 17 ) == 72)
# # s.add(low8((flags[14] + flags[8] + flags[7] ^ flags[8]*3) ) == 105)
# # s.add(low(hash2(flags[0],flags[2]) == 50141)
# # 44 hash2(flag[0],flag[2])==50141
# s.add(hash2_16(f(0), f(2)) == BitVecVal(50141, 16))
# # 44 hash2(flag[0],flag[2])==50141
# s.add(hash2_16(f(0), f(2)) == BitVecVal(50141, 16))

# --- optional: constrain flags to printable / alnum / underscore if you want:
# from string import ascii_lowercase, ascii_uppercase, digits
# allowed = [ord(c) for c in (ascii_lowercase+ascii_uppercase+digits+"_")]
# for i in range(17):
#     s.add(Or([f(i) == BitVecVal(v,8) for v in allowed]))

# Check satisfiability and (if sat) print model
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
    # print("Unsat core:", s.unsat_core())
    # print(s.assertions())