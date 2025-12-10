from Crypto.Util.number import getPrime, GCD, bytes_to_long
from secrets import token_bytes
import os
import signal

RCTF_FLAG = os.environ.get("FLAG", "RCTF{fake_flag}")

while True:
    p = getPrime(1024)
    q = getPrime(1024)
    e = 0x101
    if GCD((p - 1) * (q - 1), e) == 1:
        break
N = p * q

flag = token_bytes(68)
assert len(flag) == 68

f, l, ag = flag[:17], flag[17:34], flag[34:]
f, l, ag, flag = map(bytes_to_long, (f, l, ag, flag))

f_enc = pow(f, e, N)
l_enc = pow(l, e, N)
ag_enc = pow(ag, e, N)
flag_enc = pow(flag, e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{f_enc = }")
print(f"{l_enc = }")
print(f"{ag_enc = }")
print(f"{flag_enc = }")

signal.alarm(10)
guess = bytes.fromhex(input("🤔 flag: ").strip()).decode()
if guess == hex(flag)[2:]:
    print(f"🎉 Correct! Here is your RCTF flag: {RCTF_FLAG}")
