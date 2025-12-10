import os
from sage.all import set_random_seed, random_matrix, Zmod, ZZ, shuffle
import signal
FLAG = os.environ.get("FLAG", "RCTF{fake_flag}")
secret = os.urandom(64)
set_random_seed(int.from_bytes(secret, 'big'))

N_RUNS = 3
MACHINE_LIMIT = 16400
IS_BROKEN = False

def shuffle_int(num: int, nbits: int):
    bits = ZZ(num).digits(base = 2, padto = nbits)
    shuffle(bits)
    return ZZ(bits, 2)

def random_machine(mod: int, nrow: int, ncol: int) -> bytes:
    global IS_BROKEN
    nbits = (mod - 1).bit_length()
    outs = random_matrix(Zmod(mod), nrow, ncol).list()
    if IS_BROKEN:
        outs = [shuffle_int(x, nbits) for x in outs]
        shuffle(outs)
    print("🤖 Machine output:", outs)
    
print("✨ Yet Another Mersenne Twister Game ✨")
print("🤔 However, the random machine will break down if you extract too much randomness from it.")

leaked = 0
signal.alarm(60)
for i in range(N_RUNS):
    mod, nrow, ncol = map(int, input("✨ Enter mod and dimensions (space separated): ").split())
    if not(mod > 1 and nrow > 0 and ncol > 0):
        break
    nbits = (mod - 1).bit_length()
    leaked += nbits * nrow * ncol
    if leaked > MACHINE_LIMIT and IS_BROKEN == False:
        IS_BROKEN = True
        print("💥 The machine has broken down due to too much randomness being extracted!")
    random_machine(mod, nrow, ncol)

guess = bytes.fromhex(input("🤔 secret (hex): ").strip())
if guess == secret:
    print(f"🎉 Correct! Here is your flag: {FLAG}")