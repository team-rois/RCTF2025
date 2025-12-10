import os
from sage.all import set_random_seed, random_matrix, Zmod
import signal

FLAG = os.environ.get("FLAG", "RCTF{fake_flag}")
MACHINE_LIMIT = 19937

secret = os.urandom(64)
set_random_seed(int.from_bytes(secret, 'big'))

def random_machine(mod: int, nrow: int, ncol: int) -> bytes:
    outs = (random_matrix(Zmod(mod), nrow, ncol).list())
    print("🤖 Machine output:", outs)
    
print("✨ Yet Another Mersenne Twister Game ✨")
print("🤔 Sagemath is just an extension of python, right?")

signal.alarm(60)
mod, nrow, ncol = map(int, input("✨ Enter mod and dimension (space separated): ").split())
if not(mod > 1 and nrow > 0 and ncol > 0):
    print("❌ Invalid input!")
    exit()
    
nbits = (mod - 1).bit_length()
leaked = nbits * nrow * ncol
if leaked > MACHINE_LIMIT:
    print("💥 The machine has broken down due to too much randomness being extracted!")
    exit()
random_machine(mod, nrow, ncol)

guess = bytes.fromhex(input("🤔 secret (hex): ").strip())
if guess == secret:
    print(f"🎉 Correct! Here is your flag: {FLAG}")