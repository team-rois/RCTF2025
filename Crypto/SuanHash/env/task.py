from __future__ import annotations
from suanhash import SuanHash
import os

ROUNDS = 20 * 25
QUERIES_PER_ROUND = 4

def suanhash_fn():
    base = SuanHash()
    return lambda msg: (lambda h=base.copy(): (h.update(msg), h.hexdigest())[1])()

print(
    """
███████╗██╗   ██╗ █████╗ ███╗   ██╗██╗  ██╗ █████╗ ███████╗██╗  ██╗
██╔════╝██║   ██║██╔══██╗████╗  ██║██║  ██║██╔══██╗██╔════╝██║  ██║
███████╗██║   ██║███████║██╔██╗ ██║███████║███████║███████╗███████║
╚════██║██║   ██║██╔══██║██║╚██╗██║██╔══██║██╔══██║╚════██║██╔══██║
███████║╚██████╔╝██║  ██║██║ ╚████║██║  ██║██║  ██║███████║██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""
)
print(f"💪 Survive {ROUNDS} rounds to get the flag!\n", flush=True)

for rnd in range(1, ROUNDS + 1):
    suan_fn = suanhash_fn()

    print(f"[Round {rnd}]", flush=True)

    seen = {}      # hash -> msg
    collided = False

    for q in range(1, QUERIES_PER_ROUND + 1):
        msg = bytes.fromhex(input(f"💬 MSG {q} (hex): ").strip())
        h = suan_fn(msg)
        print(f"H = {h}", flush=True)
        if h in seen and seen[h] != msg:
            collided = True
        else:
            seen[h] = msg

    if not collided:
        print("❌ No hash collision in this round. Game over.")
        exit(-1)
    else:
        print("✅ Hash collision found! Next round.\n", flush=True)

print(f"🎉 Nice! Here is your flag: {os.environ.get('FLAG', 'RCTF{fake_flag}')}")
