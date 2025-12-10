import sys
import os
import hashlib


def pow():
    prefix = "rctf".encode()
    target = os.urandom(3).hex().encode()
    target_hash = hashlib.sha256(prefix + target).hexdigest()

    sys.stdout.write("=== Proof of Work Challenge ===\n")
    sys.stdout.write(f"Find a nonce such that SHA-256('{prefix.decode()}' + nonce) == {target_hash}\n")
    sys.stdout.write("nonce:")
    sys.stdout.flush()
    nonce = read_exactly(6).encode()
    data = prefix + nonce
    current_hash = hashlib.sha256(data).hexdigest()
    if current_hash == target_hash:
        sys.stdout.write("pow success!\n")
        sys.stdout.flush()
        return
    else:
        sys.stdout.write("pow failed!\n")
        sys.stdout.flush()
        exit(0)

def read_exactly(n):
    result = []
    remaining = n
    while remaining > 0:
        data = sys.stdin.read(remaining)
        if not data: 
            break
        result.append(data)
        remaining -= len(data)
    return ''.join(result)

pow()
sys.stdout.write("script size:\n")
sys.stdout.flush()
size = int(sys.stdin.readline().strip())
if size > 102400:
    sys.stdout.write("too large!\n")
    sys.stdout.flush()
    sys.exit(1)
sys.stdout.write("script:\n")
sys.stdout.flush()
script = read_exactly(size)
with open(sys.argv[1], 'w') as f:
    f.write(script)

os.system("/home/ctf/d8 --no-memory-protection-keys " + sys.argv[1])