
## writeup

### 题目分析

打开二进制，运行之后会发现需要需要传入参数
```
usage: ./Determinism path.txt
```

此处简单逆向，会发现程序最多读入1024个字符。然后可以看到，另一个函数约束我们读入的flag长度为17字节

主要逻辑位于`sub_11E920`，可以看到里面会将我们之前读入的path在循环中依次读入，然后传入这个`walk_step`(位于0x11E7A0)
```C

    for ( j = 0LL; j != 16; ++j )
      *((_BYTE *)a3 + j) = ~byte_182010[j];
    size = 0LL;
    exec_buff = sub_11F760(v8, off_9A6960[v7], (__int64)a3, &size);
    walk_step(exec_buff, size, (__int64)state, state[2], *iter_path);
```

然后可以发现，这个程序里面有两个解密算法，其中在`sub_11EE30`位置的是TEA，在`sub_11F760`位置的是AES，然后这两个解密算法分别解密了数组`off_934CA0`和`off_F318E0`位置的数据，这两个位置的数据最终会在`sub_11E620`和`sub_11E7A0`被当作可执行代码执行。

其中，我们可以发现

 - 程序运行的时候，使用一个栈上的类似全局变量来传递一些基本变量（这里定义这个全局变量名字为state），例如【下一个要运行的数组的下标】
 - sub_11E620 接收我们传入的flag
 - sub_11E7A0 接受我们输入的path

当完成上述运行后，全局变量state会用来检查一个类似状态的值，如果为2，之后会检查一个位置的值和一个全局对象是否相等。之后还会检查包括一个类似hash的结果
 ```C
 if ( LODWORD(state[0]) == 2 )
    {
      if ( state[1] == qword_5CDCC753BC88 )
      {
        if ( !LODWORD(state[131]) )
          goto LABEL_24;
        v11 = 0x14650FB0739D0383LL;
        do
        {
          v12 = *((int *)v1 + 6);
          v1 = (__int64 *)((char *)v1 + 4);
          v13 = v11 ^ v12;
          v11 = 0x100000001B3LL * v13;
        }
        while ( (__int64 *)((char *)state + 4 * SLODWORD(state[131])) != v1 );
```

于是可以猜测逻辑：我们需要通过让代码经过这些函数，然后将我们的`[0]`位置的值凑成2，`[1]`位置的值凑成指定的答案，并且其中的一个答案hash满足不标志。


使用动态调试，可以看到在`sub_11E620`函数处解来的代码逻辑如下：
```C
__int64 __fastcall sub_7C45AF14A000(__int64 a1, char *like_flag)
{
  int v2; // eax
  unsigned int v4; // [rsp+28h] [rbp-8h]
  unsigned int v5; // [rsp+28h] [rbp-8h]

  if ( *(_DWORD *)a1 == 1 )
  {
    *(_QWORD *)(a1 + 8) += 9030LL;
    if ( *(_DWORD *)(a1 + 1048) <= 0x3FFu )
    {
      v2 = *(_DWORD *)(a1 + 1048);
      *(_DWORD *)(a1 + 1048) = v2 + 1;
      *(_DWORD *)(a1 + 4 * (v2 + 4LL) + 8) = 9030;
    }
  }
  if ( *(_DWORD *)a1 )
  {
    if ( *(_DWORD *)a1 == 1 )
    {
      v4 = (((unsigned __int8)like_flag[8] << 8) | (unsigned __int8)like_flag[10]) - 1640531527;
      v5 = -1028477387 * ((-2048144789 * (v4 ^ HIWORD(v4))) ^ ((-2048144789 * (v4 ^ HIWORD(v4))) >> 13));
      if ( (HIWORD(v5) ^ (unsigned __int16)v5) == 0xBDF7 )
        *(_DWORD *)(a1 + 4) = 1;
      else
        *(_DWORD *)(a1 + 4) = 2;
    }
  }
  else
  {
    *(_DWORD *)(a1 + 4) = 0;
  }
  *(_DWORD *)(a1 + 16) = 1;
  return 0LL;
}
```
而在`sub_11E7A0`函数处解开的代码逻辑如下：

```C
__int64 __fastcall sub_7C45AF14A000(_DWORD *a1, __int64 a2, char a3)
{
  __int64 result; // rax
  unsigned int v4; // [rsp+14h] [rbp-1Ch]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( (a3 & 1) != 0 )
  {
    if ( !*a1 )
      *a1 = 1;
  }
  else if ( *a1 == 1 )
  {
    *a1 = 2;
    result = 0xFFFFFFFFLL;
    goto LABEL_10;
  }
  if ( (a3 & 2) != 0 )
    v4 = 5;
  else
    v4 = 4;
  a1[4] = v4;
  ++a1[5];
  result = v4;
LABEL_10:
  if ( v5 != __readfsqword(0x28u) )
    return MEMORY[0x7C45AEA8D247]();
  return result;
}
```

大致分析，可以猜测，程序分为两种执行逻辑

 - 一个专门用来约束flag的执行逻辑，并且会修改state中存放的一个疑似**总和**的值，并且这个对象本身似乎也存放了一个指定的值，state同样会存放这个值。对于这个解开的代码，我们可以假定它叫做Code
 - 一个根据我们输入的path，决定state中下一个调用的函数下标的值的逻辑，而且这个下标似乎总是2条路径。这种路径，我们可以假定他是Edge

结合前面的逻辑，我们可以得出一个初步的结论

 - 程序Code中包含权重Value，而且会有一个类似 state.sum += Value的逻辑。我们需要保证我们的state.sum 为我们题目的指定值
 - state中包含类似path的概念，程序会计算path中的所有答案的hash，这样就能保证答案的唯一
 - Code之间用Edge相连，Edge中存放了当前Code能够前往的路径（根据题目描述，能够猜测这个路径大概率只有两条）

于是我们可以编写idapython，将这些节点权重和对应的边关系全部拿下来：
```python
import idaapi
import idc
import ida_bytes
import ida_funcs

from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ----------------------------
# Utility: PKCS7 填充（通用）
# ----------------------------
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding bytes")
    return data[:-pad_len]

# ----------------------------
# TEA (Tiny Encryption Algorithm)
# 64-bit block (two 32-bit words), 128-bit key (four 32-bit words)
# ----------------------------
def _u32(x: int) -> int:
    return x & 0xFFFFFFFF

def tea_encrypt_block(v0: int, v1: int, k: Tuple[int,int,int,int], rounds: int = 32) -> Tuple[int,int]:
    sum_ = 0
    delta = 0x9E3779B9
    for _ in range(rounds):
        sum_ = _u32(sum_ + delta)
        v0 = _u32(v0 + (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1])))
        v1 = _u32(v1 + (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3])))
    return v0, v1

def tea_decrypt_block(v0: int, v1: int, k: Tuple[int,int,int,int], rounds: int = 32) -> Tuple[int,int]:
    delta = 0x9E3779B9
    sum_ = _u32(delta * rounds)
    for _ in range(rounds):
        v1 = _u32(v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3])))
        v0 = _u32(v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1])))
        sum_ = _u32(sum_ - delta)
    return v0, v1

def tea_encrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("TEA key must be 16 bytes")
    # key as four u32
    k = tuple(int.from_bytes(key[i*4:(i+1)*4], 'big') for i in range(4))
    data = pkcs7_pad(data, 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        v0 = int.from_bytes(block[0:4], 'big')
        v1 = int.from_bytes(block[4:8], 'big')
        e0, e1 = tea_encrypt_block(v0, v1, k)
        out += e0.to_bytes(4, 'big') + e1.to_bytes(4, 'big')
    return bytes(out)

def tea_decrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("TEA key must be 16 bytes")
    if len(data) % 8 != 0:
        raise ValueError("ciphertext length must be multiple of 8")
    k = tuple(int.from_bytes(key[i*4:(i+1)*4], 'big') for i in range(4))
    out = bytearray()
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        v0 = int.from_bytes(block[0:4], 'big')
        v1 = int.from_bytes(block[4:8], 'big')
        d0, d1 = tea_decrypt_block(v0, v1, k)
        out += d0.to_bytes(4, 'big') + d1.to_bytes(4, 'big')
    return pkcs7_unpad(bytes(out), 8)



def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """AES-128 ECB 模式加密（带 PKCS#7 填充）"""
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, AES.block_size)  # AES.block_size == 16
    ciphertext = cipher.encrypt(padded)
    return ciphertext

def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """AES-128 ECB 模式解密（带去填充）"""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext


def dump_func(func_start):

    func = ida_funcs.get_func(func_start)
    func_end = func.end_ea
    size = func_end - func_start
    data = ida_bytes.get_bytes(func_start, size)

    return data



def dump_array(start,count):
    now_addr = start
    array = []
    for i in range(count):
        array.append(ida_bytes.get_qword(now_addr))
        now_addr += 8

    return array

code_count = 58264
edge_count = 26057
announce_start = 0x5CDCC753BCA0
edge_start = 0x5CDCC7B388E0


code_key = b"Jump_h1gh_2_sky!"
edge_key = b"L1nk_2_th3_IN3T!"

codes = dump_array(announce_start, code_count)
edges = dump_array(edge_start, edge_count)

# print(hex(codes[5]))

# load all funcs body
codes_body = []
edges_body = []
for each_code in codes:
    if each_code !=0:
        codes_body.append(tea_decrypt(dump_func(each_code), code_key))
    else:
        codes_body.append(0)

for each_edge in edges:
    if each_edge !=0:
        edges_body.append(aes_decrypt_ecb(edge_key, dump_func(each_edge)))
    else:
        edges_body.append(0)
```

将代码dump出来之后，可以单独分析，例如以下为Code部分的代码:
```C
__int64 __fastcall sub_70000165(__int64 a1)
{
  int v1; // eax

  if ( *(_DWORD *)a1 == 1 )
  {
    *(_QWORD *)(a1 + 8) -= 3127LL;
    if ( *(_DWORD *)(a1 + 1048) <= 0x3FFu )
    {
      v1 = *(_DWORD *)(a1 + 1048);
      *(_DWORD *)(a1 + 1048) = v1 + 1;
      *(_DWORD *)(a1 + 4 * (v1 + 4LL) + 8) = -3127;
    }
  }
  if ( *(_DWORD *)a1 )
  {
    if ( *(_DWORD *)a1 == 1 )
      *(_DWORD *)(a1 + 4) = 2;
  }
  else
  {
    *(_DWORD *)(a1 + 4) = 0;
  }
  *(_DWORD *)(a1 + 16) = 2;
  return 0LL;
}
```

相关逻辑分析：

 - 取出当前Code中的一个指定值，和路径中的某个值匹配
 - 根据当前值的类型，决定是否对flag进行检查


以及Edge部分的代码
```C
__int64 __fastcall sub_706F9236(_DWORD *a1, __int64 a2, char a3)
{
  __int64 result; // rax
  unsigned int v4; // [rsp+14h] [rbp-1Ch]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( (a3 & 1) != 0 )
  {
    if ( !*a1 )
      *a1 = 1;
  }
  else if ( *a1 == 1 )
  {
    *a1 = 2;
    result = 0xFFFFFFFFLL;
    goto LABEL_12;
  }
  if ( (a3 & 2) != 0 )
    v4 = 7;
  else
    v4 = -1;
  if ( v4 == -1 )
  {
    *a1 = 2;
    result = 0xFFFFFFFFLL;
  }
  else
  {
    a1[4] = v4;
    ++a1[5];
    result = v4;
  }
LABEL_12:
  if ( v5 != __readfsqword(0x28u) )
    return sub_7003C362();
  return result;
}
```

Edge逻辑：

 - 根据我们path传入的字符，如果第1bit为0，则表示当前state为0，无需记录，否则表示当前state为1，需要记录当前值。如果之前的state为1，而且第1bit为0，则表示此时进入结束状态2
 - 根据第2bit的值，决定使用两个路径中的其中一个


### 题目解题

我们可以发现，如果将程序用Code和Edge的视野来看的话，可以看出来，其基本上**构成了一棵二叉树**的形式。所以我们需要的就是**将当前所有的Code权重拿出来**，同时**获取边关系**。根据我们之前dump的函数，可以看出，有些边对应的节点是空的，其值为-1（实际上，整个题目就是一颗二叉树）于是我们可以写代码将这部分数据dump出来：

```python

nodes = []
edges = []
for each_code in codes_body:
    if each_code[1] != 0:
        value = int.from_bytes(each_code[0][0x13:0x17],'little')
    else:
        value = -1
    nodes.append(value)

print(nodes[:10])

for each_edge in edges_body:
    if each_edge[1] == 0:
        left,right = -1,-1
    # elif len(each_edge[0]) == 0x11b:
    else:
        left = int.from_bytes(each_edge[0][0x77:0x77+4],'little')
        right = int.from_bytes(each_edge[0][0x7e:0x7e+4],'little')
    edges.append((left,right))

import json
with open("nodes.json", "w", encoding="utf-8") as f:
    json.dump(nodes, f, ensure_ascii=False, indent=2)

with open("edges.json", "w", encoding="utf-8") as f:
    json.dump(edges, f, ensure_ascii=False, indent=2)
```

之后利用深度遍历，找出可能的节点答案。这里附上一个算法脚本，
```python
from typing import List, Optional

# 二叉树节点定义（保持一致）
class TreeNode:
    def __init__(self, val=0, id=-1,  left=None, right=None):
        self.id = id
        self.val = val
        self.left = left
        self.right = right


def print_node(nodes: List[TreeNode]):

    for each in nodes:
        print((each.id,each.val),end=',')

def find_paths(root: Optional[TreeNode], target_sum: int) -> List[List[TreeNode]]:
    """
    返回所有从任意节点开始、向下延伸、节点值之和等于 target_sum 的路径。
    """
    all_paths = []

    def dfs_from(node: Optional[TreeNode], target: int, current_path: List[TreeNode]):
        """
        从当前节点向下搜索路径。
        """
        if not node:
            return
        
        current_path.append(node)

        # 计算当前路径末尾开始的连续子路径之和
        current_sum = 0
        # 从后往前遍历，检查所有后缀是否等于 target
        for i in range(len(current_path) - 1, -1, -1):
            current_sum += current_path[i].val
            if current_sum == target:
                # 复制当前满足条件的路径后缀
                all_paths.append(current_path[i:].copy())

        # 递归左右子树
        dfs_from(node.left, target, current_path)
        dfs_from(node.right, target, current_path)

        # 回溯
        current_path.pop()

    dfs_from(root, target_sum, [])
    return all_paths


def find_target_path(root, target_id):
    """
    从root出发，找到目标节点target_id的路径。
    返回字符串，例如 '0101' （0=左, 1=右）
    """
    path = []
    path_out = []

    def dfs(node):
        if not node:
            return False
        if node.id == target_id:
            return True
        # 尝试左子树
        path.append('0')
        path_out.append(node.left)
        if dfs(node.left):
            return True
        path.pop()
        path_out.pop()

        # 尝试右子树
        path.append('1')
        path_out.append(node.right)
        if dfs(node.right):
            return True
        path.pop()
        path_out.pop()

        return False

    path_out.append(root)
    found = dfs(root)
    if found:
        print([(node.id,node.val) for node in path_out])
        return ''.join(path)
    else:
        return None
```

根据上述脚本，能够找到数个答案。其中
```
5783,-7171,-1733,-3415,7703,-8204,2875,7495,7641,-183,-7455,3473,2466,-17,2740,-5885,
```
这一条路径答案非常接近，因为其总共有16个节点，而我们的输入为17字节，非常接近。（将这些节点路径丢入题目中的hash算法中，可以确认这个答案为目标路径）
于是可以得到我们所需的路劲为
```
000011113333131333332
```


将这个路径下所有的约束拿出来（*最后一个约束在主函数中*），然后写一个z3的脚本
```python
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
s.add(low8((flags[0] ^ flags[7]) ) == 115)
s.add(low8((flags[2]*3 ^ flags[7] + flags[10]) + 17 ) == 72)
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
```

最终可得到答案
```
Ct1l_fL0w_th3_eNd
```