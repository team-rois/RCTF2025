import random
import hashlib
from z3 import *

# ------------------------------
# 参数配置
# ------------------------------
FLAG_LEN = 17
FLAG_PREFIX = "flag{"
HASH_FUNC = "md5"  # 可选: md5, sha1, sha256
EXPR_COUNT = 60      # 生成多少条表达式

# ------------------------------
# 1. 生成目标flag
# ------------------------------
target_flag = "Ct1l_fL0w_th3_eNd"  # 可修改
assert len(target_flag) == FLAG_LEN

# ------------------------------
# 2. 构造符号变量
# ------------------------------
flag = [BitVec(f"flag[{i}]", 8) for i in range(FLAG_LEN)]
s = Solver()

# ------------------------------
# 3. 通用字符约束
# ------------------------------
for f in flag:
    s.add(f >= 32, f <= 126)

# 假设之前已定义：
# FLAG_LEN, target_flag, flag (list of BitVec 8), s = Solver()
# 并且定义了 hash2 函数的 python 版本（返回 0..255）
def hash2(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    x = (a * 131) ^ (b * 137)
    x ^= (a << 3) ^ (b >> 2)
    x = (x ^ (x >> 8)) & 0xFF
    return x

def mix32(x: int) -> int:
    """A small 32-bit mixing function (splitmix-like)."""
    x &= 0xFFFFFFFF
    x = (x + 0x9E3779B9) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) * 0x85EBCA6B & 0xFFFFFFFF
    x = (x ^ (x >> 13)) * 0xC2B2AE35 & 0xFFFFFFFF
    x = x ^ (x >> 16)
    return x & 0xFFFFFFFF

def hash2_16(a: int, b: int) -> int:
    """
    16-bit hash of two bytes a,b (0..255).
    Pack a into high 8 bits and b into low 8 bits, then mix and return 16 bits.
    """
    key = ((a & 0xFF) << 8) | (b & 0xFF)
    m = mix32(key)
    return m & 0xFFFF

# ------- 两个辅助函数：符号版与具体值计算版 -------
def expr_concrete(op, a, b, c, d):
    """对具体整数 a,b,c,d 计算表达式值（返回 0..255 或 int）"""
    if op == "add":
        return ((a + b + c) ^ (b * 3)) & 0xFF
    elif op == "xor":
        return ((a ^ b) + (c * 2)) & 0xFF
    elif op == "mix":
        return (((a * 3) ^ (b + c)) + 17) & 0xFF
    elif op == "shift":
        return (((a << 1) + (b >> 1)) ^ c) & 0xFF
    elif op == "mul":
        return ((a * (b + 3)) ^ (c * 2)) & 0xFF
    elif op == "hash":
        return hash2_16(a, b)  # 只用 a,b 做 hash
    elif op == "binary":
        choice = random.choice(["add", "xor", "mul"])
        if choice == "add":
            return (a + b) & 0xFF
        elif choice == "xor":
            return (a ^ b) & 0xFF
        else:
            return (a * b) & 0xFF
    else:
        # fallback
        return ((a + b + c) ^ (b * 3)) & 0xFF

from z3 import BitVec, BitVecVal, Solver, simplify, LShR, Extract, ZeroExt

def expr_symbolic(op, a, b, c, d):
    """返回一个 8-bit BitVec 表达式"""
    if op == "add":
        tmp = ((a + b + c) ^ (b * 3))
        return tmp & BitVecVal(0xFF, 8)
    elif op == "xor":
        tmp = ((a ^ b) + (c * 2))
        return tmp & BitVecVal(0xFF, 8)
    elif op == "mix":
        tmp = (((a * 3) ^ (b + c)) + 17)
        return tmp & BitVecVal(0xFF, 8)
    elif op == "shift":
        tmp = (((a << 1) + LShR(b, 1)) ^ c)
        return tmp & BitVecVal(0xFF, 8)
    elif op == "mul":
        tmp = ((a * (b + 3)) ^ (c * 2))
        return tmp & BitVecVal(0xFF, 8)
    elif op == "hash":
        # 仿照 C 的 hash2 逻辑（扩展到 16-bit，再截断）
        A16 = ZeroExt(8, a)
        B16 = ZeroExt(8, b)
        x = (A16 * BitVecVal(131, 16)) ^ (B16 * BitVecVal(137, 16))
        x = x ^ ((ZeroExt(8, a) << 3) ^ LShR(ZeroExt(8, b), 2))
        x = (x ^ LShR(x, 8)) & BitVecVal(0xFF, 16)
        return Extract(7, 0, x)
    elif op == "binary":
        subop = "xor"  # 固定，不要再随机，以保证符号值一致
        if subop == "add":
            tmp = (a + b)
        elif subop == "mul":
            tmp = (a * b)
        else:
            tmp = (a ^ b)
        return tmp & BitVecVal(0xFF, 8)
    else:
        tmp = ((a + b + c) ^ (b * 3))
        return tmp & BitVecVal(0xFF, 8)
    
# ------------------ 生成表达式（修正后的主循环） ------------------
while True:
    exprs = []
    for i in range(EXPR_COUNT):
        idxs = random.sample(range(FLAG_LEN), 4)
        # 选择一次 op（固定）
        op = random.choice(["add", "xor", "mix", "shift", "mul", "hash", "binary"])

        # 符号参数（BitVecs）
        a_sym = flag[idxs[0]]
        b_sym = flag[idxs[1]]
        c_sym = flag[idxs[2]]
        d_sym = flag[idxs[3]]

        # 构造符号表达式（用于 Z3）
        sym_expr = expr_symbolic(op, a_sym, b_sym, c_sym, d_sym)

        # 具体参数（真实 flag 字符）
        va = ord(target_flag[idxs[0]])
        vb = ord(target_flag[idxs[1]])
        vc = ord(target_flag[idxs[2]])
        vd = ord(target_flag[idxs[3]])

        # 用相同 op 计算具体值
        concrete_val = expr_concrete(op, va, vb, vc, vd)

        # 将 sym_expr == concrete_val 加入 solver
        s.add(sym_expr == BitVecVal(concrete_val, 8))

        exprs.append((idxs, op, sym_expr, concrete_val))
    # ------------------------------
    # 5. 引入哈希约束（强化混淆）
    # ------------------------------
    # def flag_hash(data: str, algo="md5"):
    #     h = hashlib.new(algo)
    #     h.update(data.encode())
    #     return h.hexdigest()

    # expected_hash = flag_hash(target_flag, HASH_FUNC)
    # hash最后几个字节转成数值约束
    # hash_tail = expected_hash[-6:]
    # target_val = sum(ord(c) for c in hash_tail) % 256
    # s.add(Sum([flag[i] for i in range(FLAG_LEN)]) % 256 == target_val)

    # ------------------------------
    # 6. 求解 + 输出
    # ------------------------------
    if s.check() == sat:
        m = s.model()
        solved = ''.join(chr(m[f].as_long()) for f in flag)
        print("[+] Solved flag:", solved)
        break
    else:
        print("[-] Unsat, adjust parameters.")
        # pass
        break

# ------------------------------
# 7. 输出C语言约束表达式
# ------------------------------
print("\n// ====== C Expression Snippets ======")
for (idxs,op, expr, val) in exprs:
    a, b, c,d= [f"flag[{i}]" for i in idxs]
    op = random.choice(["+", "^", "*", "<<", ">>"])
    print(expr,end='')
    print(f"={val}")
    # c_expr = f"((({a} {op} {b}) ^ ({c} * 3)) & 0xFF) == {val}"
    # print(c_expr + ";")
# print(f"// Sum(flag) %% 256 == {target_val}  // from {HASH_FUNC} tail")
