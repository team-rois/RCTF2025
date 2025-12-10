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
announce_start = 0xEF8020
edge_start = 0xF69CE0


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
        codes_body.append(tea_encrypt(dump_func(each_code), code_key))
    else:
        codes_body.append(0)

for each_edge in edges:
    if each_edge !=0:
        edges_body.append(aes_encrypt_ecb(edge_key, dump_func(each_edge)))
    else:
        edges_body.append(0)
    
# codes_body = [tea_encrypt(dump_func(each_code), code_key) if each_code != 0 else 0 for each_code in codes]
# edges_body = [aes_encrypt_ecb(edge_key, dump_func(each_edge)) if each_edge != 0 else 0  for each_edge in edges]
# print(codes_body[0])
# print(codes_body[5])
# create global array for new code and edge
# first define every variables

def dump_c_array(b, varname="code"):
    # 确保输入是 bytes 类型
    if isinstance(b, str):
        b = b.encode('latin1')  # 如果传入字符串

    hex_list = [f"0x{byte:02x}" for byte in b]
    formatted = ", ".join(hex_list)
    return f"unsigned char {varname}[] = {{{formatted}}};\nconst unsigned long {varname}_len = {len(b)};"

GLOBAL_TARGET_NAME = "g_target_sum"
def generate_c_code():
    out = []
    announce = "void* announce[] = {"
    announce_len = "unsigned long announce_len[] = {"
    out.append('#include "global_hdr.h"')
    out.append("")
    out.append("")
    out.append("unsigned long long " + GLOBAL_TARGET_NAME + "= 6113;")
    for code_id in range(code_count):
        each_code_body = codes_body[code_id]
        if each_code_body ==0 :
            announce += "NULL,"
            announce_len += "0,"
        else:
            varname = "Code{}".format(code_id)
            var_array = dump_c_array(each_code_body, varname)
            # if var_array:
            out.append(var_array)
            out.append("")  # blank line
            announce += varname +","
            announce_len += varname +"_len,"

    code_out = "\n".join(out)
    code_out += "\n" + announce + "};\n" + announce_len + "};\n"
    # print(code)
    with open("new_code.c", 'w') as fd:
        fd.write(code_out)

    return 


def generate_c_edge():
    out = []
    announce = "void* g_edges[] = {"
    announce_len = "unsigned long g_edges_len[] = {"
    out.append('#include "global_hdr.h"')
    out.append("")
    for edge_id in range(edge_count):
        each_edge_body = edges_body[edge_id]
        if each_edge_body ==0 :
            announce += "NULL,"
            announce_len += "0,"
        else:
            varname = "Edge{}".format(edge_id)
            print(varname)
            var_array = dump_c_array(each_edge_body, varname)
            # if var_array:
            out.append(var_array)
            out.append("")  # blank line
            announce += varname +","
            announce_len += varname +"_len,"

    code_out = "\n".join(out)
    code_out += "\n" + announce + "};\n" + announce_len + "};\n"
    # print(code)
    with open("new_edge.c", 'w') as fd:
        fd.write(code_out)
    return 


generate_c_code()
generate_c_edge()

# for code_id in range(code_count):
#     dump_c_array(codes_body[code_id], "Code{}".format(code_id))



