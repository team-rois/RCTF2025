# -*- coding: utf-8 -*-
"""
TEA 和 AES-128 的纯 Python 实现（示例用，便于移植到 C）
包含：
- TEA: block encrypt/decrypt; ECB模式 + PKCS7 padding helpers
- AES-128: block encrypt/decrypt; ECB模式 + PKCS7 padding helpers

注意：该实现主要用于学习 / 搬移到 C；生产请用成熟加密库。
"""

from typing import Tuple

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

# ----------------------------
# AES-128 (纯 Python 实现)
# - 支持 ECB 模式的 encrypt/decrypt（示例）
# - 参考标准轮函数实现，key schedule for 128-bit key
# ----------------------------
# S-box / inv S-box
_sbox = [
# 0     1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

_inv_sbox = [0] * 256
# build inv sbox
for i, v in enumerate(_sbox):
    _inv_sbox[v] = i

# Rcon
_rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def _xtime(a: int) -> int:
    return ((a << 1) & 0xFF) ^ (0x1B if (a & 0x80) else 0x00)

def _mul(a: int, b: int) -> int:
    # multiply in GF(2^8)
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res & 0xFF

def _sub_bytes(state: list):
    for i in range(16):
        state[i] = _sbox[state[i]]

def _inv_sub_bytes(state: list):
    for i in range(16):
        state[i] = _inv_sbox[state[i]]

def _shift_rows(state: list):
    # state is list of 16 bytes, column-major (col 0: 0,1,2,3; col1:4,5,6,7 ...)
    # but here we use standard mapping: state[r + 4*c]
    # perform shifts on rows:
    # row 0: no shift
    # row 1: shift left by 1
    # row 2: shift left by 2
    # row 3: shift left by 3
    tmp = state[:]
    # row 0
    state[0]  = tmp[0]
    state[4]  = tmp[4]
    state[8]  = tmp[8]
    state[12] = tmp[12]
    # row1
    state[1]  = tmp[5]
    state[5]  = tmp[9]
    state[9]  = tmp[13]
    state[13] = tmp[1]
    # row2
    state[2]  = tmp[10]
    state[6]  = tmp[14]
    state[10] = tmp[2]
    state[14] = tmp[6]
    # row3
    state[3]  = tmp[15]
    state[7]  = tmp[3]
    state[11] = tmp[7]
    state[15] = tmp[11]

def _inv_shift_rows(state: list):
    tmp = state[:]
    state[0]  = tmp[0]
    state[4]  = tmp[4]
    state[8]  = tmp[8]
    state[12] = tmp[12]
    state[1]  = tmp[13]
    state[5]  = tmp[1]
    state[9]  = tmp[5]
    state[13] = tmp[9]
    state[2]  = tmp[10]
    state[6]  = tmp[14]
    state[10] = tmp[2]
    state[14] = tmp[6]
    state[3]  = tmp[7]
    state[7]  = tmp[11]
    state[11] = tmp[15]
    state[15] = tmp[3]

def _mix_columns(state: list):
    # operate on columns
    for c in range(4):
        i = c*4
        a0 = state[i]; a1 = state[i+1]; a2 = state[i+2]; a3 = state[i+3]
        r0 = _mul(a0,2) ^ _mul(a1,3) ^ a2 ^ a3
        r1 = a0 ^ _mul(a1,2) ^ _mul(a2,3) ^ a3
        r2 = a0 ^ a1 ^ _mul(a2,2) ^ _mul(a3,3)
        r3 = _mul(a0,3) ^ a1 ^ a2 ^ _mul(a3,2)
        state[i] = r0; state[i+1] = r1; state[i+2] = r2; state[i+3] = r3

def _inv_mix_columns(state: list):
    for c in range(4):
        i = c*4
        a0 = state[i]; a1 = state[i+1]; a2 = state[i+2]; a3 = state[i+3]
        r0 = _mul(a0,0x0E) ^ _mul(a1,0x0B) ^ _mul(a2,0x0D) ^ _mul(a3,0x09)
        r1 = _mul(a0,0x09) ^ _mul(a1,0x0E) ^ _mul(a2,0x0B) ^ _mul(a3,0x0D)
        r2 = _mul(a0,0x0D) ^ _mul(a1,0x09) ^ _mul(a2,0x0E) ^ _mul(a3,0x0B)
        r3 = _mul(a0,0x0B) ^ _mul(a1,0x0D) ^ _mul(a2,0x09) ^ _mul(a3,0x0E)
        state[i] = r0; state[i+1] = r1; state[i+2] = r2; state[i+3] = r3

def _add_round_key(state: list, round_key: list):
    for i in range(16):
        state[i] ^= round_key[i]

def _key_expansion(key: bytes) -> list:
    # key: 16 bytes (AES-128)
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    # Represent key schedule as list of bytes for each round key (Nr+1)*16 bytes
    Nk = 4
    Nb = 4
    Nr = 10
    w = [0] * 44  # 4*(Nr+1) words; each word 4 bytes. here store as 32-bit ints
    # initial words
    for i in range(Nk):
        w[i] = int.from_bytes(key[4*i:4*i+4], 'big')
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            # RotWord
            temp = ((temp << 8) & 0xFFFFFFFF) | ((temp >> 24) & 0xFF)
            # SubWord
            b0 = _sbox[(temp >> 24) & 0xFF]
            b1 = _sbox[(temp >> 16) & 0xFF]
            b2 = _sbox[(temp >> 8) & 0xFF]
            b3 = _sbox[temp & 0xFF]
            temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            temp ^= (_rcon[i//Nk] << 24)
        w[i] = w[i - Nk] ^ temp
    # expand into round keys (list of bytes per round)
    round_keys = []
    for r in range(Nr+1):
        rk = []
        for j in range(4):
            word = w[r*4 + j]
            rk += [(word >> 24) & 0xFF, (word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF]
        round_keys.append(rk)
    return round_keys

def aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    state = list(block)
    Nr = 10
    # initial round key
    _add_round_key(state, round_keys[0])
    for r in range(1, Nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    # final round
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[Nr])
    return bytes(state)

def aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    state = list(block)
    Nr = 10
    _add_round_key(state, round_keys[Nr])
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    for r in range(Nr-1, 0, -1):
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    rk = _key_expansion(key)
    data = pkcs7_pad(data, 16)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += aes_encrypt_block(data[i:i+16], rk)
    return bytes(out)

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    if len(data) % 16 != 0:
        raise ValueError("ciphertext length must be multiple of 16")
    rk = _key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += aes_decrypt_block(data[i:i+16], rk)
    return pkcs7_unpad(bytes(out), 16)

# ----------------------------
# 示例 / 自检
# ----------------------------
if __name__ == "__main__":
    # TEA demo
    print("=== TEA Demo ===")
    p = b"Hello TEA! 123"  # 14 bytes
    tea_key = b"0123456789ABCDEF"  # 16 bytes key
    ct = tea_encrypt(p, tea_key)
    pt = tea_decrypt(ct, tea_key)
    print("PT:", p)
    print("CT(hex):", ct.hex())
    print("Decrypted:", pt)
    assert pt == p

    # AES demo
    print("\n=== AES-128 Demo ===")
    p2 = b"Hello AES-128! This is test."  # arbitrary
    aes_key = b"thisis16bytekey"  # 16 bytes
    ct2 = aes_encrypt(p2, aes_key)
    pt2 = aes_decrypt(ct2, aes_key)
    print("PT:", p2)
    print("CT(hex):", ct2.hex())
    print("Decrypted:", pt2)
    assert pt2 == p2

    print("\nAll tests passed.")
