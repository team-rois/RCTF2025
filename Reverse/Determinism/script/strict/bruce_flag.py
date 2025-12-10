def mix32(x: int) -> int:
    """A small 32-bit mixing function (splitmix-like)."""
    x &= 0xFFFFFFFF
    x = (x + 0x9E3779B9) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) * 0x85EBCA6B & 0xFFFFFFFF
    x = (x ^ (x >> 13)) * 0xC2B2AE35 & 0xFFFFFFFF
    x = x ^ (x >> 16)
    return x & 0xFFFFFFFF

def hash2(a: int, b: int) -> int:
    """
    16-bit hash of two bytes a,b (0..255).
    Pack a into high 8 bits and b into low 8 bits, then mix and return 16 bits.
    """
    key = ((a & 0xFF) << 8) | (b & 0xFF)
    m = mix32(key)
    return m & 0xFFFF


# hash2(flag[0],flag[11]) = 18064
# hash2(flag[11],flag[2]) = 55732
# hash2(flag[0],flag[2]) = 50141

for a in range(32,127):
    for b in range(32,127):
        for c in range(32,127):
            if hash2(a,c) == 18064 and\
                hash2(c,b) == 55732 and\
                hash2(a,b) == 50141:
                print(a,b,c)