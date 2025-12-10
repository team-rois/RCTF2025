MASK_32 = 0xFFFFFFFF
# --- SPECK-64/128 Cipher (Python Implementation) ---
# --- Constants ---
ROUNDS = 27

def ROR32(x, r): return ((x >> r) | (x << (32 - r))) & MASK_32
def ROL32(x, r): return ((x << r) | (x >> (32 - r))) & MASK_32


def speck64_encrypt_round(x, y, k):
    """Performs one 32-bit round of Speck encryption."""
    x = (ROR32(x, 8) + y) & MASK_32
    x = x ^ k
    y = (ROL32(y, 3) ^ x) & MASK_32
    return x, y


def speck64_decrypt_round(x, y, k):
    """Performs one 32-bit round of Speck decryption (inverse of encrypt_round)."""
    y_xor = y ^ x
    y_in = ROR32(y_xor, 3) 

    x_xor = x ^ k
    x_sub = (x_xor - y_in) & MASK_32
    x_in = ROL32(x_sub, 8)

    return x_in, y_in

# --- Correct 32-bit Key Schedule (for 128-bit key) ---
def speck64_128_keyschedule(key_u128, rounds=ROUNDS):
    """Generates the 32-bit round keys for Speck-64/128."""
    
    key_words = [
        (key_u128 >> 0) & MASK_32,
        (key_u128 >> 32) & MASK_32,
        (key_u128 >> 64) & MASK_32,
        (key_u128 >> 96) & MASK_32
    ]
    
    l = key_words[1:]
    k = key_words[0]  
    
    key_schedule = [k]
    
    for i in range(rounds - 1):
        l_val, k = speck64_encrypt_round(l[0], k, i)
        l = l[1:] + [l_val]
        key_schedule.append(k)
        
    return key_schedule

def speck64_encrypt(key_u128, plain_u64, rounds=ROUNDS):
    """Encrypts a 64-bit value using Speck-64/128."""
    
    key_schedule = speck64_128_keyschedule(key_u128, rounds)
    
    y = (plain_u64 >> 32) & MASK_32
    x = plain_u64 & MASK_32
    
    for k in key_schedule:
        x, y = speck64_encrypt_round(x, y, k)
        
    return (y << 32) | x

def speck64_decrypt(key_u128, cipher_u64, rounds=ROUNDS):
    """Decrypts a 64-bit value using Speck-64/128."""
    

    key_schedule = speck64_128_keyschedule(key_u128, rounds)
    
    y = (cipher_u64 >> 32) & MASK_32
    x = cipher_u64 & MASK_32
    
    for k in reversed(key_schedule):
        x, y = speck64_decrypt_round(x, y, k)
        
    return (y << 32) | x

# --- RC4 Cipher (Python Implementation) ---
def rc4_encrypt(key_int, data):
    """Encrypts/decrypts data with RC4 using the 8-byte key."""
    key = key_int.to_bytes(8, 'little', signed=False)
    key_len = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    output = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        output.append(b ^ k)
    return output
