from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_decrypt_cbc(key: bytes, ciphertext: bytes,iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC,iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext


key = b"SKygB9j6Odefxq2W"
iv = b"FHwewU_SSNSXi3hu"
cipher = bytes.fromhex("134432739c43fbc956367f49e25b6c0c")
print(aes_decrypt_cbc(key,cipher, iv))
