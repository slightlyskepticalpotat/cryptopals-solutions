import secrets
from Crypto.Cipher import AES
from s2p9 import pad

def aes_encrypt(data):
    if secrets.randbelow(2) % 2:
        print("Using: CBC", end = " ")
        cipher = AES.new(secrets.token_bytes(16), AES.MODE_CBC, secrets.token_bytes(16))
    else:
        print("Using: ECB", end = " ")
        cipher = AES.new(secrets.token_bytes(16), AES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    return secrets.token_bytes(secrets.randbelow(11)) + encrypted + secrets.token_bytes(secrets.randbelow(11))

def identify_ecb(data):
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    if len(blocks) - len(set(blocks)): # chance of collision in cbc is small
        return True
    return False

file = open('../LICENSE', "r") # use the gnu gplv3
text = pad(bytes(file.read(), "utf-8"), 16)
for _ in range(16):
    if identify_ecb(aes_encrypt(text)):
        print("Guess: ECB")
    else:
        print("Guess: CBC")
