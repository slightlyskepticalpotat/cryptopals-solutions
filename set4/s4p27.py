import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECURE_KEY = secrets.token_bytes(16)

def aes_encrypt(data):
    cipher = AES.new(SECURE_KEY, AES.MODE_CBC, SECURE_KEY)
    return cipher.encrypt(pad(data, 16))

def aes_decrypt(data):
    cipher = AES.new(SECURE_KEY, AES.MODE_CBC, SECURE_KEY)
    data = unpad(cipher.decrypt(data), 16)
    try:
        data.decode(encoding="ascii")
    except:
        return data

def bytes_xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

encrypted = aes_encrypt(b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
blocks = [encrypted[i:i + 16] for i in range(0, len(encrypted), 16)]
for i in range(256):
    try:
        decrypted = aes_decrypt(blocks[0] + b'\x00' * 15 + bytes([i]) + blocks[0]) # bruteforce padding
    except ValueError:
        pass
decrypted_blocks = [decrypted[i:i + 16] for i in range(0, len(decrypted), 16)]
for i in range(256):
    if bytes_xor(decrypted_blocks[0], decrypted_blocks[-1]) + bytes([i]) == SECURE_KEY: # we would check by forcibly decrypting in the real world
        print(SECURE_KEY)
