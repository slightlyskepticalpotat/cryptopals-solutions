import secrets
from Crypto.Cipher import AES

SECURE_KEY = secrets.token_bytes(16)
SECURE_IV = secrets.token_bytes(16)

def aes_encrypt(data):
    cipher = AES.new(SECURE_KEY, AES.MODE_CBC, SECURE_IV)
    data = data.replace(b";", b"")
    data = data.replace(b"=", b"")
    data = b"comment1=cooking%20MCs;userdata=" + data + b";comment2=%20like%20a%20pound%20of%20bacon"
    return cipher.encrypt(pad(data, 16))

def check(data):
    cipher = AES.new(SECURE_KEY, AES.MODE_CBC, SECURE_IV)
    data = unpad(cipher.decrypt(data), 16)
    return b";admin=true;" in data

def pad(text, block_size):
    padding_size = (block_size - len(text)) % block_size
    if not padding_size:
        padding_size = block_size
    return text + (chr(padding_size) * padding_size).encode()

def unpad(text, block_size):
    padding, removed = text[-1], 0
    while 0 <= text[-1] <= (block_size - 1) and text[-1] == padding:
        text, removed = text[:-1], removed + 1
    if padding == removed or padding > (block_size - 1):
        return text
    raise Exception("Padding Error")

encrypted = aes_encrypt(b"!admin!true!")
blocks = [encrypted[i:i + 16] for i in range(0, len(encrypted), 16)]
tampered_block = list(blocks[1])
tampered_block[0], tampered_block[6], tampered_block[11] = tampered_block[0] ^ 26, tampered_block[6] ^ 28, tampered_block[11] ^ 26
blocks[1] = bytes(tampered_block)
print(check(b"".join(blocks)))
# 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# comment1=cooking%20MCs;userdata=!eeeee!eeee!eeee;admin=true;
