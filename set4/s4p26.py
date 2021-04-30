import secrets
from Crypto.Cipher import AES

SECURE_KEY = secrets.token_bytes(16)
SECURE_IV = secrets.token_bytes(8) # shorter iv

def aes_ctr_keystream(key, nonce):
    counter = 0
    cipher = AES.new(key, AES.MODE_ECB)
    while True:
        plaintext = nonce + counter.to_bytes(8, "little") # pack the nonce and counter
        for byte in cipher.encrypt(plaintext):
            yield byte
        counter += 1

def aes_ctr(key, nonce, plaintext): # same function for encrypt and decrypt
    keystream = aes_ctr_keystream(key, nonce) # 0 is the nonce
    return bytes_xor(plaintext, keystream)

def bytes_xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

def aes_encrypt(data):
    data = data.replace(b";", b"")
    data = data.replace(b"=", b"")
    data = b"comment1=cooking%20MCs;userdata=" + data + b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_ctr(SECURE_KEY, SECURE_IV, pad(data, 16))

def check(data):
    data = aes_ctr(SECURE_KEY, SECURE_IV, unpad(data, 16))
    print(data)
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
print(encrypted)
blocks = [encrypted[i:i + 16] for i in range(0, len(encrypted), 16)]
tampered_block = list(blocks[2]) # we directly flip the block in ctr
tampered_block[0], tampered_block[6], tampered_block[11] = tampered_block[0] ^ 26, tampered_block[6] ^ 28, tampered_block[11] ^ 26
blocks[2] = bytes(tampered_block)
print(check(b"".join(blocks)))
