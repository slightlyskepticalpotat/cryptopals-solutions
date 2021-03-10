import base64
from Crypto.Cipher import AES

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

text = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
print(aes_ctr(b"YELLOW SUBMARINE", b"\x00\x00\x00\x00\x00\x00\x00\x00", text).decode("utf-8"))
