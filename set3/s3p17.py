import base64, secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECURE_KEY, SECURE_IV = secrets.token_bytes(16), secrets.token_bytes(16)

def aes_encrypt():
    cipher = AES.new(SECURE_KEY, AES.MODE_CBC, SECURE_IV)
    return cipher.encrypt(pad(secrets.choice([b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]), 16))

def bytes_xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

def check_padding(text, iv):
    cipher = AES.new(SECURE_KEY, AES.MODE_CBC, iv)
    try:
        unpad(cipher.decrypt(text), 16)
    except ValueError:
        return False
    return True

def decrypt_single_block(x): # to decrypt each block we need at most 16*256*2 queries to the padding oracle
    fake_iv = [0 for _ in range(16)]
    for i in range(1, 17): # padding value
        loc_iv = [i ^ j for j in fake_iv]
        for char in range(256): # try each character
            loc_iv[-i] = char
            if check_padding(block, bytes(loc_iv)): # our oracle
                loc_iv[-2] ^= 1 # check for 1/256 false positive
                if i == 1 and not check_padding(block, bytes(loc_iv)):
                    continue
                break
        fake_iv[-i] = char ^ i # update the cracked iv
    return fake_iv

ciphertext, plaintext, iv = aes_encrypt(), [], SECURE_IV
blocks = [SECURE_IV] + [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)] # setup the blocks with the initial iv
for block in blocks[1:]: # process the input block-by-block
    decoded = decrypt_single_block(block)
    plaintext.append(bytes_xor(decoded, iv))
    iv = block
print(base64.b64decode(b"".join(plaintext)).decode("utf-8"))
