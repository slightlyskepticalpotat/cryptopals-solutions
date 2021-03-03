import base64, math, secrets, string
from Crypto.Cipher import AES

SECURE_KEY = secrets.token_bytes(16)

def aes_encrypt_consistent(data):
    cipher = AES.new(SECURE_KEY, AES.MODE_ECB)
    data += base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    return cipher.encrypt(pad(data, 16))

def identify_ecb(data):
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    if len(blocks) - len(set(blocks)): # chance of collision in cbc is small
        return True
    return False

def pad(text, block_size):
    padding_size = (block_size - len(text)) % block_size
    if not padding_size:
        padding_size = block_size
    return text + (chr(padding_size) * padding_size).encode()

for i in range(1, 18):
    print(aes_encrypt_consistent(i * b"A")[:16])

file = open('../LICENSE', "r") # use the gnu gplv3
text = pad(bytes(file.read(), "utf-8"), 16) # we need to feed it enough data to identify patterns in the text
print(identify_ecb(aes_encrypt_consistent(text)))

final_size = 16 * math.ceil(len(base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")) / 16)
target, final_text = b"A" * (final_size - 1), b""
l, r = (final_size // 16 - 1) * 16, (final_size // 16) * 16 # final block, including the padding

while target:
    target_encrypted = aes_encrypt_consistent(target)[l:r]
    for char in bytes(string.printable, "utf-8"):
        test_encrypted = aes_encrypt_consistent(target + final_text + chr(char).encode('utf-8'))[l:r] # first byte not currently guessed
        if test_encrypted == target_encrypted:
            final_text += chr(char).encode('utf-8')
            break
    target = target[:-1]
print(final_text.decode(), end = "")
