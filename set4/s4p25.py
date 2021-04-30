import base64, secrets
from Crypto.Cipher import AES

SECURE_KEY, SECURE_NONCE = secrets.token_bytes(16), secrets.token_bytes(8)

def aes_ctr_fixed_keystream(key, nonce, n):
    cipher, keystream = AES.new(key, AES.MODE_ECB), []
    for counter in range(0, 2 ** 16):
        plaintext = nonce + counter.to_bytes(8, "little") # pack the nonce and counter
        for byte in cipher.encrypt(plaintext):
            keystream.append(byte)
            if len(keystream) == n:
                return keystream

def bytes_xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

def edit(ciphertext, offset, edited):
    new = bytes_xor(edited, keystream[offset:offset + len(edited)])
    result = ciphertext[:offset] + new + ciphertext[offset + len(edited):]
    return result

file = open("25.txt", "r")
plaintext = base64.b64decode(file.read())
keystream = aes_ctr_fixed_keystream(SECURE_KEY, SECURE_NONCE, len(plaintext))
ciphertext = bytes_xor(plaintext, keystream)

recovered_keystream = edit(ciphertext, 0, b"\x00" * len(ciphertext))
assert bytes_xor(recovered_keystream, ciphertext) == plaintext
print(bytes_xor(recovered_keystream, ciphertext))
