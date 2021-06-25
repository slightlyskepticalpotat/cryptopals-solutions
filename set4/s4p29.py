import secrets
import sha1
import struct

SECURE_KEY = secrets.token_bytes(16)

def gen_hmac(msg, h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0), length = 0):
    return sha1.sha1(SECURE_KEY + msg, h, length).hexdigest()

def test_hmac(msg, hmac, h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0), length = 0):
    return sha1.sha1(SECURE_KEY + msg, h, length).hexdigest() == hmac

def padding(msg):
    length = len(msg) * 8
    msg += b"\x80"
    msg += b"\x00" * ((56 - ((length // 8) + 1) % 64) % 64)
    msg += struct.pack(b'>Q', length)
    return msg

original = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
hmac = gen_hmac(original)
h0, h1, h2, h3, h4 = [int.from_bytes(bytes.fromhex(hmac[i * 8:(i + 1) * 8]), byteorder="big") for i in range(5)]
print(h0, h1, h2, h3, h4)
print(test_hmac(original, hmac))

glue_padding = padding(secrets.token_bytes(16) + original)[16 + len(original):] # or bruteforce over key size
new_message_length = 16 + len(original) + len(glue_padding)
new_message = b";admin=true"
hmac = gen_hmac(new_message, (h0, h1, h2, h3, h4), new_message_length)
new_message = original + glue_padding + new_message
print(new_message)
print(test_hmac(new_message, hmac))
