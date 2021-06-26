import md4
import secrets
import struct 

# SECURE_KEY = secrets.token_bytes(16)
SECURE_KEY = b"1234567780abcdef"

def gen_hmac(msg, regs = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), length = 0, remove_key = False):
    if remove_key:
        return md4.MD4(msg, regs, length).hexdigest()
    else:
        return md4.MD4(SECURE_KEY + msg, regs, length).hexdigest()

def test_hmac(msg, hmac, regs = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), length = 0):
    return md4.MD4(SECURE_KEY + msg, regs, length).hexdigest() == hmac

def padding(msg):
    length = len(msg) * 8
    msg += b"\x80"
    msg += bytes((56 - len(msg) % 64) % 64)
    msg += struct.pack(b'<Q', length)
    return msg 

original = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
hmac = gen_hmac(original)
a, b, c, d = [int.from_bytes(bytes.fromhex(hmac[i * 8:(i + 1) * 8]), byteorder = "little") for i in range(4)]
print(a, b, c, d)
print(test_hmac(original, hmac))

# minor error in s4p29.py here, fixed
new_message = b";admin=true"
glue_padding = padding(secrets.token_bytes(16) + original)[16:] + new_message # or bruteforce over key size
new_message_length = 16 + len(glue_padding)
hmac = gen_hmac(new_message, (a, b, c, d), new_message_length, True)
print(glue_padding)
print(test_hmac(glue_padding, hmac))
