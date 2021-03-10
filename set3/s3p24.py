import secrets, time
from s3p21 import MersenneTwister

def bytes_xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

def keygen(n, s):
    random = MersenneTwister(seed = s)
    key = b""
    while len(key) < n:
        key += random.random_integer().to_bytes(4, "little")
    return key

original_seed = secrets.randbits(16)
print(f"Original Seed: {original_seed}")
plaintext = b"".join([bytes(chr(secrets.randbelow(256)), "utf-8") for _ in range(secrets.randbelow(16))]) + b"A" * 16
keystream = keygen(len(plaintext), original_seed)
ciphertext = bytes_xor(plaintext, keystream)

for i in range(2 ** 16):
    keystream = keygen(len(plaintext), i)
    if b"A" * 16 in bytes_xor(ciphertext, keystream):
        print(f"Cracked Seed: {i}")
        print(f"Message: {bytes_xor(ciphertext, keystream)}")
        break
print(f"Original Time: {int(time.time())}")
token = keygen(16, int(time.time()))
for i in range(int(time.time()) - 30, int(time.time()) + 30):
    if keygen(16, i) == token:
        print(f"Cracked Time: {i}")
        print(f"Token: {keygen(16, i)}")
        break
