import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SECURE_KEY = secrets.token_bytes(16)

def pad(text, block_size):
    padding_size = (block_size - len(text)) % block_size
    if not padding_size:
        padding_size = block_size
    return text + (chr(padding_size) * padding_size).encode()

def parse(x):
    parts, user = x.split(b"&"), {}
    for part in parts:
        key, info = part.split(b"=")
        user[key] = info
    return user

def setup(x):
    x = x.replace(b"&", b"")
    x = x.replace(b"=", b"")
    return bytes(f"email={x.decode()}&uid=1&role=user", "utf-8")

def secure_make_user(x):
    cipher = AES.new(SECURE_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(setup(x), 16))

# 11112222333344441111222233334444
# email=fooo@gmail.com&uid=1&role=
# email=reeeeeeeeeadminxxxxxxxxxxx where x is \x0b
user = secure_make_user(b"fooo@gmail.com")
print(user[:32].hex())
insecure_user = secure_make_user(b"reeeeeeeee" + b"admin" + b"\x0b" * 11)
print(insecure_user[16:32].hex())
cipher = AES.new(SECURE_KEY, AES.MODE_ECB)
print(cipher.decrypt(user[:32] + insecure_user[16:32]))
print(parse(unpad(cipher.decrypt(user[:32] + insecure_user[16:32]), 16))) # we need to manually unpad this
