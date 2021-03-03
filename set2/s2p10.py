import base64
from Crypto.Cipher import AES

file = open('10.txt', "r")
text = base64.b64decode(file.read())
cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_CBC, b"\x00" * 16)
print(cipher.decrypt(text).decode("utf-8"), end = "")
