import base64
from Crypto.Cipher import AES

file = open('7.txt', "r")
text = base64.b64decode(file.read())
cipher = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
print(cipher.decrypt(text).decode("utf-8"), end = "")
