import binascii

from rsa import RSA

rsa = RSA()

plaintext_1 = 42
ciphertext_1 = rsa.encrypt(42)
decrypted_1 = rsa.decrypt(ciphertext_1)
print(plaintext_1, ciphertext_1, decrypted_1)
plaintext_2 = "attack"
number = int(binascii.hexlify(plaintext_2.encode()), 16)
ciphertext_2 = rsa.encrypt(number)
decrypted_2 = rsa.decrypt(ciphertext_2)
string = binascii.unhexlify(hex(decrypted_2)[2:]).decode()
print(plaintext_2, ciphertext_2, string)