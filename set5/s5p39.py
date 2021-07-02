import binascii
import math
from Crypto.Util import number

class RSA():
    def __init__(self, key_size = 4096, e = 3):
        self.e = e
        self.et = 0
        while math.gcd(self.e, self.et) != 1:
            self.p = number.getPrime(key_size // 2)
            self.q = number.getPrime(key_size // 2)
            self.et = self.lcm(self.p - 1, self.q - 1)
            self.n = self.p * self.q
        self.d = pow(self.e, -1, self.et)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def get_private_key(self):
        return [self.d, self.n]

    def get_public_key(self):
        return [self.e, self.n]

    def lcm(self, x, y):
        return abs(x * y) // math.gcd(x, y)

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