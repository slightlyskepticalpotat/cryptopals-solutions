import binascii
import random

from rsa import RSA

rsa = RSA(1024, 65537)
n = rsa.get_public_key()[1]
message = "secret"

print(message)
number = int(binascii.hexlify(message.encode()), 16)
print(number)
c = rsa.encrypt(number)
print(c)
s = 4 # guaranteed random starting number
while not (s % n > 1):
    s = random.randint(1, n)
c_prime = (pow(s, 65537, n) * c) % n
print(c_prime)
p_prime = rsa.decrypt(c_prime)
print(p_prime)
p = (p_prime // s) % n
print(p)
print(binascii.unhexlify(hex(p)[2:]).decode())
