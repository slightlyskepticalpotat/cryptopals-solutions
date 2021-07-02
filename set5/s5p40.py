import binascii
import gmpy2

from rsa import RSA

rsa_0 = RSA()
n_0 = rsa_0.get_public_key()[1]
rsa_1 = RSA()
n_1 = rsa_1.get_public_key()[1]
rsa_2 = RSA()
n_2 = rsa_2.get_public_key()[1]

message = "secret" # we use crt to find message
number = int(binascii.hexlify(message.encode()), 16)
print(number)
c_0 = rsa_0.encrypt(number)
c_1 = rsa_1.encrypt(number)
c_2 = rsa_2.encrypt(number)

result = 0
result += c_0 * (n_1 * n_2) * pow(n_1 * n_2, -1, n_0)
result += c_1 * (n_0 * n_2) * pow(n_0 * n_2, -1, n_1)
result += c_2 * (n_0 * n_1) * pow(n_0 * n_1, -1, n_2)
decrypted = result % (n_0 * n_1 * n_2)
decrypted = int(gmpy2.cbrt(decrypted))
print(decrypted)
print(binascii.unhexlify(hex(decrypted)[2:]).decode())