import hashlib
import secrets 


# manual implementation
p = 37
g = 5
a = secrets.randbelow(p) # private key 
b = secrets.randbelow(p) # private key
A = (g ** a) % p # public key
B = (g ** b) % p # public key
s_a = (B ** a) % p # session key
s_b = (A ** b) % p # session key
key = hashlib.sha256(bytes(s_a)).hexdigest() # encryption key
print(s_a, s_b)
print(key)

# class implementation
class DiffieHellman():
    def __init__(self, p, g):
        self.p = p 
        self.g = g 
        self.private_key = secrets.randbelow(p)
        self.shared_key = -1

    def get_private_key(self):
        return self.private_key 

    def get_public_key(self):
        return pow(self.g, self.private_key, self.p)

    def get_shared_key(self, other_key = -1):
        if self.shared_key == -1:
            self.shared_key = pow(other_key, self.private_key, self.p)
        return self.shared_key

alice = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2)
bob = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2)
print(alice.get_shared_key(bob.get_public_key()), bob.get_shared_key(alice.get_public_key()))
print(hashlib.sha256(alice.get_shared_key().to_bytes(2 ** 16, "little")).hexdigest())