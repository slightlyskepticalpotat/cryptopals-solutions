import hashlib
import secrets
from dh import DiffieHellman

def gen_hmac(msg, key): # takes ints
    return hashlib.sha256((str(key) + str(msg)).encode()).hexdigest()

def test_hmac(msg, key, hmac): # takes ints
    return hashlib.sha256((str(key) + str(msg)).encode()).hexdigest() == hmac

C = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2) # A
S = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2) # B

# client and server agree beforehand
N = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
g = 2
k = 3
I = "email@example.com"
P = "password"

# server actions
salt = secrets.randbelow(N)
xH = hashlib.sha256((str(salt) + P).encode()).hexdigest()
x = int(xH, 16)
v = pow(g, x, N)
# x, xH discarded here

# client to server
# client sends I to server
A = pow(g, C.get_private_key (), N)

# server to client
# server sends salt to client
B = k * v + pow(g, S.get_private_key(), N)

# client and server both compute
uH = hashlib.sha256((str(A) + str(B)).encode()).hexdigest()
u = int(uH, 16)

# client actions
# client computes x and xH
S_client = pow(B - k * pow(g, x, N), C.get_private_key() + u * x, N)
K_client = hashlib.sha256(str(S_client).encode()).hexdigest()
print(K_client)

# server actions
S_server = pow(A * pow(v, u, N), S.get_private_key(), N)
K_server = hashlib.sha256(str(S_server).encode()).hexdigest()
print(K_server)

# client to server
hmac = gen_hmac(K_client, salt)
print(hmac)

# server actions
ok = test_hmac(K_server, salt, hmac)
print(ok)

# server to client
# accept or reject conn