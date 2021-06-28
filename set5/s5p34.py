import hashlib
import secrets
from Crypto.Cipher import AES
from dh import DiffieHellman

# normal protocol
alice = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2)
bob = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2)
p = alice.p 
g = alice.g
A = alice.get_public_key()
B = bob.get_public_key()
s = alice.get_shared_key(B)
key = hashlib.sha256(s.to_bytes(2 ** 16, "little")).hexdigest()[:32] # 16 bytes
alice_iv = secrets.token_bytes(16)
bob_iv = secrets.token_bytes(16)
alice_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, alice_iv)
alice_to_bob = alice_cipher.encrypt(b"YELLOW SUBMARINE") + alice_iv 
print(alice_to_bob)
bob_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, alice_to_bob[-16:])
bob_decrypted = bob_cipher.decrypt(alice_to_bob)
print(bob_decrypted)
bob_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, bob_iv)
bob_to_alice = bob_cipher.encrypt(bob_decrypted[:-16]) + bob_iv
print(bob_to_alice)

# mitm attack
alice = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2)
bob = DiffieHellman(int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16), 2)
p = alice.p 
g = alice.g
# here the public keys are replaced by p for ease of implementation, in a real attack we would actually use mallory's public key and re-encrypt the messages
A = p 
B = p
s = alice.get_shared_key(B) # blice, bob, and mallory all know this
key = hashlib.sha256(str(s).encode()).hexdigest()[:32] # 16 bytes
alice_iv = secrets.token_bytes(16)
bob_iv = secrets.token_bytes(16)
alice_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, alice_iv)
alice_to_bob = alice_cipher.encrypt(b"YELLOW SUBMARINE") + alice_iv 
mallory_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, alice_to_bob[-16:])
mallory_decrypted = mallory_cipher.decrypt(alice_to_bob[:16])
print("intercept:", mallory_decrypted)
bob_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, alice_to_bob[-16:])
bob_decrypted = bob_cipher.decrypt(alice_to_bob)
bob_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, bob_iv)
bob_to_alice = bob_cipher.encrypt(bob_decrypted[:-16]) + bob_iv
mallory_cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, bob_to_alice[-16:])
mallory_decrypted = mallory_cipher.decrypt(bob_to_alice[:16])
print("intercept:", mallory_decrypted)
