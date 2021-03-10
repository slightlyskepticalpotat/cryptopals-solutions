import base64, secrets
from Crypto.Cipher import AES

SECURE_KEY, SECURE_NONCE = secrets.token_bytes(16), secrets.token_bytes(8)

def aes_ctr_fixed_keystream(key, nonce, n):
    cipher, keystream = AES.new(key, AES.MODE_ECB), []
    for counter in range(0, 2 ** 16):
        plaintext = nonce + counter.to_bytes(8, "little") # pack the nonce and counter
        for byte in cipher.encrypt(plaintext):
            keystream.append(byte)
            if len(keystream) == n:
                return keystream

def bytes_xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

def bytes_xor_single(x, y):
    return bytes(a ^ y for a in x)

def calculate_score_freq(x):
    return sum(freq.get(byte.lower(), 0) for byte in x)

def freq_crack_xor(x):
    keystream_length = max(map(len, x))
    cracked_keystream = []
    for i in range(keystream_length):
        best_key, best_score = b"", 0
        transposed = b"".join([ciphertext[i:i + 1] for ciphertext in x if ciphertext[i:i + 1]])
        for j in range(256): # transpose and test one byte of the keystream
            try: # not always valid
                test_score = calculate_score_freq(bytes_xor_single(transposed, j).decode("utf-8"))
            except:
                continue
            if test_score > best_score:
                best_score, best_key = test_score, j
        cracked_keystream.append(best_key)
    return cracked_keystream

file = open("20.txt", "r")
plaintexts = [base64.b64decode(bytes(plaintext.strip(), "utf-8")) for plaintext in file.readlines()]
# freq = {"a": 0.0804, "b": 0.0148, "c": 0.0334, "d": 0.0382, "e": 0.1249, "f": 0.024, "g": 0.0187, "h": 0.0505, "i": 0.0757, "j": 0.0016, "k": 0.0054, "l": 0.0407, "m": 0.0251, "n": 0.0723, "o": 0.0764, "p": 0.0214, "q": 0.0012, "r": 0.0628, "s": 0.0651, "t": 0.0928, "u": 0.0273, "v": 0.0105, "w": 0.0168, "x": 0.0023, "y": 0.0166, "z": 0.0009, " ": 0.2000} # https://norvig.com/mayzner.html
freq = {"a": 0.0651738, "b": 0.0124248, "c": 0.0217339, "d": 0.0349835, "e": 0.1041442, "f": 0.0197881, "g": 0.0158610, "h": 0.0492888, "i": 0.0558094, "j": 0.0009033, "k": 0.0050529, "l": 0.0331490, "m": 0.0202124, "n": 0.0564513, "o": 0.0596302, "p": 0.0137645, "q": 0.0008606, "r": 0.0497563, "s": 0.0515760, "t": 0.0729357, "u": 0.0225134, "v": 0.0082903, "w": 0.0171272, "x": 0.0013692, "y": 0.0145984, "z": 0.0007836, " ": 0.1918182} # http://www.data-compression.com/english.html, works better

keystream = aes_ctr_fixed_keystream(SECURE_KEY, SECURE_NONCE, max(map(len, plaintexts))) # longest plaintext
ciphertexts = [bytes_xor(plaintext, keystream) for plaintext in plaintexts] # no need for the full AES_CTR function here
cracked_keystream = freq_crack_xor(ciphertexts)
for ciphertext in ciphertexts:
    print(bytes_xor(ciphertext, cracked_keystream).decode())
