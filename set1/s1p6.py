import base64, string

def bytes_xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])

def bytes_xor_repeat(x, y):
    return bytes([x[i] ^ y[i % len(y)] for i in range(len(x))])

def bytes_xor_single(x, y):
    return bytes([a ^ y for a in x])

def calculate_score_freq(x):
    score = 0
    for byte in x:
        score += freq.get(byte.lower(), 0)
    return score

def hamming(x, y):
    dist, i = 0, int.from_bytes(bytes_xor(x, y), "little")
    while i:
        dist, i = dist + 1, i & i - 1
    return dist

def single_char_xor(x):
    best, best_key, best_score = "", "", 0
    for char in bytes(string.printable, "utf-8"):
        test = bytes_xor_single(x, char).decode("utf-8")
        test_score = calculate_score_freq(test)
        if test_score > best_score:
            best_score, best_key, best = test_score, char, test
    return best, best_key

file = open('6.txt', "r")
text, dists = base64.b64decode(file.read()), []
for i in range(2, 41):
    dists.append([(hamming(text[:i], text[i:2 * i]) + hamming(text[i:2 * i], text[2 * i:3 * i]) + hamming(text[2 * i:3 * i], text[3 * i:4 * i]) + hamming(text[3 * i:4 * i], text[4 * i:5 * i])) / (i * 4), i])
dists.sort()
poss, plaintexts = [dists[i][1] for i in range(3)], []
freq = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182} # got from github, need to replace later

for key_size in poss:
    key = b""
    for i in range(key_size):
        block = b""
        for j in range(i, len(text), key_size): # transpose the block
            block += bytes([text[j]])
        key += bytes([single_char_xor(block)[1]])
    plaintexts.append(bytes_xor_repeat(text, key))
plaintexts.sort(key = lambda x: calculate_score_freq(x.decode("utf-8")), reverse = True)
print(plaintexts[0].decode("utf-8"), end = "")
