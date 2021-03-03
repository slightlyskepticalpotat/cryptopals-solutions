file = open("8.txt", "r")
ciphertexts = [bytes.fromhex(ciphertext.strip()) for ciphertext in file.readlines()]
data = []
for ciphertext in ciphertexts:
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    data.append([ciphertext, len(blocks) - len(set(blocks))])
data.sort(key = lambda x: x[1], reverse = True)
print(data[0][0])
