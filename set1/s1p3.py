import string

def bytes_xor_single(x, y):
    return bytes([a ^ y for a in x])

def calculate_score(x):
    score = 0
    for word in words:
        if word in x:
            score += len(word)
    return score

file = open("google-10000-english.txt", "r")
words = [word.strip() for word in file.readlines()]
hex, best, best_score = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), "", 0
for char in bytes(string.printable, "utf-8"):
    test = bytes_xor_single(hex, char).decode("utf-8")
    test_score = calculate_score(test)
    if test_score > best_score:
        best_score = test_score
        best = test
print(best)
