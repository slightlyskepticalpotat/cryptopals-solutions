import string

def bytes_xor_single(x, y):
    return bytes([a ^ y for a in x])

def calculate_score(x):
    score = 0
    for word in words:
        if word in x:
            score += len(word)
    return score

file1 = open("google-10000-english.txt", "r")
words = [word.strip() for word in file1.readlines()]
file2 = open("4.txt", "r")
test_words = [test_word.strip() for test_word in file2.readlines()]
global_best, global_best_score = "", 0
for test_word in test_words:
    try: # stop decoding errors
        hex, best, best_score = bytes.fromhex(test_word), "", 0
        for char in bytes(string.printable, "utf-8"):
            test = bytes_xor_single(hex, char).decode("utf-8")
            test_score = calculate_score(test)
            if test_score > best_score:
                best_score = test_score
                best = test
        if best_score > global_best_score:
            global_best_score = best_score
            global_best = best
    except:
        pass
print(global_best.strip())
