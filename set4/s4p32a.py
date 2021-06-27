import requests
import string
import time

global_start_time = time.time()
message = input("Message to fake: ").strip()
hmac = ""
for _ in range(40): # sha-1 is 40 chars
    check = []
    for char in string.ascii_lowercase + string.digits: # all lowercase letters and chars
        loc = []
        for i in range(32):
            start_time = time.time()
            result = requests.get("http://127.0.0.1:5000", {"file": message, "hmac": hmac + char+ (40 - len(hmac + char)) * "a"})
            end_time = time.time()
            loc.append(end_time - start_time)
        check.append([char, sum(loc) / len(loc)])
    check.sort(key = lambda x: x[1], reverse = True)
    hmac += check[0][0]
    print(hmac)
print(time.time() - global_start_time)