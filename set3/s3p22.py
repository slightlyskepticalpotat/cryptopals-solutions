import time
from s3p21 import MersenneTwister

def random_time_int():
    random = MersenneTwister()
    time.sleep(random.random_integer() % 10)
    random = MersenneTwister(int(time.time()))
    n = random.random_integer()
    time.sleep(random.random_integer() % 10)
    return n

to_crack = random_time_int()
print(f"Original: {to_crack}")
l, r = int(time.time()) - 60, int(time.time()) + 60
for i in range(l, r):
    random = MersenneTwister(i)
    if random.random_integer() == to_crack:
        print("Cracked!")
        print(f"Seed: {i}")
        break
