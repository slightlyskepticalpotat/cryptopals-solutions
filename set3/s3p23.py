from s3p21 import MersenneTwister

def unshift_right(n, shift):
    i = 0
    while i * shift < 32:
        new_mask = n & (((0xffffffff << (32 - shift)) & 0xffffffff) >> (shift * i))
        n ^= new_mask >> shift
        i += 1
    return n

def unshift_left(n, shift, mask):
    i = 0
    while i * shift < 32:
        new_mask = n & ((0xffffffff >> (32 - shift)) << (shift * i))
        new_mask <<= shift
        n ^= new_mask & mask
        i += 1
    return n

random = MersenneTwister()
random_values, original_state = [random.random_integer() for _ in range(624)], [0 for _ in range(624)] # at least 624 values are needed to get the internal state
for i in range(624): # this attack is for the 32-bit prng but can be easily modified to also target other versions of the mersenne twister
    y = random_values[i]
    y = unshift_right(y, 18)
    y = unshift_left(y, 15, 0xefc60000)
    y = unshift_left(y, 7, 0x9d2c5680)
    y = unshift_right(y, 11)
    original_state[i] = y
random.set_state(original_state)
test_values = [random.random_integer() for _ in range(624)]
assert test_values == random_values
print(test_values[:10], random_values[:10])
