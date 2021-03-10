# wikipedia article and the authors' reference implementation were very helpful
class MersenneTwister:
    def __init__(self, seed = 5489, variant = "normal"):
        if variant == "normal":
            self.w = 32
            self.n = 624
            self.m = 397
            self.r = 31
            self.a = 0x9908b0df
            self.u = 11
            self.d = 0xffffffff
            self.s = 7
            self.b = 0x9d2c5680
            self.t = 15
            self.c = 0xefc60000
            self.l = 18
            self.f = 1812433253
        else:
            raise NotImplementedError
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = 1 << self.r
        self.state = [0 for _ in range(self.n)]
        self.state[0] = seed
        self.index = self.n
        for i in range(1, self.n):
            self.state[i] = self.fixed_int(self.f * (self.state[i - 1] ^ (self.state[i - 1] >> (self.w - 2))) + i)

    def random_integer(self):
        if self.index >= self.n:
            self.twist()
        y = self.state[self.index]
        y ^= (y >> self.u)
        y ^= ((y << self.s) & self.b)
        y ^= ((y << self.t) & self.c)
        y ^= (y >> self.l)
        self.index += 1
        return self.fixed_int(y)

    def twist(self):
        for i in range(self.n):
            temp = self.fixed_int((self.state[i] & self.upper_mask) + (self.state[(i + 1) % self.n] & self.lower_mask))
            shifted = temp >> 1
            if temp % 2:
                shifted ^= self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ shifted
        self.index = 0

    def get_state(self):
        return self.state

    def set_state(self, new_state):
        assert len(new_state) == self.n
        self.state = new_state
        self.index = 0

    def fixed_int(self, n):
        return self.d & n

better_random = MersenneTwister()
assert better_random.random_integer() == 3499211612 # https://oeis.org/A221557

if __name__ == "__main__":
    better_random = MersenneTwister()
    for _ in range(8):
        print(better_random.random_integer())
