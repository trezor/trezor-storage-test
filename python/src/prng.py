import sys


class Prng:
    def __init__(self, seed=0):
        self.seed = seed

    def random_buffer(self, length: int) -> bytes:
        length = length
        if length % 4 != 0:
            raise ValueError("Use only for whole words (multiples of 4 bytes)")
        b = bytearray(length)
        for i in range(length):
            if i % 4 == 0:
                rand = self.random32().to_bytes(4, sys.byteorder)
            b[i] = rand[i % 4]
        return bytes(b)

    def random8(self):
        # & 0x7fffffff is equal to % (2**31)
        self.seed = (1103515245 * self.seed + 12345) & 0x7FFFFFFF
        return self.seed & 0xFF

    def random32(self):
        r1 = self.random8()
        r2 = self.random8()
        r3 = self.random8()
        r4 = self.random8()
        return (r1 << 24) | (r2 << 16) | (r3 << 8) | r4
