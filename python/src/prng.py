class Prng:
    def __init__(self, seed=0):
        self.generator = self.lcg(seed)

    def random_buffer(self, length: int):
        length = length
        if length % 4 != 0:
            raise ValueError("Use only for whole words (multiples of 4 bytes)")
        b = bytearray(length)
        for i in range(length):
            if i % 4 == 0:
                # TODO check endianness
                rand = next(self.generator).to_bytes(4, "little")
            b[i] = rand[i % 4]
        return b

    def lcg(self, seed):
        while True:
            # & 0x7fffffff is equal to % (2**31)
            seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
            yield seed
