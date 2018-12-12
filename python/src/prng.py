import sys

seed = 0


def random_buffer(length: int) -> bytes:
    length = length
    if length % 4 != 0:
        raise ValueError("Use only for whole words (multiples of 4 bytes)")
    b = bytearray(length)
    for i in range(length):
        if i % 4 == 0:
            rand = random32().to_bytes(4, sys.byteorder)
        b[i] = rand[i % 4]
    return bytes(b)


def random8():
    global seed
    # & 0x7fffffff is equal to % (2**31)
    seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
    return seed & 0xFF


def random32():
    r1 = random8()
    r2 = random8()
    r3 = random8()
    r4 = random8()
    return (r1 << 24) | (r2 << 16) | (r3 << 8) | r4
