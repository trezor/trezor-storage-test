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


def random32():
    global seed
    seed = (1664525 * seed + 1013904223) & 0xFFFFFFFF
    return seed
