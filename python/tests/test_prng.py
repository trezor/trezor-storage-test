from ..src import prng


def test_prng():
    buf = prng.random_buffer(4)
    assert buf == b"\x2c\xdf\x7e\x39"
    buf = prng.random_buffer(4)
    assert buf == b"\x18\xfb\x8a\xf5"

    buf = prng.random_buffer(8)
    assert buf == b"\xc4\xd7\x56\x71\x30\x73\xe2\xad"
