import sys

from src.prng import Prng

sys.path.append("../src")


class TestInitPin:
    def test_prng(self):
        p = Prng()
        buf = p.random_buffer(4)
        assert buf == b"\x2c\xdf\x7e\x39"
        buf = p.random_buffer(4)
        assert buf == b"\x18\xfb\x8a\xf5"

        p = Prng()
        buf = p.random_buffer(8)
        assert buf == b"\x2c\xdf\x7e\x39\x18\xfb\x8a\xf5"