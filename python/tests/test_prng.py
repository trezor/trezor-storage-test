import sys

from src.prng import Prng

sys.path.append("../src")


class TestInitPin:
    def test_prng(self):
        p = Prng()
        buf = p.random_buffer(4)
        assert buf == b"\x39\x30\x00\x00"
        buf = p.random_buffer(4)
        assert buf == b"\x7e\x16\xdc\x53"

        p = Prng()
        buf = p.random_buffer(8)
        assert buf == b"\x39\x30\x00\x00\x7e\x16\xdc\x53"
