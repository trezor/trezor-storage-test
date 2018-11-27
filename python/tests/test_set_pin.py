import sys
from unittest import mock

from src.storage import Storage

sys.path.append("../src")


def mock_urandom(length: int) -> bytes:
    return b"x\11" * length


class TestSetPin:
    def test_init_pin(self):
        with mock.patch("os.urandom", mock_urandom):
            s = Storage()
            s.init()
            s.unlock(1)
            d = s._dump()
            print(d[0][:256].hex())
            # TODO
            assert True
