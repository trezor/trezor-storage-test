import sys
from unittest import mock

from src.storage import Storage

sys.path.append("../src")


def mock_urandom(length: int) -> bytes:
    return b"\x01" * length


class TestSetPin:
    def test_set_pin_success(self):
        with mock.patch("os.urandom", mock_urandom):
            s = Storage()
            s.init()
            s.set_pin(1)
            assert s.unlock(1)

            s = Storage()
            s.init()
            s.set_pin(229922)
            assert s.unlock(229922)

    def test_set_pin_failure(self):
        with mock.patch("os.urandom", mock_urandom):
            s = Storage()
            s.init()
            s.set_pin(1)
            assert not s.unlock(1234)

            s = Storage()
            s.init()
            s.set_pin(229922)
            assert not s.unlock(1122992211)
