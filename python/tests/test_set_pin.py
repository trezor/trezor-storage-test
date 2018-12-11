import sys
import pytest
from unittest import mock

from src.prng import Prng
from src.storage import Storage

from . import common

sys.path.append("../src")


class TestSetPin:
    def test_set_pin_success(self):
        with mock.patch.object(Prng, "random_buffer", common.mock_random_simple):
            s = Storage()
            hw_salt = b"\x00\x00\x00\x00\x00\x00"
            s.init(hw_salt)
            s._set_pin(1)
            s.unlock(1)

            s = Storage()
            s.init(hw_salt)
            s._set_pin(229922)
            s.unlock(229922)

    def test_set_pin_failure(self):
        with mock.patch.object(Prng, "random_buffer", common.mock_random_simple):
            s = Storage()
            hw_salt = b"\x00\x00\x00\x00\x00\x00"
            s.init(hw_salt)
            s._set_pin(1)
            s.unlock(1)
            with pytest.raises(RuntimeError):
                s.unlock(1234)

            s = Storage()
            s.init(hw_salt)
            s._set_pin(229922)
            with pytest.raises(RuntimeError):
                assert s.unlock(1122992211)
