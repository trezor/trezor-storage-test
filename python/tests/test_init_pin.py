import sys
from unittest import mock

import pytest

from src.storage import Storage

from . import common

sys.path.append("../src")


def mock_urandom(length: int) -> bytes:
    return b"\x01" * length


class TestInitPin:
    @pytest.mark.skip("old PIN method")
    def test_init_pin(self):
        with mock.patch("os.urandom", mock_urandom):
            s = Storage()
            s.init()
            s.unlock(1)
            d = s._dump()
            # TODO: this will change after the new PIN checking method is implemented
            # this works only with `self.nc.set(0x0001, bytearray(4) + bytearray(b'\xFF' * 4 * 31))`
            assert (
                d[0][:68].hex()
                == "4e52435702002c000101010126264102d7a5676a2cbe7abccf57085174f9fbfbd6c31e79fcee87bf9fbea3727622f7ece93bd60d03000100010000000100800000000000"
            )
            assert common.all_ff_bytes(d[0][68:256])
            assert common.all_ff_bytes(d[1][:256])
