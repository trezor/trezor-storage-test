import sys
from unittest import mock

from src.storage import Storage

from . import common

sys.path.append("../src")


class TestInitPin:
    def test_init_pin(self):
        with mock.patch("os.urandom", common.mock_urandom_simple):
            s = Storage()
            s.init()
            d = s._dump()
            assert (
                d[0][:256].hex()
                == "4e52435702002c000101010126264102d7a5676a2cbe7abccf57085174f9fbfbd6c31e79fcee87bf9fbea3727622f7ece93bd60d03000100010000000100840001010101a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            assert common.all_ff_bytes(d[1][:256])
