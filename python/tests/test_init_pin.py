import sys
from unittest import mock

from src.prng import Prng
from src.storage import Storage

from . import common

sys.path.append("../src")


class TestInitPin:
    def test_init_pin(self):
        with mock.patch.object(Prng, "random_buffer", common.mock_random_simple):
            s = Storage()
            s.init(b"\x00\x00\x00\x00\x00\x00")
            d = s._dump()
            assert (
                d[0][:256].hex()
                == "4e52435702002c000101010108e3d2771e00e8d483438695afdbb2907a66f602470bf215491fef3e99558dd5d2e22421db1aef8103000100010000000100840001010101a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            assert common.all_ff_bytes(d[1][:256])

            s = Storage()
            s.init(b"\x00\x00\x00\x00\x00\x01")
            d = s._dump()
            assert (
                d[0][:256].hex()
                == "4e52435702002c0001010101fe1b1cce20b9a8a834fe665013eb5c1c8cb9b67bbd08a32ec27a1b57b160240cab7f97e500278ab303000100010000000100840001010101a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
