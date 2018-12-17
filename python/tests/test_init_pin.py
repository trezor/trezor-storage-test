from . import common
from ..src.storage import Storage


def test_init_pin():
    s = Storage()
    s.init(b"\x00\x00\x00\x00\x00\x00")
    d = s._dump()
    assert (
        d[0][:256].hex()
        == "4e5243320100000002002c008cbfde19939337f59335bf515108d9955cdd57be41f4832ea7bff94904e5a8f4c2e0a6943aece2c12940191b03000100010000000100840078dbead57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd57edfffd5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert common.all_ff_bytes(d[1][:256])

    s = Storage()
    s.init(b"\x00\x00\x00\x00\x00\x01")
    d = s._dump()
    assert (
        d[0][:256].hex()
        == "4e5243320100000002002c0084971631844721eeb3ddf0f30f88faee14f70fe97e084ae9784cf22e79e29586590bfe800dfc3f99bec5ba56030001000100000001008400f033a26dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dfabbfb7dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
