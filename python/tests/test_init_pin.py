from . import common
from ..src.storage import Storage


def test_init_pin():
    s = Storage()
    s.init(b"\x00\x00\x00\x00\x00\x00")
    d = s._dump()
    assert (
        d[0][:256].hex()
        == "4e524332feffffff02002c00e7befd812f87c19e497bf1af4b314242c81d60cabd0f7489b330daad835c98f01f105a0634b39540ef9a536d0300010001000000010084001aaff0949ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad69ffffad6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert common.all_ff_bytes(d[1][:256])

    s = Storage()
    s.init(b"\x00\x00\x00\x00\x00\x01")
    d = s._dump()
    assert (
        d[0][:256].hex()
        == "4e524332feffffff02002c0079094f62b8711e74d5e01be54d00fd6777291b374c2f15cdb055e07624561ce54a4f1ef91016a6884023f46903000100010000000100840084a409a5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5e6f6adf5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
