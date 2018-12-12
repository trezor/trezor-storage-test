import pytest

from c.storage import Storage as StorageC
from python.src.storage import Storage as StoragePy

from . import common

# Strings for testing ChaCha20 encryption.
chacha_strings = [
    b"Short string.",
    b"",
    b"Although ChaCha20 is a stream cipher, it operates on blocks of 64 bytes. This string is over 152 bytes in length so that we test multi-block encryption.",
    b"This string is exactly 64 bytes long, that is exactly one block.",
]


def test_set_get():
    sc = StorageC()
    sp = StoragePy()
    for s in (sc, sp):
        s.init(common.uid)
        s.unlock(1)
        s.set(0xBEEF, b"Hello")
        s.set(0xCAFE, b"world!  ")
        s.set(0xDEAD, b"How\n")
        s.set(0xAAAA, b"are")
        s.set(0x0901, b"you?")
        s.set(0x0902, b"Lorem")
        s.set(0x0903, b"ipsum")
        s.set(0xDEAD, b"A\n")
        s.set(0xDEAD, b"AAAAAAAAAAA")
        s.set(0x2200, b"BBBB")
        for i, string in enumerate(chacha_strings):
            s.set(0x0301 + i, string)
    assert common.memory_equals(sc, sp)

    for s in (sc, sp):
        s.change_pin(1, 2221)
        s.change_pin(2221, 991)
        s.set(0xAAAA, b"something else")
    assert common.memory_equals(sc, sp)

    # check data are not changed by gets
    datasc = sc._dump()
    datasp = sp._dump()

    for s in (sc, sp):
        assert s.get(0xAAAA) == b"something else"
        assert s.get(0x0901) == b"you?"
        assert s.get(0x0902) == b"Lorem"
        assert s.get(0x0903) == b"ipsum"
        assert s.get(0xDEAD) == b"AAAAAAAAAAA"
        assert s.get(0x2200) == b"BBBB"
        for i, string in enumerate(chacha_strings):
            assert s.get(0x0301 + i) == string

        assert datasc == sc._dump()
        assert datasp == sp._dump()

    for s in (sc, sp):
        with pytest.raises(RuntimeError):
            s.set(0xFFFF, b"Hello")
