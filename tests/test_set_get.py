from c.storage import Storage as StorageC
from python.src.storage import Storage as StoragePy

from . import common


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
        s.set(0xDEAD, b"A\n")
        s.set(0xDEAD, b"AAAAAAAAAAA\n")
    assert common.memory_equals(sc, sp)

    for s in (sc, sp):
        s.change_pin(1, 2221)
        s.change_pin(2221, 991)
        s.set(0xAAAA, b"something else")
    assert common.memory_equals(sc, sp)

    assert sc.get(0xAAAA) == sp.get(0xAAAA)
