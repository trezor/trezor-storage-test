import pytest

from c.storage import Storage as StorageC
from python.src import consts
from python.src.storage import Storage as StoragePy

from . import common


def init() -> (StorageC, StoragePy):
    sc = StorageC()
    sp = StoragePy()
    for s in (sc, sp):
        s.init(common.uid)
        assert s.unlock(1)
    return sc, sp


def test_compact():
    sc, sp = init()
    for s in (sc, sp):
        s.set(0xBEEF, b"hello")
        s.set(0xBEEF, b"asdasdasdasd")
        s.set(0xBEEF, b"fsdasdasdasdasdsadasdsadasdasd")
        s.set(0x0101, b"a" * (consts.NORCOW_SECTOR_SIZE - 600))
        s.set(0x03FE, b"world!")
        s.set(0x04FE, b"world!xfffffffffffffffffffffffffffff")
        s.set(0x05FE, b"world!affffffffffffffffffffffffffffff")
        s.set(0x0101, b"s")
        s.set(0x06FE, b"world!aaaaaaaaaaaaaaaaaaaaaaaaab")
        s.set(0x07FE, b"worxxxxxxxxxxxxxxxxxx")
        s.set(0x09EE, b"worxxxxxxxxxxxxxxxxxx")
    assert common.memory_equals(sc, sp)

    sc, sp = init()
    for s in (sc, sp):
        s.set(0xBEEF, b"asdasdasdasd")
        s.set(0xBEEF, b"fsdasdasdasdasdsadasdsadasdasd")
        s.set(0x8101, b"a" * (consts.NORCOW_SECTOR_SIZE - 1000))
        with pytest.raises(RuntimeError):
            s.set(0x0101, b"a" * (consts.NORCOW_SECTOR_SIZE - 100))
        s.set(0x0101, b"hello")
    assert common.memory_equals(sc, sp)
