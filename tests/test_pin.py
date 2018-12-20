import pytest

from c.storage import Storage as StorageC
from python.src.storage import Storage as StoragePy
from python.src import consts

from . import common


def test_init_pin():
    sc = StorageC()
    sp = StoragePy()
    sc.init(b"\x00\x00\x00\x00\x00\x00")
    sp.init(b"\x00\x00\x00\x00\x00\x00")
    assert common.memory_equals(sc, sp)

    sc = StorageC()
    sp = StoragePy()
    sc.init(b"\x22\x00\xDD\x00\x00\xBE")
    sp.init(b"\x22\x00\xDD\x00\x00\xBE")
    assert common.memory_equals(sc, sp)


def test_change_pin():
    sc = StorageC()
    sp = StoragePy()
    for s in (sc, sp):
        s.init(b"\x22\x22\x22\x22\x22\x22")
        assert s.unlock(1) == True
        assert s.change_pin(1, 2221) == True
        # invalid PIN
        assert s.change_pin(99991, 1) == False
        assert s.unlock(2221) == True
        assert s.change_pin(2221, 999991) == True
        assert s.change_pin(999991, 991) == True
        assert s.unlock(991) == True
        assert s.unlock(99991) == False

    assert common.memory_equals(sc, sp)


def test_has_pin():
    sc = StorageC()
    sp = StoragePy()
    for s in (sc, sp):
        s.init(b"\x00\x00\x00\x00\x00\x00")
        assert not s.has_pin()
        assert s.unlock(1) == True
        assert not s.has_pin()
        assert s.change_pin(1, 221) == True
        assert s.has_pin()
        assert s.change_pin(221, 1) == True
        assert not s.has_pin()


def test_wipe_after_max_pin():
    sc = StorageC()
    sp = StoragePy()
    for s in (sc, sp):
        s.init(b"\x22\x22\x22\x22\x22\x22")
        assert s.unlock(1) == True
        assert s.change_pin(1, 2221) == True
        assert s.unlock(2221) == True
        s.set(0x0202, b"Hello")

        # try an invalid PIN MAX - 1 times
        for i in range(consts.PIN_MAX_TRIES - 1):
            assert s.unlock(99991) == False
        # this should pass
        assert s.unlock(2221) == True
        assert s.get(0x0202) == b"Hello"

        # try an invalid PIN MAX times, the storage should get wiped
        for i in range(consts.PIN_MAX_TRIES):
            assert s.unlock(99991) == False
        assert i == consts.PIN_MAX_TRIES - 1
        # this should raise an exception, the storage is wiped
        assert s.unlock(2221) == False
        with pytest.raises(RuntimeError):
            assert s.get(0x0202) == b"Hello"

    assert common.memory_equals(sc, sp)
