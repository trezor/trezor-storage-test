from c.storage import Storage as StorageC
from python.src.storage import Storage as StoragePy

import pytest


class TestPin:
    def test_init_pin(self):
        sc = StorageC()
        sp = StoragePy()
        sc.init(b"\x00\x00\x00\x00\x00\x00")
        sp.init(b"\x00\x00\x00\x00\x00\x00")
        assert memory_equals(sc, sp)

        sc = StorageC()
        sp = StoragePy()
        sc.init(b"\x22\x00\xDD\x00\x00\xBE")
        sp.init(b"\x22\x00\xDD\x00\x00\xBE")
        assert memory_equals(sc, sp)

        sc = StorageC()
        sp = StoragePy()
        sc.init(b"\x11\x11\x11\x11\x11\x11")
        sp.init(b"\x22\x22\x22\x22\x22\x22")
        assert not memory_equals(sc, sp)

    def test_change_pin(self):
        sc = StorageC()
        sp = StoragePy()
        for s in (sc, sp):
            s.init(b"\x22\x22\x22\x22\x22\x22")
            s.unlock(1)
            s.change_pin(1, 2221)
            # invalid PIN
            with pytest.raises(RuntimeError):
                s.change_pin(99991, 1)
            s.unlock(2221)
            s.change_pin(2221, 999991)
            s.change_pin(999991, 991)
            s.unlock(991)
            with pytest.raises(RuntimeError):
                s.unlock(99991)

        assert memory_equals(sc, sp)

    def test_has_pin(self):
        assert True  # TODO


def memory_equals(sc, sp) -> bool:
    return sc._dump() == sp._dump()
