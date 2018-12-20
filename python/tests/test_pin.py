import pytest

from ..src.storage import Storage
from ..src import pin_logs


def test_set_pin_success():
    s = Storage()
    hw_salt = b"\x00\x00\x00\x00\x00\x00"
    s.init(hw_salt)
    s._set_pin(1)
    assert s.unlock(1) == True

    s = Storage()
    s.init(hw_salt)
    s._set_pin(229922)
    assert s.unlock(229922) == True


def test_set_pin_failure():
    s = Storage()
    hw_salt = b"\x00\x00\x00\x00\x00\x00"
    s.init(hw_salt)
    s._set_pin(1)
    assert s.unlock(1) == True
    assert s.unlock(1234) == False

    s = Storage()
    s.init(hw_salt)
    s._set_pin(229922)
    assert s.unlock(1122992211) == False


def test_read_bytes_by_words():
    array = b"\x04\x03\x02\x01\x08\x07\x06\x05"
    n = pin_logs.to_int_by_words(array)
    assert n == 0x0102030405060708
    assert array == pin_logs.to_bytes_by_words(n)[56:]

    array = b"\xFF\xFF\xFF\x01\x01\x05\x09\x01"
    n = pin_logs.to_int_by_words(array)
    assert n == 0x01FFFFFF01090501
    assert array == pin_logs.to_bytes_by_words(n)[56:]
