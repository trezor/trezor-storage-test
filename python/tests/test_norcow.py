import sys

import pytest

from src.norcow import Norcow

from . import common

sys.path.append("../src")


class TestNorcow:
    def test_norcow_set(self):
        n = Norcow()
        n.init()
        n.set(0x0001, b"123")
        data = n._dump()[0][:256]
        assert data[:4] == b"NRCW"
        assert data[4:6] == b"\x01\x00"  # app + key
        assert data[6:8] == b"\x03\x00"  # length
        assert data[8:11] == b"123"  # data
        assert common.all_ff_bytes(data[12:])

        n.wipe()
        n.set(0x0901, b"hello")
        data = n._dump()[0][:256]
        assert data[:4] == b"NRCW"
        assert data[4:6] == b"\x01\x09"  # app + key
        assert data[6:8] == b"\x05\x00"  # length
        assert data[8:13] == b"hello"  # data
        assert data[13:16] == b"\x00\x00\x00"  # alignment
        assert common.all_ff_bytes(data[16:])

        offset = 16
        n.set(0x0102, b"world!")
        data = n._dump()[0][:256]
        assert data[offset : offset + 2] == b"\x02\x01"  # app + key
        assert data[offset + 2 : offset + 4] == b"\x06\x00"  # length
        assert data[offset + 4 : offset + 10] == b"world!"  # data
        assert data[offset + 10 : offset + 12] == b"\x00\x00"  # alignment
        assert common.all_ff_bytes(data[offset + 12 :])

    def test_norcow_read_item(self):
        n = Norcow()
        n.init()
        n.set(0x0001, b"123")
        n.set(0x0002, b"456")
        n.set(0x0101, b"789")
        key, value = n._read_item(12)
        assert key == b"\x02\x00"
        assert value == b"456"
        key, value = n._read_item(20)
        assert key == b"\x01\x01"
        assert value == b"789"

        with pytest.raises(ValueError) as e:
            key, value = n._read_item(200)
        assert "no data" in str(e)

    def test_norcow_get_item(self):
        n = Norcow()
        n.init()
        n.set(0x0001, b"123")
        n.set(0x0002, b"456")
        n.set(0x0101, b"789")
        value = n.get(0x0001)
        assert value == b"123"
        value = n.get(0x0101)
        assert value == b"789"
        n.set(0x0101, b"hello")  # item changed
        value = n.get(0x0101)
        assert value == b"hello"
        n.set(0x0002, b"world")
        n.set(0x0002, b"earth")
        value = n.get(0x0002)
        assert value == b"earth"

    def test_norcow_replace_item(self):
        n = Norcow()
        n.init()
        n.set(0x0001, b"123")
        n.set(0x0002, b"456")
        n.set(0x0101, b"789")
        value = n.get(0x0002)
        assert value == b"456"

        n.replace(0x0001, b"000")
        value = n.get(0x0001)
        assert value == b"000"

        n.replace(0x0002, b"111")
        value = n.get(0x0002)
        assert value == b"111"
        value = n.get(0x0001)
        assert value == b"000"
        value = n.get(0x0101)
        assert value == b"789"

        with pytest.raises(ValueError) as e:
            n.replace(0x0001, b"00000")
        assert "same length" in str(e)
