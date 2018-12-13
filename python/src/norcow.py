import sys
from struct import pack

from . import consts

NORCOW_SECTOR_COUNT = 2
NORCOW_SECTOR_SIZE = 64 * 1024

NORCOW_MAGIC = b"NRCW"


def align4_int(i: int):
    return (4 - i) % 4


def align4_data(data):
    return data + b"\x00" * align4_int(len(data))


class Norcow:
    def init(self):
        self.wipe()

    def wipe(self):
        self.sectors = [
            bytearray([0xFF] * NORCOW_SECTOR_SIZE) for _ in range(NORCOW_SECTOR_COUNT)
        ]
        self.sectors[0][:4] = NORCOW_MAGIC
        self.active_sector = 0
        self.active_offset = len(NORCOW_MAGIC)

    def get(self, key: int) -> bytes:
        value, _ = self._find_item(key)
        return value

    def set(self, key: int, val: bytes) -> bool:
        if key == consts.NORCOW_KEY_FREE:
            raise RuntimeError("Norcow: key 0xFFFF is not allowed")

        if self.active_offset + 4 + len(val) > NORCOW_SECTOR_SIZE:
            self._compact()

        found_value, pos = self._find_item(key)
        if found_value:
            self._erase_old(pos, found_value)
        self._append(key, val)

    def _erase_old(self, pos: int, value: bytes):
        wiped_data = b"\x00" * len(value)
        self._write(pos, 0x0000, wiped_data)

    def replace(self, key: int, new_value: bytes) -> bool:
        old_value, offset = self._find_item(key)
        if not old_value:
            raise ValueError("Norcow: key not found")
        if len(old_value) != len(new_value):
            raise ValueError("Norcow: replace works only with items of the same length")
        self._write(offset, key, new_value)

    def _append(self, key: int, value: bytes):
        self.active_offset += self._write(self.active_offset, key, value)

    def _write(self, pos: int, key: int, new_value: bytes) -> int:
        data = pack("<HH", key, len(new_value)) + align4_data(new_value)
        self.sectors[self.active_sector][pos : pos + len(data)] = data
        return len(data)

    def _find_item(self, key: int) -> (bytes, int):
        offset = len(NORCOW_MAGIC)
        value = False
        pos = offset
        while True:
            try:
                k, v = self._read_item(offset)
                if k == key:
                    value = v
                    pos = offset
            except ValueError as e:
                break
            offset = offset + self._norcow_item_length(v)
        return value, pos

    def _norcow_item_length(self, data: bytes) -> int:
        # APP_ID, KEY_ID, LENGTH, DATA, ALIGNMENT
        return 1 + 1 + 2 + len(data) + align4_int(len(data))

    def _read_item(self, offset: int) -> (int, bytes):
        key = self.sectors[self.active_sector][offset : offset + 2]
        key = int.from_bytes(key, sys.byteorder)
        if key == consts.NORCOW_KEY_FREE:
            raise ValueError("Norcow: no data on this offset")
        length = self.sectors[self.active_sector][offset + 2 : offset + 4]
        length = int.from_bytes(length, sys.byteorder)
        value = self.sectors[self.active_sector][offset + 4 : offset + 4 + length]
        return key, value

    def _dump(self):
        return [bytes(x) for x in self.sectors]

    def _compact(self):
        raise NotImplementedError
