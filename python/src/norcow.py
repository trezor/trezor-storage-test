from struct import pack

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
        return self._find_item(self.active_sector, key)

    def set(self, key: int, val: bytes) -> bool:
        if self.active_offset + 4 + len(val) > NORCOW_SECTOR_SIZE:
            self._compact()
        data = pack("<HH", key, len(val)) + align4_data(val)
        self.sectors[self.active_sector][
            self.active_offset : self.active_offset + len(data)
        ] = data
        self.active_offset += len(data)

    def _find_item(self, sector: int, key: int) -> bytes:
        offset = len(NORCOW_MAGIC)
        value = False
        key = key.to_bytes(2, "little")
        while True:
            try:
                k, v = self._read_item(sector, offset)
                if k == key:
                    value = v
            except ValueError as e:
                break
            offset = offset + 2 + 2 + len(v) + align4_int(len(v))
        return value

    def _read_item(self, sector: int, offset: int) -> (bytes, bytes):
        key = self.sectors[self.active_sector][offset : offset + 2]
        if key == b"\xff\xff":
            raise ValueError("Norcow: no data on this offset")
        length = self.sectors[self.active_sector][offset + 2 : offset + 4]
        length = int.from_bytes(length, "little")
        value = self.sectors[self.active_sector][offset + 4 : offset + 4 + length]
        return key, value

    def _dump(self):
        return [bytes(x) for x in self.sectors]

    def _compact(self):
        raise NotImplementedError
