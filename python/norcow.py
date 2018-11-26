from struct import pack

NORCOW_SECTOR_COUNT = 2
NORCOW_SECTOR_SIZE = 64 * 1024

NORCOW_MAGIC = b"NRCW"


def align4(data):
    if len(data) % 4 == 0:
        return data
    else:
        return data + b"\x00" * (4 - len(data) % 4)


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
        raise NotImplementedError

    def set(self, key: int, val: bytes) -> bool:
        if self.active_offset + 4 + len(val) > NORCOW_SECTOR_SIZE:
            self.compact()
        data = pack("<HH", key, len(val)) + align4(val)
        self.sectors[self.active_sector][
            self.active_offset : self.active_offset + len(data)
        ] = data
        self.active_offset += len(data)

    def _dump(self):
        return [bytes(x) for x in self.sectors]

    def _compact(self):
        raise NotImplementedError
