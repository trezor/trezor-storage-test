import ctypes as c
import os

sectrue = -1431655766  # 0xAAAAAAAAA
fname = os.path.join(os.path.dirname(__file__), "libtrezor-storage.so")


class Storage:
    def __init__(self) -> None:
        self.lib = c.cdll.LoadLibrary(fname)

    def init(self, salt: bytes) -> None:
        self.lib.storage_init(0, salt, c.c_uint16(len(salt)))

    def wipe(self) -> None:
        self.lib.storage_wipe()

    def unlock(self, pin: int) -> None:
        if sectrue != self.lib.storage_unlock(c.c_uint32(pin)):
            raise RuntimeError("Failed to unlock storage.")

    def has_pin(self) -> bool:
        return sectrue == self.lib.storage_has_pin()

    def get_pin_rem(self) -> int:
        return self.lib.storage_get_pin_rem()

    def change_pin(self, oldpin: int, newpin: int) -> None:
        if sectrue != self.lib.storage_change_pin(c.c_uint32(oldpin), c.c_uint32(newpin)):
            raise RuntimeError("Failed to change PIN.")

    def get(self, key: int) -> bytes:
        val_len = c.c_uint16()
        if sectrue != self.lib.storage_get(c.c_uint16(key), None, 0, c.byref(val_len)):
            raise RuntimeError("Failed to value length from storage.")
        s = c.create_string_buffer(val_len.value)
        if sectrue != self.lib.storage_get(c.c_uint16(key), s, val_len, c.byref(val_len)):
            raise RuntimeError("Failed to get value from storage.")
        return s.raw

    def set(self, key: int, val: bytes) -> None:
        if sectrue != self.lib.storage_set(c.c_uint16(key), val, c.c_uint16(len(val))):
            raise RuntimeError("Failed to set value in storage.")

    def _dump(self) -> bytes:
        size = c.cast(self.lib.FLASH_SIZE, c.POINTER(c.c_uint32)).contents.value
        addr = c.cast(self.lib.FLASH_BUFFER, c.POINTER(c.c_void_p)).contents.value
        flash_buffer = c.string_at(addr, size=size)
        # return just sectors 4 and 16 of the whole flash
        return [flash_buffer[0x010000:0x010000 + 0x10000], flash_buffer[0x110000:0x110000 + 0x10000]]
