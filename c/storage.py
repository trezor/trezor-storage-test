import ctypes as c
import os

sectrue = -1431655766  # 0xAAAAAAAAA
fname = os.path.join(os.path.dirname(__file__), "libtrezor-storage.so")


class Storage:

    def init(self) -> None:
        self.lib = c.cdll.LoadLibrary(fname)
        self.lib.storage_init(0)

    def wipe(self) -> None:
        self.lib.storage_wipe()

    def check_pin(self, pin: int) -> bool:
        return sectrue == self.lib.storage_check_pin(c.c_uint32(pin))

    def unlock(self, pin: int) -> bool:
        return sectrue == self.lib.storage_unlock(c.c_uint32(pin))

    def has_pin(self) -> bool:
        return sectrue == self.lib.storage_has_pin()

    def change_pin(self, oldpin: int, newpin: int) -> bool:
        return sectrue == self.lib.storage_change_pin(c.c_uint32(oldpin), c.c_uint32(newpin))

    def get(self, key: int) -> bytes:
        val_len = c.c_uint16()
        if sectrue != self.lib.storage_get(c.c_uint16(key), None, 0, c.byref(val_len)):
            raise RuntimeError("storage_get_len failed")
        s = c.create_string_buffer(val_len.value)
        if sectrue != self.lib.storage_get(c.c_uint16(key), s, val_len, c.byref(val_len)):
            raise RuntimeError("storage_get_data failed")
        return s.value

    def set(self, key: int, val: bytes) -> bool:
        return sectrue == self.lib.storage_set(c.c_uint16(key), val, c.c_uint16(len(val)))

    def _dump(self) -> bytes:
        size = c.cast(self.lib.FLASH_SIZE, c.POINTER(c.c_uint32)).contents.value
        addr = c.cast(self.lib.FLASH_BUFFER, c.POINTER(c.c_void_p)).contents.value
        flash_buffer = c.string_at(addr, size=size)
        # return just sectors 4 and 16 of the whole flash
        return [flash_buffer[0x010000:0x010000 + 0x10000], flash_buffer[0x110000:0x110000 + 0x10000]]
