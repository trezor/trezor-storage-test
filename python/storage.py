from .norcow import Norcow


class Storage:
    def init(self) -> None:
        self.nc = Norcow()
        self.initialized = False
        self.unlocked = False
        self.nc.init()
        self.initialized = True

    def wipe(self) -> None:
        self.nc.wipe()

    def check_pin(self, pin: int) -> bool:
        return True

    def unlock(self, pin: int) -> bool:
        self.unlocked = False
        if self.initialized and self.check_pin(pin):
            self.unlocked = True
        return self.unlocked

    def has_pin(self) -> bool:
        raise NotImplementedError

    def change_pin(self, oldpin: int, newpin: int) -> None:
        if not self.initialized or self.unlocked:
            raise ValueError("Storage not initialized or locked")
        if not self.check_pin(oldpin):
            raise ValueError("Invalid PIN")
        raise NotImplementedError

    def get(self, key: int) -> bytes:
        app = key >> 8
        if not self.initialized or app == 0:
            raise ValueError("Storage not initialized or APP_ID = 0")
        if not self.unlocked or (app & 0x80) == 0:
            raise ValueError("Storage locked or (app & 0x80) = 0")
        return self.nc.get(key)

    def set(self, key: int, val: bytes) -> bool:
        app = key >> 8
        if not self.initialized or not self.unlocked or app == 0:
            raise ValueError("Storage not initialized or locked or app = 0")
        return self.nc.set(key, val)

    def _dump(self) -> bytes:
        return self.nc._dump()
