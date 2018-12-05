from . import consts, crypto, pin
from .norcow import Norcow
from .prng import Prng


class Storage:
    def init(self) -> None:
        self.nc = Norcow()
        self.initialized = False
        self.unlocked = False
        self.nc.init()
        self.initialized = True
        self.prng = Prng()
        self._init_pin()

    def set_pin(self, pin: int) -> bool:
        salt = self.prng.random_buffer(consts.PIN_SALT_SIZE)
        kek, keiv = crypto.derive_kek_keiv(salt, pin)

        # generate random Disk Encryption Key
        dek = self.prng.random_buffer(consts.DEK_SIZE)

        # Encrypted Disk Encryption Key
        edek, tag = crypto.chacha_poly_encrypt(kek, keiv, dek)
        # Pin Verification Code
        pvc = tag[: consts.PVC_SIZE]

        return self._set(consts.EDEK_PVC_KEY, salt + edek + pvc)

    def wipe(self) -> None:
        self.nc.wipe()

    def check_pin(self, pin: int) -> bool:
        data = self.nc.get(consts.EDEK_PVC_KEY)
        salt = data[: consts.PIN_SALT_SIZE]
        edek = data[consts.PIN_SALT_SIZE : consts.PIN_SALT_SIZE + consts.DEK_SIZE]
        pvc = data[consts.PIN_SALT_SIZE + consts.DEK_SIZE :]

        return crypto.validate_pin(pin, salt, edek, pvc)

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
        return self._set(key, val)

    def _init_pin(self):
        self.set_pin(consts.PIN_EMPTY)
        self._set(consts.PIN_NOT_SET_KEY, consts.TRUE_BYTE)
        guard_key = self.prng.random_buffer(consts.PIN_LOG_GUARD_KEY_SIZE)
        self._set(consts.PIN_LOG_KEY, pin.get_init_logs(guard_key))

    def _set(self, key: int, val: bytes) -> bool:
        return self.nc.set(key, val)

    def _dump(self) -> bytes:
        return self.nc._dump()
