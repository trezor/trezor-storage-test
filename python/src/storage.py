import hashlib
import sys

from . import consts, crypto, prng
from .norcow import Norcow
from .pin_log import PinLog


class Storage:
    def __init__(self):
        self.initialized = False
        self.unlocked = False
        self.dek = None
        self.nc = Norcow()
        self.nc.init()
        self.pin_log = PinLog(self.nc)

    def init(self, hardware_salt: bytes = b"") -> None:
        self.initialized = True
        self.hw_salt_hash = hashlib.sha256(hardware_salt).digest()
        # TODO check if EDEK already present?
        self._init_pin()

    def _init_pin(self):
        # generate random Data Encryption Key
        self.dek = prng.random_buffer(consts.DEK_SIZE)
        self._set_encrypt(consts.VERSION_KEY, b"\x01\x00\x00\x00")
        self._set_pin(consts.PIN_EMPTY)
        self.unlocked = False

        self.pin_log.init()

    def _set_pin(self, pin: int):
        random_salt = prng.random_buffer(consts.PIN_SALT_SIZE)
        salt = self.hw_salt_hash + random_salt
        kek, keiv = crypto.derive_kek_keiv(salt, pin)

        # Encrypted Data Encryption Key
        edek, tag = crypto.chacha_poly_encrypt(kek, keiv, self.dek)
        # Pin Verification Code
        pvc = tag[: consts.PVC_SIZE]

        self.nc.set(consts.EDEK_PVC_KEY, random_salt + edek + pvc)
        if pin == consts.PIN_EMPTY:
            self._set_bool(consts.PIN_NOT_SET_KEY, True)
        else:
            self._set_bool(consts.PIN_NOT_SET_KEY, False)

    def wipe(self) -> None:
        self.nc.wipe()
        self._init_pin()

    def check_pin(self, pin: int) -> bool:
        self.pin_log.write_attempt()

        data = self.nc.get(consts.EDEK_PVC_KEY)
        salt = self.hw_salt_hash + data[: consts.PIN_SALT_SIZE]
        edek = data[consts.PIN_SALT_SIZE : consts.PIN_SALT_SIZE + consts.DEK_SIZE]
        pvc = data[consts.PIN_SALT_SIZE + consts.DEK_SIZE :]
        is_valid = crypto.validate_pin(pin, salt, edek, pvc)

        if is_valid:
            self.pin_log.write_success()

        else:
            fails = self.pin_log.get_failures_count()
            if fails >= consts.PIN_MAX_TRIES:
                self.wipe()

        return is_valid

    def unlock(self, pin: int) -> bool:
        if not self.initialized or not self.check_pin(pin):
            return False

        version = self.get_encrypt(consts.VERSION_KEY)
        if version != consts.NORCOW_VERSION:
            return False

        self.unlocked = True
        return True

    def has_pin(self) -> bool:
        val = self.nc.get(consts.PIN_NOT_SET_KEY)
        return val != consts.TRUE_BYTE

    def get_pin_rem(self) -> int:
        return consts.PIN_MAX_TRIES - self.pin_log.get_failures_count()

    def change_pin(self, oldpin: int, newpin: int) -> bool:
        if not self.initialized or not self.unlocked:
            return False
        if not self.check_pin(oldpin):
            return False
        self._set_pin(newpin)
        return True

    def get(self, key: int) -> bytes:
        app = key >> 8
        if not self.initialized or app == consts.PIN_APP_ID:
            raise RuntimeError("Storage not initialized or app = 0 (PIN)")
        if not self.unlocked and not (app & consts.FLAG_PUBLIC):
            # public fields can be read from an unlocked device
            raise RuntimeError("Storage locked")
        if app & consts.FLAG_PUBLIC:
            return self.nc.get(key)
        return self.get_encrypt(key)

    def get_encrypt(self, key: int) -> bytes:
        data = self.nc.get(key)
        iv = data[: consts.CHACHA_IV_SIZE]
        # cipher text with MAC
        chacha_input = data[consts.CHACHA_IV_SIZE :]
        return crypto.chacha_poly_decrypt(
            self.dek, key, iv, chacha_input, key.to_bytes(2, sys.byteorder)
        )

    def set(self, key: int, val: bytes) -> bool:
        app = key >> 8
        if not self.initialized or not self.unlocked or app == consts.PIN_APP_ID:
            raise RuntimeError("Storage not initialized or locked or app = 0 (PIN)")
        if app & consts.FLAG_PUBLIC:
            return self.nc.set(key, val)
        return self._set_encrypt(key, val)

    def _set_encrypt(self, key: int, val: bytes):
        # In C data are preallocated beforehand for encrypted values,
        # to match the behaviour we do the same.
        preallocate = b"\xFF" * (
            consts.CHACHA_IV_SIZE + len(val) + consts.POLY1305_MAC_SIZE
        )
        self.nc.set(key, preallocate)
        iv = prng.random_buffer(consts.CHACHA_IV_SIZE)
        cipher_text, tag = crypto.chacha_poly_encrypt(
            self.dek, iv, val, key.to_bytes(2, sys.byteorder)
        )
        return self.nc.replace(key, iv + cipher_text + tag)

    def _set_bool(self, key: int, val: bool) -> bool:
        if val:
            return self.nc.set(key, consts.TRUE_BYTE)
        # False is stored as an empty value
        return self.nc.set(key, consts.FALSE_BYTE)

    def _dump(self) -> bytes:
        return self.nc._dump()
