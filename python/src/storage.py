import hashlib
import sys

from . import consts, crypto, pin_logs, prng
from .norcow import Norcow


class Storage:
    def __init__(self):
        self.initialized = False
        self.unlocked = False
        self.dek = None

    def init(self, hardware_salt: bytes) -> None:
        self.initialized = False
        self.unlocked = False
        self.nc = Norcow()
        self.nc.init()
        self.initialized = True
        self.hw_salt_hash = hashlib.sha256(hardware_salt).digest()
        # TODO check if EDEK already present?
        self._init_pin()

    def _init_pin(self):
        # generate random Data Encryption Key
        self.dek = prng.random_buffer(consts.DEK_SIZE)

        self._set_pin(consts.PIN_EMPTY)

        guard_key = prng.random_buffer(consts.PIN_LOG_GUARD_KEY_SIZE)
        self._set(consts.PIN_LOG_KEY, pin_logs.get_init_logs(guard_key))

    def _set_pin(self, pin: int):
        random_salt = prng.random_buffer(consts.PIN_SALT_SIZE)
        salt = self.hw_salt_hash + random_salt
        kek, keiv = crypto.derive_kek_keiv(salt, pin)

        # Encrypted Data Encryption Key
        edek, tag = crypto.chacha_poly_encrypt(kek, keiv, self.dek)
        # Pin Verification Code
        pvc = tag[: consts.PVC_SIZE]

        self._set(consts.EDEK_PVC_KEY, random_salt + edek + pvc)
        if pin == consts.PIN_EMPTY:
            self._set_bool(consts.PIN_NOT_SET_KEY, True)
        else:
            self._set_bool(consts.PIN_NOT_SET_KEY, False)

    def wipe(self) -> None:
        self.nc.wipe()

    def check_pin(self, pin: int) -> bool:
        pin_log = self._get(consts.PIN_LOG_KEY)
        guard_key = pin_log[: consts.PIN_LOG_GUARD_KEY_SIZE]
        guard_mask, guard = pin_logs.derive_guard_mask_and_value(guard_key)
        pin_entry_log = pin_log[consts.PIN_LOG_GUARD_KEY_SIZE + consts.PIN_LOG_SIZE :]

        pin_entry_log = pin_logs.write_attempt_to_log(guard_mask, guard, pin_entry_log)
        pin_log[consts.PIN_LOG_GUARD_KEY_SIZE + consts.PIN_LOG_SIZE :] = pin_entry_log
        self.nc.replace(consts.PIN_LOG_KEY, pin_log)

        data = self.nc.get(consts.EDEK_PVC_KEY)
        salt = self.hw_salt_hash + data[: consts.PIN_SALT_SIZE]
        edek = data[consts.PIN_SALT_SIZE : consts.PIN_SALT_SIZE + consts.DEK_SIZE]
        pvc = data[consts.PIN_SALT_SIZE + consts.DEK_SIZE :]
        is_valid = crypto.validate_pin(pin, salt, edek, pvc)

        if is_valid:
            pin_success_log = pin_entry_log
            pin_log[
                consts.PIN_LOG_GUARD_KEY_SIZE : consts.PIN_LOG_GUARD_KEY_SIZE
                + consts.PIN_LOG_SIZE
            ] = pin_success_log
            self.nc.replace(consts.PIN_LOG_KEY, pin_log)

        return is_valid

    def unlock(self, pin: int) -> None:
        self.unlocked = False
        if self.initialized and self.check_pin(pin):
            self.unlocked = True
        else:
            raise RuntimeError("Failed to unlock storage.")

    def has_pin(self) -> bool:
        val = self._get(consts.PIN_NOT_SET_KEY)
        return val != consts.TRUE_BYTE

    def change_pin(self, oldpin: int, newpin: int) -> None:
        if not self.initialized or not self.unlocked:
            raise RuntimeError("Storage not initialized or locked")
        if not self.check_pin(oldpin):
            raise RuntimeError("Invalid PIN")
        self._set_pin(newpin)

    def get(self, key: int) -> bytes:
        app = key >> 8
        if not self.initialized or app == consts.PIN_APP_ID:
            raise RuntimeError("Storage not initialized or app = 0 (PIN)")
        if not self.unlocked and not (app & consts.FLAG_PUBLIC):
            # public fields can be read from an unlocked device
            raise RuntimeError("Storage locked")
        if app & consts.FLAG_PUBLIC:
            return self._get(key)
        return self._get_decrypt(key)

    def set(self, key: int, val: bytes) -> bool:
        app = key >> 8
        if not self.initialized or not self.unlocked or app == consts.PIN_APP_ID:
            raise RuntimeError("Storage not initialized or locked or app = 0 (PIN)")
        if app & consts.FLAG_PUBLIC:
            return self._set(key, val)
        return self._set_encrypt(key, val)

    def _set_encrypt(self, key: int, val: bytes) -> bool:
        # In C data are preallocated beforehand for encrypted values,
        # to match the behaviour we do the same.
        preallocate = b"\x00" * (consts.CHACHA_IV_SIZE + len(val) + consts.POLY1305_MAC_SIZE)
        self._set(key, preallocate)
        iv = prng.random_buffer(consts.CHACHA_IV_SIZE)
        cipher_text, tag = crypto.chacha_poly_encrypt(
            self.dek, iv, val, key.to_bytes(2, sys.byteorder)
        )
        return self.nc.replace(key, iv + cipher_text + tag)

    def _get_decrypt(self, key: int) -> bytes:
        data = self._get(key)
        iv = data[: consts.CHACHA_IV_SIZE]
        # cipher text with MAC
        chacha_input = data[consts.CHACHA_IV_SIZE :]
        return crypto.chacha_poly_decrypt(
            self.dek, key, iv, chacha_input, key.to_bytes(2, sys.byteorder)
        )

    def _get(self, key: int) -> bytes:
        return self.nc.get(key)

    def _set(self, key: int, val: bytes) -> bool:
        return self.nc.set(key, val)

    def _set_bool(self, key: int, val: bool) -> bool:
        if val:
            return self.nc.set(key, consts.TRUE_BYTE)
        # False is stored as an empty value
        return self.nc.set(key, consts.FALSE_BYTE)

    def _dump(self) -> bytes:
        return self.nc._dump()
