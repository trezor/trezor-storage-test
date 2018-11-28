import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import consts
from .norcow import Norcow


class Storage:
    def init(self) -> None:
        self.nc = Norcow()
        self.initialized = False
        self.unlocked = False
        self.nc.init()
        self.initialized = True
        self.init_pin()

    def init_pin(self):
        self.set_pin(consts.PIN_EMPTY)
        self._set(consts.PIN_NOT_SET_KEY, consts.TRUE_BYTE)

    def set_pin(self, pin: int):
        salt = os.urandom(consts.PIN_SALT_SIZE)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=consts.KEK_SIZE + consts.KEIV_SIZE,
            salt=salt,
            iterations=10000,
            backend=default_backend(),
        )
        pbkdf_output = kdf.derive(pin.to_bytes(4, "little"))
        # the first 256b are Key Encryption Key
        kek = pbkdf_output[: consts.KEK_SIZE]
        # following with 96b of Initialization Vector
        keiv = pbkdf_output[consts.KEK_SIZE :]

        # generate random Disk Encryption Key
        dek = os.urandom(consts.DEK_SIZE)

        chacha = ChaCha20Poly1305(kek)
        chacha_output = chacha.encrypt(keiv, dek, None)
        # Encrypted Disk Encryption Key
        edek = chacha_output[: consts.DEK_SIZE]
        # Pin Verification Code
        pvc = chacha_output[consts.DEK_SIZE : consts.DEK_SIZE + consts.PVC_SIZE]

        self._set(consts.EDEK_PVC_KEY, salt + edek + pvc)

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
        return self._set(key, val)

    def _set(self, key: int, val: bytes) -> bool:
        return self.nc.set(key, val)

    def _dump(self) -> bytes:
        return self.nc._dump()
