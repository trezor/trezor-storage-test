from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import consts


def derive_kek_keiv(salt: bytes, pin: int) -> (bytes, bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=consts.KEK_SIZE + consts.KEIV_SIZE,
        salt=bytes(salt),
        iterations=10000,
        backend=default_backend(),
    )
    pbkdf_output = kdf.derive(pin.to_bytes(4, "little"))
    # the first 256b is Key Encryption Key
    kek = pbkdf_output[: consts.KEK_SIZE]
    # following with 96b of Initialization Vector
    keiv = pbkdf_output[consts.KEK_SIZE :]

    return kek, keiv


def chacha_poly_encrypt(key: bytes, iv: bytes, data: bytes) -> (bytes, bytes):
    chacha = ChaCha20Poly1305(key)
    chacha_output = chacha.encrypt(iv, bytes(data), None)
    # cipher text and 128b authentication tag
    return chacha_output[: len(data)], chacha_output[len(data) :]


def chacha_poly_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    chacha_output = chacha.decrypt(bytes(iv), bytes(data), None)
    return chacha_output


def validate_pin(pin: int, salt: bytes, edek: bytes, pvc: bytes):
    """
    This a little bit hackish. We do not store the whole
    authentication tag so we can't decrypt using ChaCha20Poly1305
    because it obviously checks the tag first and fails.
    So we are using the sole ChaCha20 cipher to decipher and then encrypt
    again with Chacha20Poly1305 to get the tag and compare it to PVC.
    """
    kek, keiv = derive_kek_keiv(salt, pin)

    algorithm = algorithms.ChaCha20(kek, (1).to_bytes(4, "little") + keiv)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    dek = decryptor.update(bytes(edek))

    _, tag = chacha_poly_encrypt(kek, keiv, dek)
    return tag[: consts.PVC_SIZE] == pvc
